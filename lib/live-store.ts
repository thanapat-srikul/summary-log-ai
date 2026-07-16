import type { ZeekConnEvent } from "./zeek";
import { evaluateRules, flowBytes, flowPackets, isUncommonPort, type HostWindow } from "./rules";
import { isFailedConnection } from "./zeek";

type FlowGroup = {
  bucketTs: number;
  protocol: string;
  flows: number;
  bytes: number;
  packets: number;
  failed: number;
};

type HostGroup = {
  bucketTs: number;
  srcIp: string;
  destinations: Set<string>;
  connections: number;
  bytes: number;
  packets: number;
  failed: number;
  maxDurationMs: number;
  maxFlowBytes: number;
  uncommonPorts: number;
  representative: ZeekConnEvent;
};

type ExistingHostBucket = {
  connection_count: number;
  destinations_json: string;
  byte_count: number;
  packet_count: number;
  failed_count: number;
  max_duration_ms: number;
  max_flow_bytes: number;
  uncommon_port_count: number;
  max_score: number;
};

const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;

function minuteBucket(tsSeconds: number): number {
  return Math.floor((tsSeconds * 1000) / MINUTE) * MINUTE;
}

function incidentId(sourceId: string, bucketTs: number, srcIp: string): string {
  return `WIN-${sourceId}-${bucketTs}-${srcIp.replace(/[^a-zA-Z0-9]/g, "-")}`.slice(0, 180);
}

function parseDestinations(value: string | null | undefined): Set<string> {
  try {
    const parsed = JSON.parse(value ?? "[]");
    return new Set(Array.isArray(parsed) ? parsed.filter((entry) => typeof entry === "string").slice(0, 512) : []);
  } catch {
    return new Set();
  }
}

function groupEvents(events: ZeekConnEvent[]): { flows: FlowGroup[]; hosts: HostGroup[] } {
  const flowMap = new Map<string, FlowGroup>();
  const hostMap = new Map<string, HostGroup>();
  for (const event of events) {
    const bucketTs = minuteBucket(event.ts);
    const bytes = flowBytes(event);
    const packets = flowPackets(event);
    const failed = isFailedConnection(event.conn_state) ? 1 : 0;
    const flowKey = `${bucketTs}|${event.proto}`;
    const flow = flowMap.get(flowKey) ?? { bucketTs, protocol: event.proto, flows: 0, bytes: 0, packets: 0, failed: 0 };
    flow.flows += 1;
    flow.bytes += bytes;
    flow.packets += packets;
    flow.failed += failed;
    flowMap.set(flowKey, flow);

    const hostKey = `${bucketTs}|${event.orig_h}`;
    const host = hostMap.get(hostKey) ?? {
      bucketTs,
      srcIp: event.orig_h,
      destinations: new Set<string>(),
      connections: 0,
      bytes: 0,
      packets: 0,
      failed: 0,
      maxDurationMs: 0,
      maxFlowBytes: 0,
      uncommonPorts: 0,
      representative: event,
    };
    host.destinations.add(event.resp_h);
    host.connections += 1;
    host.bytes += bytes;
    host.packets += packets;
    host.failed += failed;
    host.maxDurationMs = Math.max(host.maxDurationMs, Math.round((event.duration ?? 0) * 1000));
    host.maxFlowBytes = Math.max(host.maxFlowBytes, bytes);
    host.uncommonPorts += isUncommonPort(event.resp_p) ? 1 : 0;
    if (bytes >= flowBytes(host.representative)) host.representative = event;
    hostMap.set(hostKey, host);
  }
  return { flows: [...flowMap.values()], hosts: [...hostMap.values()] };
}

async function cleanupRetention(db: D1Database, now: number): Promise<void> {
  const state = await db.prepare("SELECT value FROM maintenance_state WHERE key = ?1").bind("retention_cleanup").first<{ value: string }>();
  const lastCleanup = Number(state?.value ?? 0);
  if (now - lastCleanup < 60 * MINUTE) return;
  const cutoff = now - 7 * DAY;
  await db.batch([
    db.prepare("DELETE FROM event_dedup WHERE created_at < ?1").bind(cutoff),
    db.prepare("DELETE FROM flow_buckets WHERE bucket_ts < ?1").bind(cutoff),
    db.prepare("DELETE FROM host_buckets WHERE bucket_ts < ?1").bind(cutoff),
    db.prepare("DELETE FROM incidents WHERE detected_at < ?1").bind(cutoff),
    db.prepare("DELETE FROM ingest_batches WHERE received_at < ?1").bind(cutoff),
    db.prepare("INSERT INTO maintenance_state (key, value, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind("retention_cleanup", String(now), now),
  ]);
}

export async function ingestEvents(db: D1Database, sourceId: string, events: ZeekConnEvent[], initiallyRejected: number, spoolBacklog = 0) {
  const now = Date.now();
  const dedupResults = await db.batch(events.map((event) => db
    .prepare("INSERT OR IGNORE INTO event_dedup (source_id, uid, event_ts, created_at) VALUES (?1, ?2, ?3, ?4)")
    .bind(sourceId, event.uid, Math.round(event.ts * 1000), now)));
  const acceptedEvents = events.filter((_, index) => Number(dedupResults[index]?.meta?.changes ?? 0) > 0);
  const duplicates = events.length - acceptedEvents.length;
  const { flows, hosts } = groupEvents(acceptedEvents);

  const baseStatements: D1PreparedStatement[] = [
    db.prepare("INSERT INTO sources (id, name, last_seen_at, spool_backlog, created_at) VALUES (?1, ?1, ?2, ?3, ?2) ON CONFLICT(id) DO UPDATE SET last_seen_at = excluded.last_seen_at, spool_backlog = excluded.spool_backlog").bind(sourceId, now, spoolBacklog),
  ];
  for (const flow of flows) {
    baseStatements.push(db.prepare(`
      INSERT INTO flow_buckets (source_id, bucket_ts, protocol, flow_count, byte_count, packet_count, failed_count, anomaly_count)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)
      ON CONFLICT(source_id, bucket_ts, protocol) DO UPDATE SET
        flow_count = flow_count + excluded.flow_count,
        byte_count = byte_count + excluded.byte_count,
        packet_count = packet_count + excluded.packet_count,
        failed_count = failed_count + excluded.failed_count
    `).bind(sourceId, flow.bucketTs, flow.protocol, flow.flows, flow.bytes, flow.packets, flow.failed));
  }
  await db.batch(baseStatements);

  for (const host of hosts) {
    const existing = await db.prepare(`
      SELECT connection_count, destinations_json, byte_count, packet_count, failed_count,
             max_duration_ms, max_flow_bytes, uncommon_port_count, max_score
      FROM host_buckets WHERE source_id = ?1 AND bucket_ts = ?2 AND src_ip = ?3
    `).bind(sourceId, host.bucketTs, host.srcIp).first<ExistingHostBucket>();
    const destinations = parseDestinations(existing?.destinations_json);
    for (const destination of host.destinations) destinations.add(destination);
    const window: HostWindow = {
      connectionCount: Number(existing?.connection_count ?? 0) + host.connections,
      uniqueDestinations: destinations.size,
      byteCount: Number(existing?.byte_count ?? 0) + host.bytes,
      packetCount: Number(existing?.packet_count ?? 0) + host.packets,
      failedCount: Number(existing?.failed_count ?? 0) + host.failed,
      maxDurationMs: Math.max(Number(existing?.max_duration_ms ?? 0), host.maxDurationMs),
      maxFlowBytes: Math.max(Number(existing?.max_flow_bytes ?? 0), host.maxFlowBytes),
      uncommonPortCount: Number(existing?.uncommon_port_count ?? 0) + host.uncommonPorts,
    };
    const result = evaluateRules(window, host.representative);
    await db.prepare(`
      INSERT INTO host_buckets (source_id, bucket_ts, src_ip, connection_count, destinations_json, byte_count, packet_count, failed_count, max_duration_ms, max_flow_bytes, uncommon_port_count, max_score)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
      ON CONFLICT(source_id, bucket_ts, src_ip) DO UPDATE SET
        connection_count = excluded.connection_count,
        destinations_json = excluded.destinations_json,
        byte_count = excluded.byte_count,
        packet_count = excluded.packet_count,
        failed_count = excluded.failed_count,
        max_duration_ms = excluded.max_duration_ms,
        max_flow_bytes = excluded.max_flow_bytes,
        uncommon_port_count = excluded.uncommon_port_count,
        max_score = MAX(max_score, excluded.max_score)
    `).bind(sourceId, host.bucketTs, host.srcIp, window.connectionCount, JSON.stringify([...destinations].slice(0, 512)), window.byteCount, window.packetCount, window.failedCount, window.maxDurationMs, window.maxFlowBytes, window.uncommonPortCount, result.score).run();

    if (result.score >= 45) {
      const id = incidentId(sourceId, host.bucketTs, host.srcIp);
      const insert = await db.prepare(`
        INSERT OR IGNORE INTO incidents (id, source_id, zeek_uid, detected_at, src_ip, dst_ip, dst_port, protocol, score, severity, rule_codes_json, reason, action, status, byte_count, packet_count, created_at)
        VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'รอตรวจสอบ', ?13, ?14, ?15)
      `).bind(id, sourceId, host.bucketTs, host.srcIp, host.representative.resp_h, host.representative.resp_p, host.representative.proto, result.score, result.severity, JSON.stringify(result.codes), result.reason, result.action, window.byteCount, window.packetCount, now).run();
      if (Number(insert.meta?.changes ?? 0) > 0) {
        await db.prepare("UPDATE flow_buckets SET anomaly_count = anomaly_count + 1 WHERE source_id = ?1 AND bucket_ts = ?2 AND protocol = ?3")
          .bind(sourceId, host.bucketTs, host.representative.proto).run();
      } else {
        await db.prepare("UPDATE incidents SET score = ?1, severity = ?2, rule_codes_json = ?3, reason = ?4, action = ?5, byte_count = ?6, packet_count = ?7 WHERE id = ?8 AND score < ?1")
          .bind(result.score, result.severity, JSON.stringify(result.codes), result.reason, result.action, window.byteCount, window.packetCount, id).run();
      }
    }
  }

  const batchResult = await db.prepare("INSERT INTO ingest_batches (source_id, received_at, accepted_count, rejected_count, duplicate_count, error_code) VALUES (?1, ?2, ?3, ?4, ?5, NULL)")
    .bind(sourceId, now, acceptedEvents.length, initiallyRejected + duplicates, duplicates).run();
  await cleanupRetention(db, now);
  return {
    accepted: acceptedEvents.length,
    rejected: initiallyRejected + duplicates,
    duplicates,
    cursor: Number(batchResult.meta?.last_row_id ?? 0),
  };
}

function windowToMs(window: string | null): number {
  if (window === "1h") return 60 * MINUTE;
  if (window === "24h") return DAY;
  return 15 * MINUTE;
}

export async function latestCursor(db: D1Database): Promise<number> {
  const row = await db.prepare("SELECT COALESCE(MAX(id), 0) AS cursor FROM ingest_batches").first<{ cursor: number }>();
  return Number(row?.cursor ?? 0);
}

export async function getSnapshot(db: D1Database, windowName: string | null) {
  const now = Date.now();
  const start = now - windowToMs(windowName);
  const [totals, timeline, severities, riskyHosts, recentIncidents, sourceRows, cursorRow] = await Promise.all([
    db.prepare("SELECT COALESCE(SUM(flow_count), 0) AS flows, COALESCE(SUM(byte_count), 0) AS bytes, COALESCE(SUM(anomaly_count), 0) AS anomalies FROM flow_buckets WHERE bucket_ts >= ?1").bind(start).first<{ flows: number; bytes: number; anomalies: number }>(),
    db.prepare("SELECT bucket_ts, SUM(flow_count) AS flows, SUM(anomaly_count) AS anomalies FROM flow_buckets WHERE bucket_ts >= ?1 GROUP BY bucket_ts ORDER BY bucket_ts ASC").bind(start).all<{ bucket_ts: number; flows: number; anomalies: number }>(),
    db.prepare("SELECT severity, COUNT(*) AS count FROM incidents WHERE detected_at >= ?1 GROUP BY severity").bind(start).all<{ severity: string; count: number }>(),
    db.prepare("SELECT src_ip, MAX(max_score) AS score, SUM(connection_count) AS connections, MAX(bucket_ts) AS last_seen FROM host_buckets WHERE bucket_ts >= ?1 GROUP BY src_ip ORDER BY score DESC, connections DESC LIMIT 10").bind(start).all<{ src_ip: string; score: number; connections: number; last_seen: number }>(),
    db.prepare("SELECT id, detected_at, src_ip, dst_ip, dst_port, protocol, score, severity, reason, action, status, byte_count, packet_count FROM incidents WHERE detected_at >= ?1 ORDER BY score DESC, detected_at DESC LIMIT 50").bind(start).all(),
    db.prepare(`
      SELECT s.id, s.name, s.last_seen_at, s.spool_backlog,
             COALESCE(SUM(b.accepted_count), 0) AS accepted,
             COALESCE(SUM(b.rejected_count), 0) AS rejected
      FROM sources s LEFT JOIN ingest_batches b ON b.source_id = s.id AND b.received_at >= ?1
      GROUP BY s.id, s.name, s.last_seen_at, s.spool_backlog ORDER BY s.last_seen_at DESC
    `).bind(start).all<{ id: string; name: string; last_seen_at: number; spool_backlog: number; accepted: number; rejected: number }>(),
    db.prepare("SELECT COALESCE(MAX(id), 0) AS cursor FROM ingest_batches").first<{ cursor: number }>(),
  ]);
  const severity = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const row of severities.results) {
    if (row.severity in severity) severity[row.severity as keyof typeof severity] = Number(row.count);
  }
  const sources = sourceRows.results.map((source) => ({
    id: source.id,
    name: source.name,
    lastSeenAt: Number(source.last_seen_at),
    state: now - Number(source.last_seen_at) <= 10_000 ? "live" : "offline",
    accepted: Number(source.accepted),
    rejected: Number(source.rejected),
    spoolBacklog: Number(source.spool_backlog),
  }));
  return {
    generatedAt: now,
    cursor: Number(cursorRow?.cursor ?? 0),
    window: windowName ?? "15m",
    totals: {
      flows: Number(totals?.flows ?? 0),
      bytes: Number(totals?.bytes ?? 0),
      anomalies: Number(totals?.anomalies ?? 0),
      highCritical: severity.High + severity.Critical,
      riskyHosts: riskyHosts.results.filter((host) => Number(host.score) >= 45).length,
    },
    timeline: timeline.results.map((row) => ({ bucketTs: Number(row.bucket_ts), flows: Number(row.flows), anomalies: Number(row.anomalies) })),
    severity,
    riskyHosts: riskyHosts.results.map((row) => ({ ip: row.src_ip, score: Number(row.score), connections: Number(row.connections), lastSeenAt: Number(row.last_seen) })),
    incidents: recentIncidents.results,
    sources,
  };
}

export async function getHealth(db: D1Database) {
  const now = Date.now();
  const sources = await db.prepare("SELECT id, name, last_seen_at FROM sources ORDER BY last_seen_at DESC").all<{ id: string; name: string; last_seen_at: number }>();
  return {
    status: "ok",
    generatedAt: now,
    sources: sources.results.map((source) => ({ ...source, state: now - Number(source.last_seen_at) <= 10_000 ? "live" : "offline" })),
  };
}
