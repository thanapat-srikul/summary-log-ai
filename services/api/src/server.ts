import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import cookie from "@fastify/cookie";
import rateLimit from "@fastify/rate-limit";
import argon2 from "argon2";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import nodemailer from "nodemailer";
import pg from "pg";
import { evaluateRules, validateEvent } from "./rules.js";
import { canTransition, type IncidentStatus } from "./incident-policy.js";

const { Pool } = pg;
const app = Fastify({ logger: { redact: ["req.headers.authorization", "req.headers.cookie", "body", "password", "apiKey"] }, bodyLimit: 1024 * 1024 });
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const sessionCookie = "summary_log_session";
const appSecret = process.env.APP_SECRET ?? "";
const allowedStates = new Set(["new", "acknowledged", "investigating", "resolved"]);
const allowedResolutions = new Set(["true_positive", "false_positive", "benign"]);
const failedStates = new Set(["S0", "REJ", "RSTO", "RSTR", "SH", "SHR", "OTH"]);
const standardPorts = new Set([20, 21, 22, 25, 53, 67, 68, 80, 110, 123, 143, 161, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443]);

type Principal = { id: string; organizationId: string; email: string; displayName: string; role: "admin" | "analyst" | "viewer"; csrfToken: string };
type AuthedRequest = FastifyRequest & { principal?: Principal };

function id() { return crypto.randomUUID(); }
function token(bytes = 32) { return crypto.randomBytes(bytes).toString("base64url"); }
function sha256(value: string) { return crypto.createHash("sha256").update(value).digest("hex"); }
function bucketDate(ts: number) { return new Date(Math.floor(ts / 60) * 60_000); }
function isEmail(value: unknown): value is string { return typeof value === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 254; }
function asText(value: unknown, max = 200) { return typeof value === "string" ? value.trim().slice(0, max) : ""; }
function audit(orgId: string, actor: string | null, action: string, targetType: string, targetId: string | null) {
  return pool.query("INSERT INTO audit_log(organization_id, actor_user_id, action, target_type, target_id) VALUES($1,$2,$3,$4,$5)", [orgId, actor, action, targetType, targetId]);
}
function encryptSecret(value: string) {
  if (!appSecret || appSecret.length < 32) throw new Error("APP_SECRET must be at least 32 characters");
  const key = crypto.createHash("sha256").update(appSecret).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return [iv.toString("base64url"), cipher.getAuthTag().toString("base64url"), encrypted.toString("base64url")].join(".");
}
function decryptSecret(value: string) {
  const [iv, tag, data] = value.split(".");
  const key = crypto.createHash("sha256").update(appSecret).digest();
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64url"));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(data, "base64url")), decipher.final()]).toString("utf8");
}

async function migrate() {
  const sql = await fs.readFile(new URL("./schema.sql", import.meta.url), "utf8");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(sql);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function principalFrom(request: FastifyRequest): Promise<Principal | null> {
  const raw = request.cookies?.[sessionCookie];
  if (!raw) return null;
  const result = await pool.query(`
    SELECT u.id, u.organization_id, u.email, u.display_name, u.role, s.csrf_token
    FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=$1 AND s.expires_at>now() AND u.active=true
  `, [sha256(raw)]);
  if (!result.rowCount) return null;
  const row = result.rows[0];
  return { id: row.id, organizationId: row.organization_id, email: row.email, displayName: row.display_name, role: row.role, csrfToken: row.csrf_token };
}

async function requireAuth(request: AuthedRequest, reply: FastifyReply) {
  const principal = await principalFrom(request);
  if (!principal) return reply.code(401).send({ error: "authentication_required" });
  request.principal = principal;
}
async function requireWrite(request: AuthedRequest, reply: FastifyReply) {
  if (!request.principal || request.principal.role === "viewer") return reply.code(403).send({ error: "insufficient_role" });
  if (request.headers["x-csrf-token"] !== request.principal.csrfToken) return reply.code(403).send({ error: "invalid_csrf_token" });
}
async function requireCsrf(request: AuthedRequest, reply: FastifyReply) {
  if (!request.principal || request.headers["x-csrf-token"] !== request.principal.csrfToken) return reply.code(403).send({ error: "invalid_csrf_token" });
}
async function requireAdmin(request: AuthedRequest, reply: FastifyReply) {
  if (!request.principal || request.principal.role !== "admin") return reply.code(403).send({ error: "admin_required" });
  if (request.headers["x-csrf-token"] !== request.principal.csrfToken) return reply.code(403).send({ error: "invalid_csrf_token" });
}

await app.register(cookie);
await app.register(rateLimit, { global: false });

app.get("/api/v1/health", async () => {
  const db = await pool.query("SELECT now() AS now");
  const sources = await pool.query("SELECT max(last_seen_at) AS latest FROM sources");
  return { status: "ok", version: "0.3.0", databaseTime: db.rows[0].now, lastBatchAt: sources.rows[0].latest };
});

app.get("/api/v1/setup/status", async () => {
  const result = await pool.query("SELECT EXISTS(SELECT 1 FROM users) AS configured");
  return { configured: result.rows[0].configured };
});

app.post("/api/v1/setup", { config: { rateLimit: { max: 5, timeWindow: "1 minute" } } }, async (request, reply) => {
  const existing = await pool.query("SELECT EXISTS(SELECT 1 FROM users) AS configured");
  if (existing.rows[0].configured) return reply.code(409).send({ error: "already_configured" });
  const body = request.body as Record<string, unknown>;
  const organizationName = asText(body.organizationName, 100);
  const displayName = asText(body.displayName, 100);
  const email = asText(body.email, 254).toLowerCase();
  const password = typeof body.password === "string" ? body.password : "";
  const timezone = asText(body.timezone, 80) || "Asia/Bangkok";
  if (!organizationName || !displayName || !isEmail(email) || password.length < 12) return reply.code(400).send({ error: "invalid_setup", message: "กรอกข้อมูลให้ครบและใช้รหัสผ่านอย่างน้อย 12 ตัวอักษร" });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const orgId = id();
    const userId = id();
    await client.query("INSERT INTO organizations(id,name,timezone) VALUES($1,$2,$3)", [orgId, organizationName, timezone]);
    await client.query("INSERT INTO users(id,organization_id,email,display_name,password_hash,role) VALUES($1,$2,$3,$4,$5,'admin')", [userId, orgId, email, displayName, await argon2.hash(password, { type: argon2.argon2id })]);
    await client.query("INSERT INTO system_settings(organization_id) VALUES($1)", [orgId]);
    await client.query("COMMIT");
    return reply.code(201).send({ configured: true });
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
});

app.post("/api/v1/auth/login", { config: { rateLimit: { max: 10, timeWindow: "15 minutes" } } }, async (request, reply) => {
  const body = request.body as Record<string, unknown>;
  const email = asText(body.email, 254).toLowerCase();
  const password = typeof body.password === "string" ? body.password : "";
  const result = await pool.query("SELECT * FROM users WHERE lower(email)=$1 AND active=true LIMIT 1", [email]);
  const user = result.rows[0];
  if (!user || !(await argon2.verify(user.password_hash, password))) return reply.code(401).send({ error: "invalid_credentials" });
  const rawToken = token();
  const csrfToken = token(24);
  await pool.query("INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at) VALUES($1,$2,$3,now()+interval '12 hours')", [sha256(rawToken), user.id, csrfToken]);
  reply.setCookie(sessionCookie, rawToken, { httpOnly: true, secure: process.env.COOKIE_SECURE !== "false", sameSite: "strict", path: "/", maxAge: 43_200 });
  return { user: { id: user.id, email: user.email, displayName: user.display_name, role: user.role }, csrfToken };
});

app.post("/api/v1/auth/logout", { preHandler: [requireAuth, requireCsrf] }, async (request: AuthedRequest, reply) => {
  const raw = request.cookies?.[sessionCookie];
  if (raw) await pool.query("DELETE FROM sessions WHERE token_hash=$1", [sha256(raw)]);
  reply.clearCookie(sessionCookie, { path: "/" });
  return { ok: true };
});
app.get("/api/v1/auth/me", { preHandler: requireAuth }, async (request: AuthedRequest) => ({ user: request.principal, csrfToken: request.principal!.csrfToken }));

app.get("/api/v1/sources", { preHandler: requireAuth }, async (request: AuthedRequest) => {
  const result = await pool.query(`
    SELECT s.id,s.name,s.active,s.last_seen_at,s.spool_backlog,s.created_at,
      coalesce(sum(b.accepted_count),0)::int accepted,coalesce(sum(b.rejected_count),0)::int rejected
    FROM sources s LEFT JOIN ingest_batches b ON b.source_id=s.id
    WHERE s.organization_id=$1 GROUP BY s.id ORDER BY s.created_at DESC
  `, [request.principal!.organizationId]);
  return { sources: result.rows };
});
app.post("/api/v1/sources", { preHandler: [requireAuth, requireAdmin] }, async (request: AuthedRequest, reply) => {
  const name = asText((request.body as Record<string, unknown>).name, 100);
  if (!name) return reply.code(400).send({ error: "name_required" });
  const duplicate = await pool.query("SELECT id FROM sources WHERE organization_id=$1 AND lower(name)=lower($2)", [request.principal!.organizationId, name]);
  if (duplicate.rowCount) return reply.code(409).send({ error: "source_name_exists", message: "มี Source ชื่อนี้อยู่แล้ว" });
  const sourceId = id();
  const apiKey = `sla_${token(32)}`;
  await pool.query("INSERT INTO sources(id,organization_id,name,api_key_hash) VALUES($1,$2,$3,$4)", [sourceId, request.principal!.organizationId, name, sha256(apiKey)]);
  await audit(request.principal!.organizationId, request.principal!.id, "source.create", "source", sourceId);
  return reply.code(201).send({ source: { id: sourceId, name }, apiKey, message: "API key จะแสดงเพียงครั้งเดียว" });
});
app.post("/api/v1/sources/:id/rotate-key", { preHandler: [requireAuth, requireAdmin] }, async (request: AuthedRequest, reply) => {
  const apiKey = `sla_${token(32)}`;
  const result = await pool.query("UPDATE sources SET api_key_hash=$1 WHERE id=$2 AND organization_id=$3 RETURNING id", [sha256(apiKey), (request.params as { id: string }).id, request.principal!.organizationId]);
  if (!result.rowCount) return reply.code(404).send({ error: "source_not_found" });
  await audit(request.principal!.organizationId, request.principal!.id, "source.rotate_key", "source", result.rows[0].id);
  return { apiKey, message: "API key จะแสดงเพียงครั้งเดียว" };
});
app.patch("/api/v1/sources/:id", { preHandler: [requireAuth, requireAdmin] }, async (request: AuthedRequest, reply) => {
  const active = (request.body as Record<string, unknown>).active;
  if (typeof active !== "boolean") return reply.code(400).send({ error: "active_required" });
  const sourceId = (request.params as { id: string }).id;
  const result = await pool.query("UPDATE sources SET active=$1 WHERE id=$2 AND organization_id=$3 RETURNING id", [active, sourceId, request.principal!.organizationId]);
  if (!result.rowCount) return reply.code(404).send({ error: "source_not_found" });
  await audit(request.principal!.organizationId, request.principal!.id, active ? "source.enable" : "source.disable", "source", sourceId);
  return { ok: true, active };
});

app.post("/api/v1/ingest/zeek", async (request, reply) => {
  const auth = request.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return reply.code(401).send({ error: "unauthorized" });
  const sourceResult = await pool.query("SELECT id,organization_id FROM sources WHERE api_key_hash=$1 AND active=true", [sha256(auth.slice(7))]);
  if (!sourceResult.rowCount) return reply.code(401).send({ error: "unauthorized" });
  const source = sourceResult.rows[0];
  const body = request.body as Record<string, unknown>;
  if (body.sourceId !== source.id || !Array.isArray(body.events) || body.events.length > 100) return reply.code(400).send({ error: "invalid_payload" });
  const events = body.events.filter(validateEvent);
  const rejected = body.events.length - events.length;
  const nowSeconds = Date.now() / 1000;
  const timely = events.filter((event) => Math.abs(event.ts - nowSeconds) <= 7 * 24 * 3600);
  const timestampRejected = events.length - timely.length;
  let accepted = 0;
  let duplicates = 0;
  let cursor = Date.now();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const event of timely) {
      const dedup = await client.query("INSERT INTO event_dedup(source_id,uid,event_ts) VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING uid", [source.id, event.uid, new Date(event.ts * 1000)]);
      if (!dedup.rowCount) { duplicates += 1; continue; }
      accepted += 1;
      const bucket = bucketDate(event.ts);
      const bytes = event.orig_bytes + event.resp_bytes;
      const packets = event.orig_pkts + event.resp_pkts;
      const failed = failedStates.has(event.conn_state) ? 1 : 0;
      const uncommon = standardPorts.has(event.resp_p) ? 0 : 1;
      await client.query(`
        INSERT INTO flow_buckets(source_id,bucket_ts,protocol,flow_count,byte_count,packet_count,failed_count)
        VALUES($1,$2,$3,1,$4,$5,$6)
        ON CONFLICT(source_id,bucket_ts,protocol) DO UPDATE SET
          flow_count=flow_buckets.flow_count+1,byte_count=flow_buckets.byte_count+excluded.byte_count,
          packet_count=flow_buckets.packet_count+excluded.packet_count,failed_count=flow_buckets.failed_count+excluded.failed_count
      `, [source.id, bucket, event.proto, bytes, packets, failed]);
      const host = await client.query(`
        INSERT INTO host_buckets(source_id,bucket_ts,src_ip,connection_count,destinations,byte_count,packet_count,failed_count,max_duration_ms,max_flow_bytes,uncommon_port_count)
        VALUES($1,$2,$3,1,ARRAY[$4::inet],$5,$6,$7,$8,$5,$9)
        ON CONFLICT(source_id,bucket_ts,src_ip) DO UPDATE SET
          connection_count=host_buckets.connection_count+1,
          destinations=(SELECT ARRAY(SELECT DISTINCT unnest(host_buckets.destinations || excluded.destinations))),
          byte_count=host_buckets.byte_count+excluded.byte_count,packet_count=host_buckets.packet_count+excluded.packet_count,
          failed_count=host_buckets.failed_count+excluded.failed_count,max_duration_ms=greatest(host_buckets.max_duration_ms,excluded.max_duration_ms),
          max_flow_bytes=greatest(host_buckets.max_flow_bytes,excluded.max_flow_bytes),
          uncommon_port_count=host_buckets.uncommon_port_count+excluded.uncommon_port_count
        RETURNING *
      `, [source.id, bucket, event.orig_h, event.resp_h, bytes, packets, failed, Math.round((event.duration ?? 0) * 1000), uncommon]);
      const h = host.rows[0];
      const rule = evaluateRules({
        connectionCount: Number(h.connection_count), uniqueDestinations: h.destinations.length, failedCount: Number(h.failed_count),
        byteCount: Number(h.byte_count), uncommonPortCount: Number(h.uncommon_port_count), maxDurationMs: Number(h.max_duration_ms), maxFlowBytes: Number(h.max_flow_bytes),
      }, event);
      await client.query("UPDATE host_buckets SET max_score=greatest(max_score,$1) WHERE source_id=$2 AND bucket_ts=$3 AND src_ip=$4", [rule.score, source.id, bucket, event.orig_h]);
      if (rule.score >= 45) {
        const allowlisted = await client.query(`
          SELECT EXISTS(SELECT 1 FROM allowlist_entries WHERE organization_id=$1
            AND (source_id IS NULL OR source_id=$2) AND (expires_at IS NULL OR expires_at>now())
            AND (cidr IS NULL OR $3::inet <<= cidr) AND (port IS NULL OR port=$4)
            AND (protocol IS NULL OR lower(protocol)=lower($5))) AS allowed
        `, [source.organization_id, source.id, event.orig_h, event.resp_p, event.proto]);
        if (!allowlisted.rows[0].allowed) {
          const observedAt = new Date(event.ts * 1000);
          const latest = await client.query(`
            SELECT id,status FROM incidents
            WHERE source_id=$1 AND src_ip=$2::inet AND last_seen_at<=$3
              AND last_seen_at>=$3::timestamptz-interval '10 minutes'
            ORDER BY last_seen_at DESC LIMIT 1 FOR UPDATE
          `, [source.id, event.orig_h, observedAt]);
          const wasResolved = latest.rows[0]?.status === "resolved";
          const incidentId = latest.rows[0]?.id ?? id();
          const incident = latest.rowCount ? await client.query(`
            UPDATE incidents SET
              last_seen_at=$2,detected_at=$2,dst_ip=$3,dst_port=$4,protocol=$5,
              score=greatest(score,$6),severity=CASE WHEN $6>score THEN $7 ELSE severity END,
              rule_codes=ARRAY(SELECT DISTINCT unnest(rule_codes || $8::text[])),
              reason=$9,suggested_action=$10,byte_count=$11,packet_count=$12,
              occurrence_count=occurrence_count+1,
              status=CASE WHEN status='resolved' THEN 'investigating' ELSE status END,
              resolution=CASE WHEN status='resolved' THEN NULL ELSE resolution END,updated_at=now()
            WHERE id=$1 RETURNING id,severity,status
          `, [incidentId, observedAt, event.resp_h, event.resp_p, event.proto, rule.score, rule.severity, rule.codes, rule.reason, rule.action, Number(h.byte_count), Number(h.packet_count)]) : await client.query(`
            INSERT INTO incidents(id,source_id,bucket_ts,detected_at,src_ip,dst_ip,dst_port,protocol,score,severity,rule_codes,reason,suggested_action,byte_count,packet_count,first_seen_at,last_seen_at,occurrence_count)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$4,$4,1)
            RETURNING id,severity,status
          `, [incidentId, source.id, bucket, observedAt, event.orig_h, event.resp_h, event.resp_p, event.proto, rule.score, rule.severity, rule.codes, rule.reason, rule.action, Number(h.byte_count), Number(h.packet_count)]);
          const occurrenceId = id();
          await client.query(`
            INSERT INTO incident_occurrences(id,incident_id,observed_at,src_ip,dst_ip,dst_port,protocol,score,severity,rule_codes,score_breakdown,connection_count,destination_count,failed_count,failed_ratio,byte_count,packet_count,max_duration_ms)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$14,$15,$16,$17,$18)
          `, [occurrenceId, incidentId, observedAt, event.orig_h, event.resp_h, event.resp_p, event.proto, rule.score, rule.severity, rule.codes, JSON.stringify(rule.matches), Number(h.connection_count), h.destinations.length, Number(h.failed_count), Number(h.failed_count) / Math.max(1, Number(h.connection_count)), Number(h.byte_count), Number(h.packet_count), Number(h.max_duration_ms)]);
          await client.query(`INSERT INTO incident_history(incident_id,from_status,to_status,action,note,metadata)
            VALUES($1,$2,$3,$4,$5,$6::jsonb)`, [incidentId, latest.rows[0]?.status ?? null, incident.rows[0].status, latest.rowCount ? (wasResolved ? "reopened" : "merged") : "created", wasResolved ? "Incident reopened after a matching occurrence" : null, JSON.stringify({ occurrenceId, observedAt })]);
          await client.query("UPDATE flow_buckets SET anomaly_count=anomaly_count+1 WHERE source_id=$1 AND bucket_ts=$2 AND protocol=$3", [source.id, bucket, event.proto]);
          if (["High", "Critical"].includes(incident.rows[0].severity)) {
            await client.query(`
              INSERT INTO alert_deliveries(id,incident_id,occurrence_id,recipient)
              SELECT gen_random_uuid(),$1,$5,recipient
              FROM system_settings settings
              CROSS JOIN unnest(settings.alert_recipients) recipient
              WHERE settings.organization_id=$2
                AND CASE settings.alert_min_severity
                  WHEN 'Critical' THEN $3='Critical'
                  WHEN 'High' THEN $3 IN ('High','Critical')
                  ELSE true END
                AND NOT EXISTS (
                  SELECT 1 FROM alert_deliveries previous
                  JOIN incidents previous_incident ON previous_incident.id=previous.incident_id
                  JOIN sources previous_source ON previous_source.id=previous_incident.source_id
                  WHERE previous.recipient=recipient AND previous_source.organization_id=$2
                    AND previous_incident.src_ip=$4::inet
                    AND previous.created_at>now()-(settings.alert_cooldown_minutes||' minutes')::interval
                )
              ON CONFLICT DO NOTHING
            `, [incident.rows[0].id, source.organization_id, incident.rows[0].severity, event.orig_h, occurrenceId]);
          }
        }
      }
      cursor = Math.max(cursor, event.ts * 1000);
    }
    await client.query("UPDATE sources SET last_seen_at=now(),spool_backlog=$1 WHERE id=$2", [Math.max(0, Number(body.spoolBacklog) || 0), source.id]);
    await client.query("INSERT INTO ingest_batches(source_id,accepted_count,rejected_count,duplicate_count) VALUES($1,$2,$3,$4)", [source.id, accepted, rejected + timestampRejected, duplicates]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
  return reply.code(202).send({ accepted, rejected: rejected + timestampRejected, duplicates, cursor });
});

app.get("/api/v1/dashboard/snapshot", { preHandler: requireAuth }, async (request: AuthedRequest) => {
  const orgId = request.principal!.organizationId;
  const minutes = Math.min(10080, Math.max(5, Number((request.query as { minutes?: string }).minutes) || 15));
  const [totals, timeline, severity, hosts, incidents, sources] = await Promise.all([
    pool.query(`SELECT coalesce(sum(flow_count),0)::bigint flows,coalesce(sum(byte_count),0)::bigint bytes,coalesce(sum(failed_count),0)::bigint failed,coalesce(sum(anomaly_count),0)::bigint anomalies FROM flow_buckets f JOIN sources s ON s.id=f.source_id WHERE s.organization_id=$1 AND f.bucket_ts>=now()-($2||' minutes')::interval`, [orgId, minutes]),
    pool.query(`SELECT extract(epoch from bucket_ts)*1000 bucket_ts,sum(flow_count)::bigint flows,sum(anomaly_count)::bigint anomalies FROM flow_buckets f JOIN sources s ON s.id=f.source_id WHERE s.organization_id=$1 AND bucket_ts>=now()-($2||' minutes')::interval GROUP BY bucket_ts ORDER BY bucket_ts`, [orgId, minutes]),
    pool.query(`SELECT severity,count(*)::int count FROM incidents i JOIN sources s ON s.id=i.source_id WHERE s.organization_id=$1 AND detected_at>=now()-($2||' minutes')::interval GROUP BY severity`, [orgId, minutes]),
    pool.query(`SELECT host.src_ip::text ip,max(host.max_score)::int score,sum(host.connection_count)::bigint connections,max(host.bucket_ts) last_seen_at FROM host_buckets host JOIN sources s ON s.id=host.source_id WHERE s.organization_id=$1 AND host.bucket_ts>=now()-($2||' minutes')::interval GROUP BY host.src_ip ORDER BY score DESC LIMIT 10`, [orgId, minutes]),
    pool.query(`SELECT i.*,s.name source_name FROM incidents i JOIN sources s ON s.id=i.source_id WHERE s.organization_id=$1 AND i.status<>'resolved' ORDER BY i.detected_at DESC LIMIT 100`, [orgId]),
    pool.query(`SELECT id,name,active,last_seen_at,spool_backlog,CASE WHEN last_seen_at>now()-interval '15 seconds' THEN 'online' WHEN last_seen_at>now()-interval '2 minutes' THEN 'delayed' ELSE 'offline' END state FROM sources WHERE organization_id=$1 ORDER BY name`, [orgId]),
  ]);
  const sev = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const row of severity.rows) sev[row.severity as keyof typeof sev] = row.count;
  const total = totals.rows[0];
  return {
    generatedAt: Date.now(), cursor: Math.max(0, ...incidents.rows.map((row) => new Date(row.updated_at).getTime())),
    totals: { flows: Number(total.flows), bytes: Number(total.bytes), failed: Number(total.failed), anomalies: Number(total.anomalies), incidents: incidents.rowCount },
    timeline: timeline.rows.map((row) => ({ bucketTs: Number(row.bucket_ts), flows: Number(row.flows), anomalies: Number(row.anomalies) })),
    severity: sev, riskyHosts: hosts.rows, incidents: incidents.rows, sources: sources.rows,
  };
});

app.get("/api/v1/incidents", { preHandler: requireAuth }, async (request: AuthedRequest) => {
  const query = request.query as { status?: string; severity?: string; sourceId?: string; assigneeId?: string; ip?: string; q?: string; from?: string; to?: string; sort?: string; order?: string; page?: string; pageSize?: string };
  const values: unknown[] = [request.principal!.organizationId];
  const where = ["s.organization_id=$1"];
  if (query.status && query.status !== "all") { values.push(query.status); where.push(`i.status=$${values.length}`); }
  if (query.severity && query.severity !== "all") { values.push(query.severity); where.push(`i.severity=$${values.length}`); }
  if (query.sourceId) { values.push(query.sourceId); where.push(`i.source_id=$${values.length}`); }
  if (query.assigneeId === "unassigned") where.push("i.assignee_user_id IS NULL");
  else if (query.assigneeId) { values.push(query.assigneeId); where.push(`i.assignee_user_id=$${values.length}`); }
  const ip = query.ip || query.q;
  if (ip) { values.push(`%${asText(ip, 100)}%`); where.push(`(i.src_ip::text ILIKE $${values.length} OR i.dst_ip::text ILIKE $${values.length} OR i.reason ILIKE $${values.length})`); }
  if (query.from && !Number.isNaN(Date.parse(query.from))) { values.push(new Date(query.from)); where.push(`i.last_seen_at>=$${values.length}`); }
  if (query.to && !Number.isNaN(Date.parse(query.to))) { values.push(new Date(query.to)); where.push(`i.first_seen_at<=$${values.length}`); }
  const sortColumns: Record<string,string> = { severity: "CASE i.severity WHEN 'Critical' THEN 3 WHEN 'High' THEN 2 ELSE 1 END", source: "s.name", ip: "i.src_ip", firstSeen: "i.first_seen_at", lastSeen: "i.last_seen_at" };
  const sort = sortColumns[query.sort || "severity"] || sortColumns.severity;
  const order = query.order === "asc" ? "ASC" : "DESC";
  const page = Math.max(1, Number(query.page) || 1);
  const pageSize = Math.min(100, Math.max(10, Number(query.pageSize) || 25));
  const count = await pool.query(`SELECT count(*)::int total FROM incidents i JOIN sources s ON s.id=i.source_id WHERE ${where.join(" AND ")}`, values);
  values.push(pageSize, (page - 1) * pageSize);
  const result = await pool.query(`SELECT i.*,s.name source_name,u.display_name assignee_name,u.email assignee_email
    FROM incidents i JOIN sources s ON s.id=i.source_id LEFT JOIN users u ON u.id=i.assignee_user_id
    WHERE ${where.join(" AND ")} ORDER BY ${sort} ${order},i.last_seen_at DESC LIMIT $${values.length - 1} OFFSET $${values.length}`, values);
  const total = Number(count.rows[0].total);
  return { incidents: result.rows, pagination: { page, pageSize, total, totalPages: Math.ceil(total / pageSize) } };
});
app.get("/api/v1/incidents/:id", { preHandler: requireAuth }, async (request: AuthedRequest, reply) => {
  const incidentId = (request.params as { id: string }).id;
  const incident = await pool.query(`SELECT i.*,s.name source_name,u.display_name assignee_name,u.email assignee_email
    FROM incidents i JOIN sources s ON s.id=i.source_id LEFT JOIN users u ON u.id=i.assignee_user_id
    WHERE i.id=$1 AND s.organization_id=$2`, [incidentId, request.principal!.organizationId]);
  if (!incident.rowCount) return reply.code(404).send({ error: "incident_not_found" });
  const [history,occurrences,assignees] = await Promise.all([
    pool.query("SELECT h.*,u.display_name actor_name FROM incident_history h LEFT JOIN users u ON u.id=h.actor_user_id WHERE h.incident_id=$1 ORDER BY h.created_at DESC", [incidentId]),
    pool.query("SELECT * FROM incident_occurrences WHERE incident_id=$1 ORDER BY observed_at DESC", [incidentId]),
    pool.query("SELECT id,display_name,email,role FROM users WHERE organization_id=$1 AND active=true AND role IN ('admin','analyst') ORDER BY display_name", [request.principal!.organizationId]),
  ]);
  return { incident: incident.rows[0], occurrences: occurrences.rows, history: history.rows, assignees: assignees.rows };
});
app.patch("/api/v1/incidents/:id", { preHandler: [requireAuth, requireWrite] }, async (request: AuthedRequest, reply) => {
  const body = request.body as Record<string, unknown>;
  const status = asText(body.status, 30);
  if (!allowedStates.has(status)) return reply.code(400).send({ error: "invalid_status" });
  const incidentId = (request.params as { id: string }).id;
  const previous = await pool.query("SELECT i.status FROM incidents i JOIN sources s ON s.id=i.source_id WHERE i.id=$1 AND s.organization_id=$2", [incidentId, request.principal!.organizationId]);
  if (!previous.rowCount) return reply.code(404).send({ error: "incident_not_found" });
  if (!canTransition(previous.rows[0].status as IncidentStatus, status as IncidentStatus)) return reply.code(409).send({ error: "invalid_status_transition", from: previous.rows[0].status, to: status });
  const resolution = asText(body.resolution, 30) || null;
  if (resolution && !allowedResolutions.has(resolution)) return reply.code(400).send({ error: "invalid_resolution" });
  if (status === "resolved" && !resolution) return reply.code(400).send({ error: "resolution_required" });
  await pool.query("UPDATE incidents SET status=$1,resolution=$2,updated_at=now() WHERE id=$3", [status, status === "resolved" ? resolution : null, incidentId]);
  await pool.query("INSERT INTO incident_history(incident_id,actor_user_id,from_status,to_status,action,note,metadata) VALUES($1,$2,$3,$4,'status_changed',$5,$6::jsonb)", [incidentId, request.principal!.id, previous.rows[0].status, status, asText(body.note, 500) || null, JSON.stringify({ resolution: status === "resolved" ? resolution : null })]);
  return { ok: true };
});
app.patch("/api/v1/incidents/:id/assignee", { preHandler: [requireAuth, requireAdmin] }, async (request: AuthedRequest, reply) => {
  const incidentId = (request.params as { id: string }).id;
  const assigneeUserId = asText((request.body as Record<string,unknown>).assigneeUserId, 80) || null;
  const incident = await pool.query("SELECT i.status,i.assignee_user_id FROM incidents i JOIN sources s ON s.id=i.source_id WHERE i.id=$1 AND s.organization_id=$2", [incidentId, request.principal!.organizationId]);
  if (!incident.rowCount) return reply.code(404).send({ error: "incident_not_found" });
  if (assigneeUserId) {
    const user = await pool.query("SELECT id FROM users WHERE id=$1 AND organization_id=$2 AND active=true AND role IN ('admin','analyst')", [assigneeUserId, request.principal!.organizationId]);
    if (!user.rowCount) return reply.code(400).send({ error: "invalid_assignee" });
  }
  const old = incident.rows[0];
  const nextStatus = assigneeUserId ? "investigating" : old.status;
  await pool.query("UPDATE incidents SET assignee_user_id=$1,status=$2,resolution=CASE WHEN $2='investigating' THEN NULL ELSE resolution END,updated_at=now() WHERE id=$3", [assigneeUserId,nextStatus,incidentId]);
  await pool.query("INSERT INTO incident_history(incident_id,actor_user_id,from_status,to_status,action,note,metadata) VALUES($1,$2,$3,$4,'assigned',NULL,$5::jsonb)", [incidentId,request.principal!.id,old.status,nextStatus,JSON.stringify({ fromAssigneeUserId: old.assignee_user_id, toAssigneeUserId: assigneeUserId })]);
  await audit(request.principal!.organizationId, request.principal!.id, "incident.assigned", "incident", incidentId);
  return { ok: true };
});
app.post("/api/v1/incidents/:id/notes", { preHandler: [requireAuth, requireWrite] }, async (request: AuthedRequest, reply) => {
  const incidentId = (request.params as { id: string }).id;
  const note = asText((request.body as Record<string, unknown>).note, 500);
  if (!note) return reply.code(400).send({ error: "note_required" });
  const incident = await pool.query("SELECT i.status FROM incidents i JOIN sources s ON s.id=i.source_id WHERE i.id=$1 AND s.organization_id=$2", [incidentId, request.principal!.organizationId]);
  if (!incident.rowCount) return reply.code(404).send({ error: "incident_not_found" });
  await pool.query("INSERT INTO incident_history(incident_id,actor_user_id,from_status,to_status,action,note) VALUES($1,$2,$3,$3,'note_added',$4)", [incidentId, request.principal!.id, incident.rows[0].status, note]);
  await pool.query("UPDATE incidents SET updated_at=now() WHERE id=$1", [incidentId]);
  return reply.code(201).send({ ok: true });
});

app.get("/api/v1/allowlist", { preHandler: requireAuth }, async (request: AuthedRequest) => {
  const result = await pool.query("SELECT a.*,s.name source_name FROM allowlist_entries a LEFT JOIN sources s ON s.id=a.source_id WHERE a.organization_id=$1 ORDER BY a.created_at DESC", [request.principal!.organizationId]);
  return { entries: result.rows };
});
app.post("/api/v1/allowlist", { preHandler: [requireAuth, requireWrite] }, async (request: AuthedRequest, reply) => {
  const body = request.body as Record<string, unknown>;
  const cidr = asText(body.cidr, 80) || null;
  const port = body.port === null || body.port === "" || body.port === undefined ? null : Number(body.port);
  const protocol = asText(body.protocol, 16).toLowerCase() || null;
  if (!cidr && port === null && !protocol) return reply.code(400).send({ error: "allowlist_condition_required" });
  const entryId = id();
  try {
    await pool.query("INSERT INTO allowlist_entries(id,organization_id,source_id,cidr,port,protocol,description,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", [entryId, request.principal!.organizationId, body.sourceId || null, cidr, port, protocol, asText(body.description, 250), body.expiresAt || null]);
  } catch {
    return reply.code(400).send({ error: "invalid_allowlist_entry" });
  }
  await audit(request.principal!.organizationId, request.principal!.id, "allowlist.create", "allowlist", entryId);
  return reply.code(201).send({ id: entryId });
});
app.delete("/api/v1/allowlist/:id", { preHandler: [requireAuth, requireWrite] }, async (request: AuthedRequest, reply) => {
  const entryId = (request.params as { id: string }).id;
  const result = await pool.query("DELETE FROM allowlist_entries WHERE id=$1 AND organization_id=$2 RETURNING id", [entryId, request.principal!.organizationId]);
  if (!result.rowCount) return reply.code(404).send({ error: "entry_not_found" });
  await audit(request.principal!.organizationId, request.principal!.id, "allowlist.delete", "allowlist", entryId);
  return { ok: true };
});

app.get("/api/v1/users", { preHandler: requireAuth }, async (request: AuthedRequest) => {
  const result = await pool.query("SELECT id,email,display_name,role,active,created_at FROM users WHERE organization_id=$1 ORDER BY created_at", [request.principal!.organizationId]);
  return { users: result.rows };
});
app.post("/api/v1/users", { preHandler: [requireAuth, requireAdmin] }, async (request: AuthedRequest, reply) => {
  const body = request.body as Record<string, unknown>;
  const email = asText(body.email, 254).toLowerCase();
  const password = typeof body.password === "string" ? body.password : "";
  const role = asText(body.role, 20);
  if (!isEmail(email) || password.length < 12 || !["admin", "analyst", "viewer"].includes(role)) return reply.code(400).send({ error: "invalid_user" });
  const userId = id();
  try {
    await pool.query("INSERT INTO users(id,organization_id,email,display_name,password_hash,role) VALUES($1,$2,$3,$4,$5,$6)", [userId, request.principal!.organizationId, email, asText(body.displayName, 100), await argon2.hash(password, { type: argon2.argon2id }), role]);
  } catch {
    return reply.code(409).send({ error: "email_exists" });
  }
  await audit(request.principal!.organizationId, request.principal!.id, "user.create", "user", userId);
  return reply.code(201).send({ id: userId });
});

app.get("/api/v1/settings", { preHandler: requireAuth }, async (request: AuthedRequest) => {
  const result = await pool.query(`SELECT o.name,o.timezone,o.retention_days,s.smtp_host,s.smtp_port,s.smtp_secure,s.smtp_username,s.smtp_from,s.alert_recipients,s.alert_min_severity,s.alert_cooldown_minutes,(s.smtp_password_encrypted IS NOT NULL) smtp_password_set FROM organizations o JOIN system_settings s ON s.organization_id=o.id WHERE o.id=$1`, [request.principal!.organizationId]);
  return { settings: result.rows[0] };
});
app.patch("/api/v1/settings", { preHandler: [requireAuth, requireAdmin] }, async (request: AuthedRequest) => {
  const body = request.body as Record<string, unknown>;
  const orgId = request.principal!.organizationId;
  await pool.query("UPDATE organizations SET name=coalesce($1,name),timezone=coalesce($2,timezone),retention_days=coalesce($3,retention_days) WHERE id=$4", [asText(body.name, 100) || null, asText(body.timezone, 80) || null, body.retentionDays ? Number(body.retentionDays) : null, orgId]);
  const encrypted = typeof body.smtpPassword === "string" && body.smtpPassword ? encryptSecret(body.smtpPassword) : null;
  await pool.query(`
    UPDATE system_settings SET smtp_host=$1,smtp_port=$2,smtp_secure=$3,smtp_username=$4,
      smtp_password_encrypted=coalesce($5,smtp_password_encrypted),smtp_from=$6,alert_recipients=$7,
      alert_min_severity=$8,alert_cooldown_minutes=$9 WHERE organization_id=$10
  `, [asText(body.smtpHost, 250) || null, Number(body.smtpPort) || null, body.smtpSecure !== false, asText(body.smtpUsername, 250) || null, encrypted, asText(body.smtpFrom, 254) || null, Array.isArray(body.alertRecipients) ? body.alertRecipients.filter(isEmail) : [], ["Medium", "High", "Critical"].includes(String(body.alertMinSeverity)) ? body.alertMinSeverity : "High", Math.max(1, Number(body.alertCooldownMinutes) || 15), orgId]);
  await audit(orgId, request.principal!.id, "settings.update", "organization", orgId);
  return { ok: true };
});
app.post("/api/v1/settings/test-email", { preHandler: [requireAuth, requireAdmin] }, async (request: AuthedRequest, reply) => {
  const result = await pool.query("SELECT * FROM system_settings WHERE organization_id=$1", [request.principal!.organizationId]);
  const settings = result.rows[0];
  if (!settings.smtp_host || !settings.smtp_password_encrypted || !settings.smtp_from || !settings.alert_recipients.length) return reply.code(400).send({ error: "smtp_not_configured" });
  const transporter = nodemailer.createTransport({ host: settings.smtp_host, port: settings.smtp_port, secure: settings.smtp_secure, auth: settings.smtp_username ? { user: settings.smtp_username, pass: decryptSecret(settings.smtp_password_encrypted) } : undefined });
  await transporter.sendMail({ from: settings.smtp_from, to: settings.alert_recipients, subject: "[Summary Log AI] ทดสอบการแจ้งเตือน", text: "การตั้งค่า SMTP ใช้งานได้สำเร็จ" });
  return { ok: true };
});

app.get("/api/v1/stream", { preHandler: requireAuth }, async (request: AuthedRequest, reply) => {
  reply.hijack();
  const response = reply.raw;
  response.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache, no-transform", Connection: "keep-alive", "X-Accel-Buffering": "no" });
  let cursor = Number((request.query as { cursor?: string }).cursor) || 0;
  const orgId = request.principal!.organizationId;
  const poll = setInterval(async () => {
    try {
      const result = await pool.query("SELECT coalesce(max(extract(epoch from i.updated_at)*1000),0)::bigint cursor FROM incidents i JOIN sources s ON s.id=i.source_id WHERE s.organization_id=$1", [orgId]);
      const next = Number(result.rows[0].cursor);
      if (next > cursor) {
        cursor = next;
        response.write(`event: update\ndata: ${JSON.stringify({ cursor })}\n\n`);
      }
    } catch {
      response.end();
    }
  }, 2000);
  const heartbeat = setInterval(() => response.write(`event: heartbeat\ndata: ${Date.now()}\n\n`), 15000);
  const close = setTimeout(() => response.end(), 60000);
  request.raw.on("close", () => { clearInterval(poll); clearInterval(heartbeat); clearTimeout(close); });
});

app.setErrorHandler((error, _request, reply) => {
  app.log.error({ err: error }, "request failed");
  if (!reply.sent) reply.code(500).send({ error: "internal_error" });
});

await migrate();
await app.listen({ host: "0.0.0.0", port: Number(process.env.PORT) || 8080 });
