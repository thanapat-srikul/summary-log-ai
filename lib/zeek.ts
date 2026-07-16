export type ZeekConnEvent = {
  uid: string;
  ts: number;
  orig_h: string;
  orig_p: number;
  resp_h: string;
  resp_p: number;
  proto: string;
  service: string | null;
  conn_state: string;
  duration: number | null;
  orig_bytes: number;
  resp_bytes: number;
  orig_pkts: number;
  resp_pkts: number;
};

export type IngestPayload = {
  sourceId: string;
  sentAt: string;
  events: ZeekConnEvent[];
};

export type ValidationResult = {
  sourceId: string | null;
  sentAt: string | null;
  events: ZeekConnEvent[];
  rejected: number;
  errors: string[];
  spoolBacklog: number;
};

const SOURCE_ID = /^[a-zA-Z0-9._-]{1,64}$/;

function finiteNumber(value: unknown, fallback: number | null = null): number | null {
  if (value === null || value === undefined || value === "" || value === "-") return fallback;
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function safeString(value: unknown, max = 128): string {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}

export function normalizeZeekEvent(value: unknown, nowMs = Date.now()): ZeekConnEvent | null {
  if (!value || typeof value !== "object") return null;
  const row = value as Record<string, unknown>;
  const uid = safeString(row.uid);
  const orig_h = safeString(row.orig_h ?? row["id.orig_h"]);
  const resp_h = safeString(row.resp_h ?? row["id.resp_h"]);
  const proto = safeString(row.proto, 24).toLowerCase();
  const conn_state = safeString(row.conn_state, 24);
  const ts = finiteNumber(row.ts);
  const orig_p = finiteNumber(row.orig_p ?? row["id.orig_p"]);
  const resp_p = finiteNumber(row.resp_p ?? row["id.resp_p"]);

  if (!uid || !orig_h || !resp_h || !proto || !conn_state || ts === null || orig_p === null || resp_p === null) return null;
  const eventMs = ts * 1000;
  if (eventMs > nowMs + 10 * 60_000 || eventMs < nowMs - 7 * 24 * 60 * 60_000) return null;
  if (orig_p < 0 || orig_p > 65535 || resp_p < 0 || resp_p > 65535) return null;

  return {
    uid,
    ts,
    orig_h,
    orig_p: Math.trunc(orig_p),
    resp_h,
    resp_p: Math.trunc(resp_p),
    proto,
    service: safeString(row.service, 64) || null,
    conn_state,
    duration: finiteNumber(row.duration),
    orig_bytes: Math.max(0, Math.trunc(finiteNumber(row.orig_bytes, 0) ?? 0)),
    resp_bytes: Math.max(0, Math.trunc(finiteNumber(row.resp_bytes, 0) ?? 0)),
    orig_pkts: Math.max(0, Math.trunc(finiteNumber(row.orig_pkts, 0) ?? 0)),
    resp_pkts: Math.max(0, Math.trunc(finiteNumber(row.resp_pkts, 0) ?? 0)),
  };
}

export function validateIngestPayload(value: unknown, nowMs = Date.now()): ValidationResult {
  const result: ValidationResult = { sourceId: null, sentAt: null, events: [], rejected: 0, errors: [], spoolBacklog: 0 };
  if (!value || typeof value !== "object") {
    result.errors.push("payload must be an object");
    return result;
  }
  const body = value as Record<string, unknown>;
  const sourceId = safeString(body.sourceId, 64);
  if (!SOURCE_ID.test(sourceId)) result.errors.push("sourceId is invalid");
  else result.sourceId = sourceId;

  const sentAt = safeString(body.sentAt, 64);
  if (!sentAt || !Number.isFinite(Date.parse(sentAt))) result.errors.push("sentAt must be an ISO timestamp");
  else result.sentAt = sentAt;
  const spoolBacklog = finiteNumber(body.spoolBacklog, 0) ?? 0;
  result.spoolBacklog = Math.min(1_000_000, Math.max(0, Math.trunc(spoolBacklog)));

  if (!Array.isArray(body.events) || body.events.length < 1 || body.events.length > 100) {
    result.errors.push("events must contain between 1 and 100 items");
    return result;
  }
  for (const event of body.events) {
    const normalized = normalizeZeekEvent(event, nowMs);
    if (normalized) result.events.push(normalized);
    else result.rejected += 1;
  }
  return result;
}

export function isFailedConnection(state: string): boolean {
  return !new Set(["SF", "S1", "S2", "S3", "RSTO", "RSTR"]).has(state.toUpperCase());
}
