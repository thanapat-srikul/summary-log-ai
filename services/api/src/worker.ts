import crypto from "node:crypto";
import nodemailer from "nodemailer";
import pg from "pg";
import { ALERT_EMAIL_ITEM_LIMIT, ALERT_MAX_ATTEMPTS, retryDelayMinutes } from "./alert-policy.js";

const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const appSecret = process.env.APP_SECRET ?? "";
const appBaseUrl = (process.env.APP_BASE_URL || "http://localhost").replace(/\/$/, "");

function decryptSecret(value: string) {
  const [iv, tag, data] = value.split(".");
  const key = crypto.createHash("sha256").update(appSecret).digest();
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64url"));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(data, "base64url")), decipher.final()]).toString("utf8");
}

type AlertItem = { incident_id: string | null; summary: Record<string, unknown>; severity: string };
type SmtpSettings={smtp_host:string;smtp_port:number;smtp_secure:boolean;smtp_username?:string|null;smtp_password_encrypted?:string|null;smtp_from:string};
type TransportMessage={settings:SmtpSettings;recipient:string;subject:string;text:string;html:string};
type NotificationTransport={send:(message:TransportMessage)=>Promise<void>};
const escapeHtml = (value: unknown) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]!);

const notificationTransports:Record<string,NotificationTransport>={email:{async send(message){const settings=message.settings;const transport=nodemailer.createTransport({host:settings.smtp_host,port:settings.smtp_port,secure:settings.smtp_secure,auth:settings.smtp_username?{user:settings.smtp_username,pass:decryptSecret(settings.smtp_password_encrypted!)}:undefined});await transport.sendMail({from:settings.smtp_from,to:message.recipient,subject:message.subject,text:message.text,html:message.html});}}};

function renderDigest(delivery: Record<string, unknown>, items: AlertItem[], total: number) {
  if (delivery.delivery_type === "test") return { text: "Summary Log AI SMTP test completed successfully.", html: "<p><strong>Summary Log AI</strong></p><p>SMTP test completed successfully.</p>" };
  const lines = items.map((item, index) => {
    const row = item.summary;
    return `${index + 1}. [${item.severity}] ${row.source || "Source"}: ${row.srcIp || "?"} -> ${row.dstIp || "?"}:${row.dstPort || "?"}/${row.protocol || "?"} | Score ${row.score || 0} | Rules ${(row.ruleCodes as string[] || []).join(", ")} | ${row.suggestedAction || "Review the incident"} | ${appBaseUrl}/app/incidents/${item.incident_id}`;
  });
  const remaining = Math.max(0, total - items.length);
  const header = `${delivery.highest_severity || "High"} security digest: ${total} incident${total === 1 ? "" : "s"}`;
  const text = [header, `Window: ${delivery.window_start} - ${delivery.window_end}`, "", ...lines, remaining ? `\n+${remaining} more incidents. Open ${appBaseUrl}/app/alerts/${delivery.id}` : "", `\nDashboard: ${appBaseUrl}/app`].join("\n");
  const cards = items.map((item) => {
    const row = item.summary;
    return `<tr><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(row.source)}</td><td>${escapeHtml(row.srcIp)} &rarr; ${escapeHtml(row.dstIp)}:${escapeHtml(row.dstPort)}/${escapeHtml(row.protocol)}</td><td>${escapeHtml(row.score)}</td><td>${escapeHtml((row.ruleCodes as string[] || []).join(", "))}</td><td><a href="${appBaseUrl}/app/incidents/${item.incident_id}">Open</a></td></tr>`;
  }).join("");
  const html = `<h2>${escapeHtml(header)}</h2><p>${escapeHtml(String(delivery.window_start))} - ${escapeHtml(String(delivery.window_end))}</p><table border="1" cellpadding="8" cellspacing="0"><thead><tr><th>Severity</th><th>Source</th><th>Route</th><th>Score</th><th>Rules</th><th>Incident</th></tr></thead><tbody>${cards}</tbody></table>${remaining ? `<p>+${remaining} more incidents. <a href="${appBaseUrl}/app/alerts/${delivery.id}">Open full alert</a></p>` : ""}<p><a href="${appBaseUrl}/app">Open Dashboard</a></p>`;
  return { text, html };
}

async function deliverAlerts() {
  for (let index = 0; index < 20; index++) {
    const claimed = await pool.query(`UPDATE alert_deliveries SET status='sending',attempts=attempts+1,updated_at=now() WHERE id=(
      SELECT id FROM alert_deliveries WHERE status IN ('pending','failed') AND next_attempt_at<=now() AND attempts<$1
        AND (delivery_type='test' OR window_end IS NULL OR window_end<=now()) ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1
      ) RETURNING *`, [ALERT_MAX_ATTEMPTS]);
    if (!claimed.rowCount) break;
    const delivery = claimed.rows[0];
    const attemptNo = Number(delivery.attempts);
    const started = new Date();
    try {
      const settingsResult = await pool.query("SELECT * FROM system_settings WHERE organization_id=$1", [delivery.organization_id]);
      const settings = settingsResult.rows[0];
      if (!settings?.smtp_host || !settings.smtp_from) throw new Error("SMTP is not configured");
      if (settings.smtp_username && !settings.smtp_password_encrypted) throw new Error("SMTP password is not configured");
      const itemResult = await pool.query("SELECT incident_id,severity,summary FROM alert_delivery_items WHERE delivery_id=$1 ORDER BY created_at LIMIT $2", [delivery.id, ALERT_EMAIL_ITEM_LIMIT]);
      const content = renderDigest(delivery, itemResult.rows as AlertItem[], Number(delivery.item_count) || 0);
      const subject=delivery.delivery_type==="test"?(delivery.subject||"[Summary Log AI] SMTP test"):`[Summary Log AI] ${delivery.highest_severity||"High"} security digest`;
      const selectedTransport=notificationTransports[String(delivery.channel||"email")];if(!selectedTransport)throw new Error(`Unsupported notification channel: ${delivery.channel}`);
      await selectedTransport.send({settings:settings as SmtpSettings,recipient:delivery.recipient,subject,text:content.text,html:content.html});
      await pool.query("UPDATE alert_deliveries SET status='sent',sent_at=now(),last_error=NULL,updated_at=now() WHERE id=$1", [delivery.id]);
      await pool.query("INSERT INTO alert_attempts(delivery_id,attempt_no,status,started_at,completed_at) VALUES($1,$2,'sent',$3,now())", [delivery.id, attemptNo, started]);
    } catch (error) {
      const message = error instanceof Error ? error.message.slice(0, 500) : "send failed";
      const delay = retryDelayMinutes(attemptNo);
      await pool.query("UPDATE alert_deliveries SET status='failed',last_error=$1,next_attempt_at=now()+($2||' minutes')::interval,updated_at=now() WHERE id=$3", [message, delay, delivery.id]);
      await pool.query("INSERT INTO alert_attempts(delivery_id,attempt_no,status,error,started_at,completed_at) VALUES($1,$2,'failed',$3,$4,now())", [delivery.id, attemptNo, message, started]);
    }
  }
}

async function maintenance() {
  await pool.query("DELETE FROM sessions WHERE expires_at<now()");
  await pool.query("UPDATE alert_deliveries SET status='failed',last_error='Worker interrupted during delivery',next_attempt_at=now(),updated_at=now() WHERE status='sending' AND updated_at<now()-interval '10 minutes'");
  await pool.query("DELETE FROM event_dedup d USING sources s,organizations o WHERE d.source_id=s.id AND s.organization_id=o.id AND d.created_at<now()-(o.retention_days||' days')::interval");
  await pool.query("DELETE FROM flow_buckets f USING sources s,organizations o WHERE f.source_id=s.id AND s.organization_id=o.id AND f.bucket_ts<now()-(o.retention_days||' days')::interval");
  await pool.query("DELETE FROM host_buckets h USING sources s,organizations o WHERE h.source_id=s.id AND s.organization_id=o.id AND h.bucket_ts<now()-(o.retention_days||' days')::interval");
  await pool.query("DELETE FROM incidents i USING sources s,organizations o WHERE i.source_id=s.id AND s.organization_id=o.id AND i.detected_at<now()-(o.retention_days||' days')::interval");
  await pool.query("DELETE FROM ingest_batches b USING sources s,organizations o WHERE b.source_id=s.id AND s.organization_id=o.id AND b.received_at<now()-(o.retention_days||' days')::interval");
  await pool.query("DELETE FROM alert_deliveries d USING organizations o WHERE d.organization_id=o.id AND d.created_at<now()-(o.retention_days||' days')::interval");
  await pool.query("DELETE FROM alert_suppressions WHERE cooldown_until<now()-interval '1 day'");
}

async function rebuildBaselines(sourceId?: string) {
  const values: unknown[] = [];
  const sourceFilter = sourceId ? (values.push(sourceId), `AND h.source_id=$${values.length}`) : "";
  await pool.query(`
    WITH samples AS (
      SELECT h.source_id,extract(hour FROM h.bucket_ts AT TIME ZONE o.timezone)::int hour_of_day,
        metric.rule_code,metric.value,((h.bucket_ts AT TIME ZONE o.timezone)::date) sample_day
      FROM host_buckets h JOIN sources s ON s.id=h.source_id JOIN organizations o ON o.id=s.organization_id
      CROSS JOIN LATERAL (VALUES
        ('HIGH_CONNECTION_RATE',h.connection_count::double precision),
        ('MANY_DESTINATIONS',cardinality(h.destinations)::double precision),
        ('HIGH_FAILURE_RATIO',h.failed_count::double precision),
        ('HIGH_TRANSFER_VOLUME',h.byte_count::double precision),
        ('LONG_CONNECTION',h.max_duration_ms::double precision),
        ('LARGE_SINGLE_FLOW',h.max_flow_bytes::double precision)
      ) metric(rule_code,value)
      WHERE h.bucket_ts>=now()-interval '7 days' AND h.bucket_ts<date_trunc('hour',now()) ${sourceFilter}
        AND NOT EXISTS (SELECT 1 FROM incidents i JOIN incident_occurrences io ON io.incident_id=i.id
          WHERE i.source_id=h.source_id AND io.src_ip=h.src_ip AND i.resolution='true_positive'
            AND date_trunc('minute',io.observed_at)=h.bucket_ts)
    ), medians AS (
      SELECT source_id,hour_of_day,rule_code,count(*)::int sample_count,count(DISTINCT sample_day)::int day_count,
        percentile_cont(.5) WITHIN GROUP(ORDER BY value) median,
        percentile_cont(.95) WITHIN GROUP(ORDER BY value) p95
      FROM samples GROUP BY source_id,hour_of_day,rule_code
    ), stats AS (
      SELECT m.*,coalesce(percentile_cont(.5) WITHIN GROUP(ORDER BY abs(s.value-m.median)),0)::double precision mad
      FROM medians m JOIN samples s USING(source_id,hour_of_day,rule_code)
      GROUP BY m.source_id,m.hour_of_day,m.rule_code,m.sample_count,m.day_count,m.median,m.p95
    )
    INSERT INTO baseline_profiles(source_id,hour_of_day,rule_code,sample_count,day_count,median,p95,mad,suggested_threshold,status,computed_at)
    SELECT source_id,hour_of_day,rule_code,sample_count,day_count,median,p95,mad,ceil(greatest(0,p95+3*mad)),
      CASE WHEN sample_count>=100 AND day_count>=3 THEN 'ready' ELSE 'insufficient_data' END,now() FROM stats
    ON CONFLICT(source_id,hour_of_day,rule_code) DO UPDATE SET sample_count=excluded.sample_count,day_count=excluded.day_count,
      median=excluded.median,p95=excluded.p95,mad=excluded.mad,suggested_threshold=excluded.suggested_threshold,status=excluded.status,computed_at=now()
  `, values);
}

async function processBaselineRebuilds() {
  const requests = await pool.query("SELECT source_id FROM baseline_rebuild_requests WHERE status='pending' ORDER BY requested_at LIMIT 10");
  for (const row of requests.rows) {
    try {
      await pool.query("UPDATE baseline_rebuild_requests SET status='running',last_error=NULL WHERE source_id=$1", [row.source_id]);
      await rebuildBaselines(row.source_id);
      await pool.query("UPDATE baseline_rebuild_requests SET status='complete',completed_at=now() WHERE source_id=$1", [row.source_id]);
    } catch (error) {
      await pool.query("UPDATE baseline_rebuild_requests SET status='failed',last_error=$2 WHERE source_id=$1", [row.source_id, error instanceof Error ? error.message.slice(0, 500) : "baseline rebuild failed"]);
    }
  }
}

async function tick() {
  try { await deliverAlerts(); } catch (error) { console.error("alert worker", error); }
  try { await processBaselineRebuilds(); } catch (error) { console.error("baseline rebuild", error); }
}
await maintenance();
try { await rebuildBaselines(); } catch (error) { console.error("baseline worker", error); }
setInterval(tick, 5000);
setInterval(maintenance, 60 * 60 * 1000);
setInterval(() => rebuildBaselines().catch((error) => console.error("baseline worker", error)), 60 * 60 * 1000);
await tick();
console.log("Summary Log AI worker started");
