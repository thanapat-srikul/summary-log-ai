import crypto from "node:crypto";
import nodemailer from "nodemailer";
import pg from "pg";

const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const appSecret = process.env.APP_SECRET ?? "";

function decryptSecret(value: string) {
  const [iv, tag, data] = value.split(".");
  const key = crypto.createHash("sha256").update(appSecret).digest();
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64url"));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(data, "base64url")), decipher.final()]).toString("utf8");
}

async function deliverAlerts() {
  const rows = await pool.query(`
    SELECT d.*,i.severity,i.src_ip::text,i.dst_ip::text,i.dst_port,i.reason,i.suggested_action,
      s.name source_name,st.smtp_host,st.smtp_port,st.smtp_secure,st.smtp_username,st.smtp_password_encrypted,st.smtp_from
    FROM alert_deliveries d JOIN incidents i ON i.id=d.incident_id JOIN sources s ON s.id=i.source_id
    JOIN system_settings st ON st.organization_id=s.organization_id
    WHERE d.status IN ('pending','failed') AND d.next_attempt_at<=now() AND d.attempts<6
    ORDER BY d.created_at LIMIT 20
  `);
  for (const row of rows.rows) {
    if (!row.smtp_host || !row.smtp_from || !row.smtp_password_encrypted) continue;
    await pool.query("UPDATE alert_deliveries SET status='sending',attempts=attempts+1 WHERE id=$1", [row.id]);
    try {
      const transport = nodemailer.createTransport({ host: row.smtp_host, port: row.smtp_port, secure: row.smtp_secure, auth: row.smtp_username ? { user: row.smtp_username, pass: decryptSecret(row.smtp_password_encrypted) } : undefined });
      await transport.sendMail({
        from: row.smtp_from, to: row.recipient,
        subject: `[Summary Log AI] ${row.severity}: ${row.src_ip}`,
        text: `Source: ${row.source_name}\nSeverity: ${row.severity}\nเส้นทาง: ${row.src_ip} → ${row.dst_ip}:${row.dst_port}\nเหตุผล: ${row.reason}\nคำแนะนำ: ${row.suggested_action}`,
      });
      await pool.query("UPDATE alert_deliveries SET status='sent',sent_at=now(),last_error=NULL WHERE id=$1", [row.id]);
    } catch (error) {
      await pool.query("UPDATE alert_deliveries SET status='failed',last_error=$1,next_attempt_at=now()+(least(60,power(2,attempts))||' minutes')::interval WHERE id=$2", [error instanceof Error ? error.message.slice(0, 500) : "send failed", row.id]);
    }
  }
}

async function maintenance() {
  await pool.query("DELETE FROM sessions WHERE expires_at<now()");
  await pool.query("DELETE FROM event_dedup d USING sources s,organizations o WHERE d.source_id=s.id AND s.organization_id=o.id AND d.created_at<now()-(o.retention_days||' days')::interval");
  await pool.query("DELETE FROM flow_buckets f USING sources s,organizations o WHERE f.source_id=s.id AND s.organization_id=o.id AND f.bucket_ts<now()-(o.retention_days||' days')::interval");
  await pool.query("DELETE FROM host_buckets h USING sources s,organizations o WHERE h.source_id=s.id AND s.organization_id=o.id AND h.bucket_ts<now()-(o.retention_days||' days')::interval");
  await pool.query("DELETE FROM incidents i USING sources s,organizations o WHERE i.source_id=s.id AND s.organization_id=o.id AND i.detected_at<now()-(o.retention_days||' days')::interval");
  await pool.query("DELETE FROM ingest_batches b USING sources s,organizations o WHERE b.source_id=s.id AND s.organization_id=o.id AND b.received_at<now()-(o.retention_days||' days')::interval");
}

async function tick() {
  try { await deliverAlerts(); } catch (error) { console.error("alert worker", error); }
}
await maintenance();
setInterval(tick, 5000);
setInterval(maintenance, 60 * 60 * 1000);
await tick();
console.log("Summary Log AI worker started");
