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

async function rebuildBaselines(sourceId?:string){
  const values:unknown[]=[];const sourceFilter=sourceId?(values.push(sourceId),`AND h.source_id=$${values.length}`):"";
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
  `,values);
}

async function processBaselineRebuilds(){
  const requests=await pool.query("SELECT source_id FROM baseline_rebuild_requests WHERE status='pending' ORDER BY requested_at LIMIT 10");
  for(const row of requests.rows){try{await pool.query("UPDATE baseline_rebuild_requests SET status='running',last_error=NULL WHERE source_id=$1",[row.source_id]);await rebuildBaselines(row.source_id);await pool.query("UPDATE baseline_rebuild_requests SET status='complete',completed_at=now() WHERE source_id=$1",[row.source_id]);}catch(error){await pool.query("UPDATE baseline_rebuild_requests SET status='failed',last_error=$2 WHERE source_id=$1",[row.source_id,error instanceof Error?error.message.slice(0,500):"baseline rebuild failed"]);}}
}

async function tick() {
  try { await deliverAlerts(); } catch (error) { console.error("alert worker", error); }
  try { await processBaselineRebuilds(); } catch (error) { console.error("baseline rebuild", error); }
}
await maintenance();
try { await rebuildBaselines(); } catch (error) { console.error("baseline worker", error); }
setInterval(tick, 5000);
setInterval(maintenance, 60 * 60 * 1000);
setInterval(()=>rebuildBaselines().catch(error=>console.error("baseline worker",error)),60*60*1000);
await tick();
console.log("Summary Log AI worker started");
