CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS organizations (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  timezone text NOT NULL DEFAULT 'Asia/Bangkok',
  retention_days integer NOT NULL DEFAULT 30 CHECK (retention_days BETWEEN 1 AND 3650),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email text NOT NULL,
  display_name text NOT NULL,
  password_hash text NOT NULL,
  role text NOT NULL CHECK (role IN ('admin','analyst','viewer')),
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, email)
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sources (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL,
  api_key_hash text NOT NULL UNIQUE,
  active boolean NOT NULL DEFAULT true,
  last_seen_at timestamptz,
  spool_backlog integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS event_dedup (
  source_id uuid NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  uid text NOT NULL,
  event_ts timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (source_id, uid)
);
CREATE TABLE IF NOT EXISTS flow_buckets (
  source_id uuid NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  bucket_ts timestamptz NOT NULL,
  protocol text NOT NULL,
  flow_count bigint NOT NULL DEFAULT 0,
  byte_count bigint NOT NULL DEFAULT 0,
  packet_count bigint NOT NULL DEFAULT 0,
  failed_count bigint NOT NULL DEFAULT 0,
  anomaly_count bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (source_id, bucket_ts, protocol)
);
CREATE TABLE IF NOT EXISTS host_buckets (
  source_id uuid NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  bucket_ts timestamptz NOT NULL,
  src_ip inet NOT NULL,
  connection_count bigint NOT NULL DEFAULT 0,
  destinations inet[] NOT NULL DEFAULT '{}',
  byte_count bigint NOT NULL DEFAULT 0,
  packet_count bigint NOT NULL DEFAULT 0,
  failed_count bigint NOT NULL DEFAULT 0,
  max_duration_ms bigint NOT NULL DEFAULT 0,
  max_flow_bytes bigint NOT NULL DEFAULT 0,
  uncommon_port_count bigint NOT NULL DEFAULT 0,
  max_score integer NOT NULL DEFAULT 0,
  PRIMARY KEY (source_id, bucket_ts, src_ip)
);
CREATE TABLE IF NOT EXISTS incidents (
  id uuid PRIMARY KEY,
  source_id uuid NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  bucket_ts timestamptz NOT NULL,
  detected_at timestamptz NOT NULL,
  src_ip inet NOT NULL,
  dst_ip inet NOT NULL,
  dst_port integer NOT NULL,
  protocol text NOT NULL,
  score integer NOT NULL CHECK (score BETWEEN 0 AND 100),
  severity text NOT NULL CHECK (severity IN ('Medium','High','Critical')),
  rule_codes text[] NOT NULL,
  reason text NOT NULL,
  suggested_action text NOT NULL,
  status text NOT NULL DEFAULT 'new' CHECK (status IN ('new','acknowledged','investigating','resolved')),
  resolution text CHECK (resolution IS NULL OR resolution IN ('true_positive','false_positive','benign')),
  byte_count bigint NOT NULL DEFAULT 0,
  packet_count bigint NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (source_id, bucket_ts, src_ip)
);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS assignee_user_id uuid REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS first_seen_at timestamptz;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS last_seen_at timestamptz;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS occurrence_count integer NOT NULL DEFAULT 1;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS suppressed_count integer NOT NULL DEFAULT 0;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS last_suppressed_at timestamptz;
UPDATE incidents SET first_seen_at=coalesce(first_seen_at,detected_at),last_seen_at=coalesce(last_seen_at,detected_at);
ALTER TABLE incidents ALTER COLUMN first_seen_at SET NOT NULL;
ALTER TABLE incidents ALTER COLUMN last_seen_at SET NOT NULL;
ALTER TABLE incidents DROP CONSTRAINT IF EXISTS incidents_source_id_bucket_ts_src_ip_key;
CREATE TABLE IF NOT EXISTS incident_history (
  id bigserial PRIMARY KEY,
  incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  from_status text,
  to_status text NOT NULL,
  note text,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE incident_history ADD COLUMN IF NOT EXISTS action text NOT NULL DEFAULT 'status_changed';
ALTER TABLE incident_history ADD COLUMN IF NOT EXISTS metadata jsonb NOT NULL DEFAULT '{}'::jsonb;
CREATE TABLE IF NOT EXISTS incident_occurrences (
  id uuid PRIMARY KEY,
  incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  observed_at timestamptz NOT NULL,
  src_ip inet NOT NULL,
  dst_ip inet NOT NULL,
  dst_port integer NOT NULL,
  protocol text NOT NULL,
  score integer NOT NULL CHECK (score BETWEEN 0 AND 100),
  severity text NOT NULL CHECK (severity IN ('Medium','High','Critical')),
  rule_codes text[] NOT NULL,
  score_breakdown jsonb NOT NULL DEFAULT '[]'::jsonb,
  connection_count bigint NOT NULL DEFAULT 0,
  destination_count bigint NOT NULL DEFAULT 0,
  failed_count bigint NOT NULL DEFAULT 0,
  failed_ratio double precision NOT NULL DEFAULT 0,
  byte_count bigint NOT NULL DEFAULT 0,
  packet_count bigint NOT NULL DEFAULT 0,
  max_duration_ms bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO incident_occurrences(id,incident_id,observed_at,src_ip,dst_ip,dst_port,protocol,score,severity,rule_codes,byte_count,packet_count)
SELECT gen_random_uuid(),i.id,i.detected_at,i.src_ip,i.dst_ip,i.dst_port,i.protocol,i.score,i.severity,i.rule_codes,i.byte_count,i.packet_count
FROM incidents i WHERE NOT EXISTS (SELECT 1 FROM incident_occurrences o WHERE o.incident_id=i.id);
CREATE TABLE IF NOT EXISTS allowlist_entries (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  source_id uuid REFERENCES sources(id) ON DELETE CASCADE,
  cidr cidr,
  port integer,
  protocol text,
  description text NOT NULL,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (cidr IS NOT NULL OR port IS NOT NULL OR protocol IS NOT NULL)
);
CREATE TABLE IF NOT EXISTS rule_configs (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  source_id uuid REFERENCES sources(id) ON DELETE CASCADE,
  rule_code text NOT NULL,
  enabled boolean NOT NULL,
  points integer NOT NULL CHECK (points BETWEEN 0 AND 100),
  threshold jsonb NOT NULL,
  cooldown_minutes integer NOT NULL CHECK (cooldown_minutes BETWEEN 1 AND 1440),
  updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS rule_configs_default_idx ON rule_configs(organization_id,rule_code) WHERE source_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS rule_configs_source_idx ON rule_configs(source_id,rule_code) WHERE source_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS baseline_profiles (
  source_id uuid NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  hour_of_day integer NOT NULL CHECK (hour_of_day BETWEEN 0 AND 23),
  rule_code text NOT NULL,
  sample_count integer NOT NULL,
  day_count integer NOT NULL,
  median double precision NOT NULL,
  p95 double precision NOT NULL,
  mad double precision NOT NULL,
  suggested_threshold double precision NOT NULL,
  status text NOT NULL CHECK (status IN ('learning','ready','insufficient_data')),
  computed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(source_id,hour_of_day,rule_code)
);
CREATE TABLE IF NOT EXISTS baseline_rebuild_requests (
  source_id uuid PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE,
  requested_by uuid REFERENCES users(id) ON DELETE SET NULL,
  requested_at timestamptz NOT NULL DEFAULT now(),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','complete','failed')),
  completed_at timestamptz,
  last_error text
);
CREATE TABLE IF NOT EXISTS rule_suppressions (
  source_id uuid NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  src_ip inet NOT NULL,
  rule_code text NOT NULL,
  incident_id uuid REFERENCES incidents(id) ON DELETE SET NULL,
  last_triggered_at timestamptz NOT NULL,
  cooldown_until timestamptz NOT NULL,
  suppressed_count integer NOT NULL DEFAULT 0,
  max_actual double precision NOT NULL DEFAULT 0,
  PRIMARY KEY(source_id,src_ip,rule_code)
);
CREATE TABLE IF NOT EXISTS ingest_batches (
  id bigserial PRIMARY KEY,
  source_id uuid NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  received_at timestamptz NOT NULL DEFAULT now(),
  accepted_count integer NOT NULL,
  rejected_count integer NOT NULL,
  duplicate_count integer NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS system_settings (
  organization_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  smtp_host text,
  smtp_port integer,
  smtp_secure boolean NOT NULL DEFAULT true,
  smtp_username text,
  smtp_password_encrypted text,
  smtp_from text,
  alert_recipients text[] NOT NULL DEFAULT '{}',
  alert_min_severity text NOT NULL DEFAULT 'High',
  alert_cooldown_minutes integer NOT NULL DEFAULT 15
);
CREATE TABLE IF NOT EXISTS alert_deliveries (
  id uuid PRIMARY KEY,
  incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  recipient text NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sending','sent','failed')),
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_error text,
  sent_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (incident_id, recipient)
);
ALTER TABLE alert_deliveries ADD COLUMN IF NOT EXISTS occurrence_id uuid REFERENCES incident_occurrences(id) ON DELETE CASCADE;
ALTER TABLE alert_deliveries DROP CONSTRAINT IF EXISTS alert_deliveries_incident_id_recipient_key;
CREATE UNIQUE INDEX IF NOT EXISTS alert_deliveries_occurrence_recipient_idx ON alert_deliveries(occurrence_id,recipient) WHERE occurrence_id IS NOT NULL;
ALTER TABLE alert_deliveries ALTER COLUMN incident_id DROP NOT NULL;
ALTER TABLE alert_deliveries ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE alert_deliveries ADD COLUMN IF NOT EXISTS channel text NOT NULL DEFAULT 'email';
ALTER TABLE alert_deliveries ADD COLUMN IF NOT EXISTS delivery_type text NOT NULL DEFAULT 'legacy';
ALTER TABLE alert_deliveries ADD COLUMN IF NOT EXISTS window_start timestamptz;
ALTER TABLE alert_deliveries ADD COLUMN IF NOT EXISTS window_end timestamptz;
ALTER TABLE alert_deliveries ADD COLUMN IF NOT EXISTS highest_severity text;
ALTER TABLE alert_deliveries ADD COLUMN IF NOT EXISTS subject text;
ALTER TABLE alert_deliveries ADD COLUMN IF NOT EXISTS item_count integer NOT NULL DEFAULT 1;
ALTER TABLE alert_deliveries ADD COLUMN IF NOT EXISTS suppressed_count integer NOT NULL DEFAULT 0;
ALTER TABLE alert_deliveries ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
UPDATE alert_deliveries d SET organization_id=s.organization_id,window_start=coalesce(d.window_start,d.created_at),window_end=coalesce(d.window_end,d.created_at),highest_severity=coalesce(d.highest_severity,i.severity),subject=coalesce(d.subject,'Legacy incident alert')
FROM incidents i JOIN sources s ON s.id=i.source_id WHERE d.incident_id=i.id AND d.organization_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS alert_deliveries_digest_group_idx ON alert_deliveries(organization_id,recipient,channel,delivery_type,window_start) WHERE delivery_type='digest';
CREATE INDEX IF NOT EXISTS alert_deliveries_history_idx ON alert_deliveries(organization_id,created_at DESC);
CREATE INDEX IF NOT EXISTS alert_deliveries_queue_idx ON alert_deliveries(status,next_attempt_at,window_end);
CREATE TABLE IF NOT EXISTS alert_delivery_items (
  id bigserial PRIMARY KEY,
  delivery_id uuid NOT NULL REFERENCES alert_deliveries(id) ON DELETE CASCADE,
  incident_id uuid REFERENCES incidents(id) ON DELETE SET NULL,
  occurrence_id uuid REFERENCES incident_occurrences(id) ON DELETE SET NULL,
  severity text NOT NULL,
  summary jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(delivery_id,occurrence_id)
);
INSERT INTO alert_delivery_items(delivery_id,incident_id,occurrence_id,severity,summary)
SELECT d.id,d.incident_id,d.occurrence_id,coalesce(d.highest_severity,'High'),jsonb_build_object('legacy',true)
FROM alert_deliveries d WHERE d.incident_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM alert_delivery_items x WHERE x.delivery_id=d.id);
CREATE INDEX IF NOT EXISTS alert_delivery_items_incident_idx ON alert_delivery_items(incident_id,delivery_id);
CREATE TABLE IF NOT EXISTS alert_attempts (
  id bigserial PRIMARY KEY,
  delivery_id uuid NOT NULL REFERENCES alert_deliveries(id) ON DELETE CASCADE,
  attempt_no integer NOT NULL,
  status text NOT NULL,
  error text,
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);
CREATE INDEX IF NOT EXISTS alert_attempts_delivery_idx ON alert_attempts(delivery_id,started_at DESC);
CREATE TABLE IF NOT EXISTS alert_suppressions (
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  recipient text NOT NULL,
  channel text NOT NULL DEFAULT 'email',
  source_id uuid NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  src_ip inet NOT NULL,
  last_delivery_id uuid REFERENCES alert_deliveries(id) ON DELETE SET NULL,
  last_triggered_at timestamptz NOT NULL,
  cooldown_until timestamptz NOT NULL,
  suppressed_count integer NOT NULL DEFAULT 0,
  PRIMARY KEY(organization_id,recipient,channel,source_id,src_ip)
);
CREATE INDEX IF NOT EXISTS alert_suppressions_cooldown_idx ON alert_suppressions(cooldown_until);
CREATE TABLE IF NOT EXISTS audit_log (
  id bigserial PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  action text NOT NULL,
  target_type text NOT NULL,
  target_id text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS flow_buckets_time_idx ON flow_buckets(bucket_ts);
CREATE INDEX IF NOT EXISTS host_buckets_risk_idx ON host_buckets(bucket_ts, max_score DESC);
CREATE INDEX IF NOT EXISTS incidents_detected_idx ON incidents(detected_at DESC);
CREATE INDEX IF NOT EXISTS incidents_merge_idx ON incidents(source_id,src_ip,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS incidents_assignee_idx ON incidents(assignee_user_id,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS incidents_filter_idx ON incidents(status,severity,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS incident_occurrences_incident_idx ON incident_occurrences(incident_id,observed_at DESC);
CREATE INDEX IF NOT EXISTS baseline_profiles_status_idx ON baseline_profiles(source_id,status,computed_at DESC);
CREATE INDEX IF NOT EXISTS rule_suppressions_cooldown_idx ON rule_suppressions(cooldown_until);
CREATE INDEX IF NOT EXISTS event_dedup_created_idx ON event_dedup(created_at);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions(expires_at);

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS resolution text;
