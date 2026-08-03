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
CREATE TABLE IF NOT EXISTS incident_history (
  id bigserial PRIMARY KEY,
  incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  from_status text,
  to_status text NOT NULL,
  note text,
  created_at timestamptz NOT NULL DEFAULT now()
);
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
CREATE INDEX IF NOT EXISTS event_dedup_created_idx ON event_dedup(created_at);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions(expires_at);

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS resolution text;
