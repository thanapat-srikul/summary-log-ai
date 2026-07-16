import { index, integer, primaryKey, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

export const sources = sqliteTable("sources", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  lastSeenAt: integer("last_seen_at").notNull(),
  spoolBacklog: integer("spool_backlog").notNull().default(0),
  createdAt: integer("created_at").notNull(),
});

export const eventDedup = sqliteTable("event_dedup", {
  sourceId: text("source_id").notNull(),
  uid: text("uid").notNull(),
  eventTs: integer("event_ts").notNull(),
  createdAt: integer("created_at").notNull(),
}, (table) => [
  primaryKey({ columns: [table.sourceId, table.uid] }),
  index("event_dedup_created_idx").on(table.createdAt),
]);

export const flowBuckets = sqliteTable("flow_buckets", {
  sourceId: text("source_id").notNull(),
  bucketTs: integer("bucket_ts").notNull(),
  protocol: text("protocol").notNull(),
  flowCount: integer("flow_count").notNull().default(0),
  byteCount: integer("byte_count").notNull().default(0),
  packetCount: integer("packet_count").notNull().default(0),
  failedCount: integer("failed_count").notNull().default(0),
  anomalyCount: integer("anomaly_count").notNull().default(0),
}, (table) => [
  primaryKey({ columns: [table.sourceId, table.bucketTs, table.protocol] }),
  index("flow_buckets_time_idx").on(table.bucketTs),
]);

export const hostBuckets = sqliteTable("host_buckets", {
  sourceId: text("source_id").notNull(),
  bucketTs: integer("bucket_ts").notNull(),
  srcIp: text("src_ip").notNull(),
  connectionCount: integer("connection_count").notNull().default(0),
  destinationsJson: text("destinations_json").notNull().default("[]"),
  byteCount: integer("byte_count").notNull().default(0),
  packetCount: integer("packet_count").notNull().default(0),
  failedCount: integer("failed_count").notNull().default(0),
  maxDuration: integer("max_duration_ms").notNull().default(0),
  maxFlowBytes: integer("max_flow_bytes").notNull().default(0),
  uncommonPortCount: integer("uncommon_port_count").notNull().default(0),
  maxScore: integer("max_score").notNull().default(0),
}, (table) => [
  primaryKey({ columns: [table.sourceId, table.bucketTs, table.srcIp] }),
  index("host_buckets_time_idx").on(table.bucketTs),
  index("host_buckets_risk_idx").on(table.maxScore),
]);

export const incidents = sqliteTable("incidents", {
  id: text("id").primaryKey(),
  sourceId: text("source_id").notNull(),
  zeekUid: text("zeek_uid"),
  detectedAt: integer("detected_at").notNull(),
  srcIp: text("src_ip").notNull(),
  dstIp: text("dst_ip").notNull(),
  dstPort: integer("dst_port").notNull(),
  protocol: text("protocol").notNull(),
  score: integer("score").notNull(),
  severity: text("severity").notNull(),
  ruleCodesJson: text("rule_codes_json").notNull(),
  reason: text("reason").notNull(),
  action: text("action").notNull(),
  status: text("status").notNull().default("รอตรวจสอบ"),
  byteCount: integer("byte_count").notNull().default(0),
  packetCount: integer("packet_count").notNull().default(0),
  createdAt: integer("created_at").notNull(),
}, (table) => [
  uniqueIndex("incidents_source_uid_idx").on(table.sourceId, table.zeekUid),
  index("incidents_detected_idx").on(table.detectedAt),
  index("incidents_score_idx").on(table.score),
]);

export const ingestBatches = sqliteTable("ingest_batches", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  sourceId: text("source_id").notNull(),
  receivedAt: integer("received_at").notNull(),
  acceptedCount: integer("accepted_count").notNull(),
  rejectedCount: integer("rejected_count").notNull(),
  duplicateCount: integer("duplicate_count").notNull().default(0),
  errorCode: text("error_code"),
}, (table) => [index("ingest_batches_received_idx").on(table.receivedAt)]);

export const maintenanceState = sqliteTable("maintenance_state", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
  updatedAt: integer("updated_at").notNull(),
});
