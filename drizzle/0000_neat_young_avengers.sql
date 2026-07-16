CREATE TABLE `event_dedup` (
	`source_id` text NOT NULL,
	`uid` text NOT NULL,
	`event_ts` integer NOT NULL,
	`created_at` integer NOT NULL,
	PRIMARY KEY(`source_id`, `uid`)
);
--> statement-breakpoint
CREATE INDEX `event_dedup_created_idx` ON `event_dedup` (`created_at`);--> statement-breakpoint
CREATE TABLE `flow_buckets` (
	`source_id` text NOT NULL,
	`bucket_ts` integer NOT NULL,
	`protocol` text NOT NULL,
	`flow_count` integer DEFAULT 0 NOT NULL,
	`byte_count` integer DEFAULT 0 NOT NULL,
	`packet_count` integer DEFAULT 0 NOT NULL,
	`failed_count` integer DEFAULT 0 NOT NULL,
	`anomaly_count` integer DEFAULT 0 NOT NULL,
	PRIMARY KEY(`source_id`, `bucket_ts`, `protocol`)
);
--> statement-breakpoint
CREATE INDEX `flow_buckets_time_idx` ON `flow_buckets` (`bucket_ts`);--> statement-breakpoint
CREATE TABLE `host_buckets` (
	`source_id` text NOT NULL,
	`bucket_ts` integer NOT NULL,
	`src_ip` text NOT NULL,
	`connection_count` integer DEFAULT 0 NOT NULL,
	`destinations_json` text DEFAULT '[]' NOT NULL,
	`byte_count` integer DEFAULT 0 NOT NULL,
	`packet_count` integer DEFAULT 0 NOT NULL,
	`failed_count` integer DEFAULT 0 NOT NULL,
	`max_duration_ms` integer DEFAULT 0 NOT NULL,
	`max_flow_bytes` integer DEFAULT 0 NOT NULL,
	`uncommon_port_count` integer DEFAULT 0 NOT NULL,
	`max_score` integer DEFAULT 0 NOT NULL,
	PRIMARY KEY(`source_id`, `bucket_ts`, `src_ip`)
);
--> statement-breakpoint
CREATE INDEX `host_buckets_time_idx` ON `host_buckets` (`bucket_ts`);--> statement-breakpoint
CREATE INDEX `host_buckets_risk_idx` ON `host_buckets` (`max_score`);--> statement-breakpoint
CREATE TABLE `incidents` (
	`id` text PRIMARY KEY NOT NULL,
	`source_id` text NOT NULL,
	`zeek_uid` text,
	`detected_at` integer NOT NULL,
	`src_ip` text NOT NULL,
	`dst_ip` text NOT NULL,
	`dst_port` integer NOT NULL,
	`protocol` text NOT NULL,
	`score` integer NOT NULL,
	`severity` text NOT NULL,
	`rule_codes_json` text NOT NULL,
	`reason` text NOT NULL,
	`action` text NOT NULL,
	`status` text DEFAULT 'รอตรวจสอบ' NOT NULL,
	`byte_count` integer DEFAULT 0 NOT NULL,
	`packet_count` integer DEFAULT 0 NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `incidents_source_uid_idx` ON `incidents` (`source_id`,`zeek_uid`);--> statement-breakpoint
CREATE INDEX `incidents_detected_idx` ON `incidents` (`detected_at`);--> statement-breakpoint
CREATE INDEX `incidents_score_idx` ON `incidents` (`score`);--> statement-breakpoint
CREATE TABLE `ingest_batches` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`source_id` text NOT NULL,
	`received_at` integer NOT NULL,
	`accepted_count` integer NOT NULL,
	`rejected_count` integer NOT NULL,
	`duplicate_count` integer DEFAULT 0 NOT NULL,
	`error_code` text
);
--> statement-breakpoint
CREATE INDEX `ingest_batches_received_idx` ON `ingest_batches` (`received_at`);--> statement-breakpoint
CREATE TABLE `maintenance_state` (
	`key` text PRIMARY KEY NOT NULL,
	`value` text NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `sources` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`last_seen_at` integer NOT NULL,
	`created_at` integer NOT NULL
);
