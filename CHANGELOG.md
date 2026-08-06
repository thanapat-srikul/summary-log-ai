# Changelog

## 0.5.0

- Group qualifying Incident alerts into one email per recipient every five minutes.
- Add a secondary per-recipient, Source, and Source IP email cooldown with suppression counters.
- Add durable delivery items and attempt history without storing Raw Zeek Logs.
- Add Alert History and Alert Detail pages with filtering, status KPIs, error details, and Admin retry.
- Queue Test Email through the Worker so successful and failed tests appear in Alert History.
- Prepare the notification model for future LINE and Microsoft Teams transports while enabling email only.

## 0.4.0

- Add Admin-managed organization rule defaults and per-Source overrides for thresholds, scores, enabled state, and cooldown.
- Build automatic seven-day hourly baselines from summary buckets using median, P95, and MAD without storing Raw Logs.
- Add rule-level suppression and cooldown so repeated matches update evidence and counters without duplicate occurrences or email.
- Add a Rule Management page showing Admin, Baseline, and effective thresholds with reset and rebuild controls.
- Expand Allowlist management with search, expiry state, Source scope, CIDR, port, and protocol filters.
- Show threshold origin and suppressed matches in Incident score breakdowns.

## 0.3.0

- Merge matching incidents from the same Source and Source IP within a ten-minute window, including resolved-incident reopening.
- Store occurrence summaries, score breakdowns, assignees, first/last seen timestamps, and auditable workflow history without Raw Logs.
- Add strict New → Acknowledged → Investigating → Resolved transitions and required resolution classifications.
- Add Admin-only assignment to active Admin/Analyst users and Viewer read-only enforcement.
- Add full Incident List and Incident Detail routes with URL filters, sorting, pagination, evidence, notes, workflow actions, and occurrence timeline.

## 0.2.1

- Display dashboard, source, incident, chart, and history timestamps in the configured organization timezone.
- Fall back safely to `Asia/Bangkok` when the configured timezone is missing or invalid.
- Show the active timezone beside the live dashboard update time.

## 0.2.0

- Redesigned the self-hosted console around a clearer monitor, investigate, and resolve workflow.
- Added dashboard time ranges, KPI explanations, source health summaries, and an open-only priority queue.
- Added incident search and filters, an evidence drawer, notes, history, and true/false-positive resolution.
- Added source duplicate protection, enable/disable controls, safer key rotation, and one-click secret copying.
- Added readable Rule Engine documentation and clearer action success/error/loading feedback.
- Added API support for filtered incidents, incident detail/history/notes, source status changes, and 7-day snapshots.

## 0.1.0

- Public product website and authenticated self-hosted operations console
- PostgreSQL data model for users, sources, buckets, incidents, allowlist, alerts and audit log
- Per-source API keys and Zeek conn.log ingestion
- Near-real-time SSE dashboard updates
- Incident status workflow and role-based access
- SMTP alerts with retry worker
- Docker Compose, Caddy HTTPS and systemd Collector deployment
- Configurable retention with no Raw Log storage
