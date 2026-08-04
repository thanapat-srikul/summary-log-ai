# Changelog

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
