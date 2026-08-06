# Summary Log AI

Self-hosted Zeek `conn.log` monitoring สำหรับเปลี่ยน Network Flow เป็น Dashboard, Incident workflow และ Email Alert โดยไม่จัดเก็บ Raw Log

## Architecture

```text
Zeek conn.log
  └─ Python Collector (JSON/TSV, rotation, retry, spool)
       └─ HTTPS POST /api/v1/ingest/zeek
            └─ API + Rule Engine
                 ├─ PostgreSQL summaries/incidents
                 ├─ SSE dashboard updates
                 └─ Background Worker → SMTP
```

หนึ่งการติดตั้งแทนหนึ่งองค์กร และรองรับ Zeek Source หลายเครื่อง

## Requirements

- Linux server: 4 vCPU, 8 GB RAM และพื้นที่ว่างอย่างน้อย 50 GB สำหรับการติดตั้งทั่วไป
- Docker Engine 27+ และ Docker Compose v2
- Domain ที่ชี้มายัง server และเปิด TCP 80/443 สำหรับ HTTPS
- Zeek ที่สร้าง `conn.log` แบบ JSON หรือ TSV

## Install

```bash
cp .env.selfhost.example .env
```

แก้ `.env` และกำหนด `POSTGRES_PASSWORD`, `APP_SECRET` อย่างน้อย 32 ตัวอักษร และ `SUMMARY_LOG_DOMAIN` จากนั้น:

```bash
docker compose up -d --build
```

เปิด `https://<SUMMARY_LOG_DOMAIN>/app` และทำ Setup Wizard เพื่อสร้าง Admin คนแรก

## Connect a Zeek source

1. เข้าหน้า **Sources** และสร้าง Source
2. คัดลอก `SOURCE_ID` และ API key ที่แสดงเพียงครั้งเดียว
3. ติดตั้ง Collector บนเครื่องที่อ่าน `conn.log` ได้
4. สร้าง `/etc/summary-log-ai/collector.env`:

```dotenv
ZEEK_CONN_LOG=/opt/zeek/logs/current/conn.log
SUMMARY_LOG_URL=https://monitor.example.com
SUMMARY_LOG_INGEST_KEY=sla_replace_me
SOURCE_ID=00000000-0000-0000-0000-000000000000
COLLECTOR_SPOOL=/var/lib/summary-log-ai/collector-spool.ndjson
FLUSH_INTERVAL_MS=1000
MAX_BATCH_SIZE=100
```

คัดลอก `collector/zeek_collector.py` ไป `/opt/summary-log-ai/collector/` และใช้ `collector/summary-log-collector.service` เป็น systemd unit

## Operations

- Health: `GET /api/v1/health`
- Logs: `docker compose logs -f api worker`
- Stop collector: `systemctl stop summary-log-collector`
- Stop stack: `docker compose down` (ข้อมูลใน volume ยังอยู่)
- Rotate API key ในหน้า Sources หาก key รั่ว
- ตั้ง SMTP และผู้รับในหน้า Settings แล้วใช้ Test Email
- ตั้ง `SUMMARY_LOG_PUBLIC_URL` ให้ตรง URL ที่ผู้ดูแลใช้เปิด Dashboard เพื่อให้ลิงก์ในอีเมลถูกต้อง
- Alert ระดับ High/Critical จะถูกรวมทุก 5 นาที ดูผลการส่งและ Retry ได้ที่ `/app/alerts`

### Backup

```bash
docker compose exec -T postgres pg_dump -U summary_log -d summary_log -Fc > summary-log.backup
```

### Restore

หยุด API และ Worker ก่อน restore:

```bash
docker compose stop api worker
docker compose exec -T postgres pg_restore -U summary_log -d summary_log --clean --if-exists < summary-log.backup
docker compose start api worker
```

### Upgrade and rollback

1. Backup ฐานข้อมูล
2. อ่าน `CHANGELOG.md`
3. ดึง release tag ที่ต้องการและรัน `docker compose up -d --build`
4. หากต้อง rollback ให้กลับไป release tag เดิมและ restore backup เมื่อ migration ไม่ backward-compatible

## Security defaults

- Admin เป็นผู้สร้างผู้ใช้; ไม่มี public registration
- Roles: Admin, Analyst, Viewer
- Password ใช้ Argon2id
- Session cookie เป็น HttpOnly, Secure, SameSite=Strict
- Source API key เก็บเฉพาะ SHA-256 hash และแสดงครั้งเดียว
- SMTP password เข้ารหัส AES-256-GCM ด้วย `APP_SECRET`
- เก็บ summary และ Incident 30 วันโดยค่าเริ่มต้น; ไม่เก็บ Raw Log

## Development

Web:

```bash
npm install
npm run dev
```

API:

```bash
cd services/api
npm install
npm run dev
```

Tests:

```bash
npm test
cd services/api && npm test
python -m unittest collector/test_zeek_collector.py
```

## License

Apache-2.0 — see `LICENSE`.
