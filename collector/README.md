# Summary Log AI Zeek Collector

The collector uses only Python's standard library. It supports Zeek `conn.log` in JSON or the default TSV format.

## Run manually

1. Copy `.env.example` values into your shell environment.
2. Ensure `ZEEK_CONN_LOG` points to an authorized Zeek `conn.log` file.
3. Run:

```bash
python3 zeek_collector.py
```

Use `--from-start` to read the current file from the beginning. By default, the collector starts at the end and only sends new events. `Ctrl+C` stops collection safely; unsent events remain in the spool file.

For Zeek JSON output, add this to `local.zeek` and restart Zeek:

```zeek
@load policy/tuning/json-logs.zeek
```

Keep both tokens private. The collector sends only normalized fields and never uploads the raw log file.
