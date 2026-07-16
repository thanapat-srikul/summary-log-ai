#!/usr/bin/env python3
"""Tail Zeek conn.log and send normalized events to Summary Log AI."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


MAX_SPOOL_BYTES = 50 * 1024 * 1024
EMPTY_VALUES = {"", "-", "(empty)"}


def _number(value: Any, default: float = 0) -> float:
    if value in EMPTY_VALUES or value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def normalize_event(row: dict[str, Any]) -> dict[str, Any] | None:
    try:
        uid = str(row.get("uid", "")).strip()
        orig_h = str(row.get("orig_h", row.get("id.orig_h", ""))).strip()
        resp_h = str(row.get("resp_h", row.get("id.resp_h", ""))).strip()
        proto = str(row.get("proto", "")).strip().lower()
        conn_state = str(row.get("conn_state", "")).strip()
        ts = _number(row.get("ts"), -1)
        orig_p = int(_number(row.get("orig_p", row.get("id.orig_p")), -1))
        resp_p = int(_number(row.get("resp_p", row.get("id.resp_p")), -1))
        if not uid or not orig_h or not resp_h or not proto or not conn_state or ts < 0:
            return None
        if not 0 <= orig_p <= 65535 or not 0 <= resp_p <= 65535:
            return None
        service = str(row.get("service", "")).strip()
        duration_raw = row.get("duration")
        return {
            "uid": uid[:128],
            "ts": ts,
            "orig_h": orig_h[:128],
            "orig_p": orig_p,
            "resp_h": resp_h[:128],
            "resp_p": resp_p,
            "proto": proto[:24],
            "service": None if service in EMPTY_VALUES else service[:64],
            "conn_state": conn_state[:24],
            "duration": None if duration_raw in EMPTY_VALUES or duration_raw is None else _number(duration_raw),
            "orig_bytes": max(0, int(_number(row.get("orig_bytes")))),
            "resp_bytes": max(0, int(_number(row.get("resp_bytes")))),
            "orig_pkts": max(0, int(_number(row.get("orig_pkts")))),
            "resp_pkts": max(0, int(_number(row.get("resp_pkts")))),
        }
    except (TypeError, ValueError):
        return None


class ZeekParser:
    def __init__(self) -> None:
        self.fields: list[str] = []
        self.separator = "\t"

    def parse_line(self, line: str) -> dict[str, Any] | None:
        line = line.rstrip("\r\n")
        if not line:
            return None
        if line.startswith("#separator "):
            encoded = line.split(" ", 1)[1]
            try:
                self.separator = bytes(encoded, "utf-8").decode("unicode_escape")
            except UnicodeDecodeError:
                self.separator = "\t"
            return None
        if line.startswith("#fields"):
            parts = line.split(self.separator)
            self.fields = parts[1:] if parts and parts[0] == "#fields" else []
            return None
        if line.startswith("#"):
            return None
        if line.lstrip().startswith("{"):
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                return None
            return normalize_event(value) if isinstance(value, dict) else None
        if not self.fields:
            return None
        values = line.split(self.separator)
        if len(values) != len(self.fields):
            return None
        return normalize_event(dict(zip(self.fields, values)))


class ZeekTailer:
    def __init__(self, path: Path, from_start: bool = False) -> None:
        self.path = path
        self.from_start = from_start
        self.parser = ZeekParser()
        self.inode: int | None = None
        self.offset = 0
        self.first_open = True

    def _identity(self, stat: os.stat_result) -> int:
        return hash((stat.st_dev, stat.st_ino, stat.st_ctime_ns))

    def _prepare(self) -> os.stat_result | None:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return None
        identity = self._identity(stat)
        rotated = self.inode is not None and identity != self.inode
        truncated = stat.st_size < self.offset
        if rotated or truncated:
            self.offset = 0
            self.parser = ZeekParser()
        self.inode = identity
        if self.first_open and not self.from_start:
            self.offset = stat.st_size
        self.first_open = False
        return stat

    def poll(self, limit: int = 1000) -> list[dict[str, Any]]:
        if self._prepare() is None:
            return []
        events: list[dict[str, Any]] = []
        try:
            with self.path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(self.offset)
                for _ in range(limit):
                    line = handle.readline()
                    if not line:
                        break
                    event = self.parser.parse_line(line)
                    if event:
                        events.append(event)
                self.offset = handle.tell()
        except FileNotFoundError:
            return events
        return events

    def close(self) -> None:
        return None


class Spool:
    def __init__(self, path: Path, max_bytes: int = MAX_SPOOL_BYTES) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        events: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                events.append(value)
        return events

    def append(self, event: dict[str, Any]) -> None:
        encoded = (json.dumps(event, separators=(",", ":")) + "\n").encode("utf-8")
        if self.path.exists() and self.path.stat().st_size + len(encoded) > self.max_bytes:
            current = self.path.read_bytes()
            keep = current[-max(0, self.max_bytes // 2):]
            newline = keep.find(b"\n")
            keep = keep[newline + 1:] if newline >= 0 else b""
            self.path.write_bytes(keep)
        with self.path.open("ab") as handle:
            handle.write(encoded)

    def replace(self, events: list[dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix="collector-spool-", suffix=".ndjson", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                for event in events:
                    handle.write(json.dumps(event, separators=(",", ":")) + "\n")
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


class HttpSender:
    def __init__(self, base_url: str, ingest_key: str, bypass_token: str, source_id: str) -> None:
        self.url = base_url.rstrip("/") + "/api/ingest/zeek"
        self.ingest_key = ingest_key
        self.bypass_token = bypass_token
        self.source_id = source_id

    def send(self, events: list[dict[str, Any]], spool_backlog: int = 0, timeout: float = 10) -> dict[str, Any]:
        body = json.dumps({
            "sourceId": self.source_id,
            "sentAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "spoolBacklog": max(0, spool_backlog),
            "events": events,
        }, separators=(",", ":")).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.ingest_key}",
            "Content-Type": "application/json",
            "User-Agent": "summary-log-zeek-collector/1.0",
        }
        if self.bypass_token:
            headers["OAI-Sites-Authorization"] = f"Bearer {self.bypass_token}"
        request = Request(self.url, data=body, headers=headers, method="POST")
        try:
            with urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
                if response.status not in (200, 202):
                    raise RuntimeError(f"ingest returned HTTP {response.status}")
                return payload
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[:300]
            raise RuntimeError(f"ingest returned HTTP {error.code}: {detail}") from error
        except URLError as error:
            raise RuntimeError(f"ingest connection failed: {error.reason}") from error


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send Zeek conn.log events to Summary Log AI")
    parser.add_argument("--from-start", action="store_true", help="Read the current log from the beginning")
    parser.add_argument("--once", action="store_true", help="Read available data, flush once, and exit")
    return parser.parse_args()


def run() -> int:
    args = parse_args()
    log_path = Path(required_env("ZEEK_CONN_LOG"))
    source_id = required_env("SOURCE_ID")
    base_url = required_env("SUMMARY_LOG_URL")
    ingest_key = required_env("SUMMARY_LOG_INGEST_KEY")
    bypass_token = os.environ.get("OAI_SITES_BYPASS_TOKEN", "").strip()
    if not bypass_token and not base_url.startswith(("http://localhost", "http://127.0.0.1")):
        raise SystemExit("Missing required environment variable: OAI_SITES_BYPASS_TOKEN")
    interval = max(100, int(os.environ.get("FLUSH_INTERVAL_MS", "1000"))) / 1000
    max_batch = min(100, max(1, int(os.environ.get("MAX_BATCH_SIZE", "100"))))
    spool_path = Path(os.environ.get("COLLECTOR_SPOOL", str(Path(__file__).with_name("collector-spool.ndjson"))))

    spool = Spool(spool_path)
    queue = spool.load()
    tailer = ZeekTailer(log_path, from_start=args.from_start)
    sender = HttpSender(base_url, ingest_key, bypass_token, source_id)
    next_flush = time.monotonic() + interval
    next_retry = 0.0
    backoff = 1
    print(f"Summary Log collector watching {log_path} as {source_id}", flush=True)
    try:
        while True:
            for event in tailer.poll():
                queue.append(event)
                spool.append(event)
            now = time.monotonic()
            should_flush = queue and (len(queue) >= max_batch or now >= next_flush)
            if should_flush and now >= next_retry:
                batch = queue[:max_batch]
                try:
                    result = sender.send(batch, max(0, len(queue) - len(batch)))
                    queue = queue[len(batch):]
                    spool.replace(queue)
                    backoff = 1
                    next_retry = 0
                    next_flush = now + interval
                    print(f"sent={result.get('accepted', 0)} rejected={result.get('rejected', 0)} queued={len(queue)}", flush=True)
                except RuntimeError as error:
                    print(f"send failed; retrying in {backoff}s: {error}", file=sys.stderr, flush=True)
                    next_retry = now + backoff
                    backoff = min(30, backoff * 2)
            if args.once:
                if not queue or next_retry > now:
                    return 0 if not queue else 1
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("collector stopped", flush=True)
        return 0
    finally:
        tailer.close()


if __name__ == "__main__":
    raise SystemExit(run())
