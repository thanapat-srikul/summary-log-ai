import json
from pathlib import Path
import tempfile
import unittest

from zeek_collector import Spool, ZeekParser, ZeekTailer


class ZeekParserTests(unittest.TestCase):
    def test_parses_json_with_dotted_fields(self):
        parser = ZeekParser()
        event = parser.parse_line(json.dumps({
            "ts": 1784160000.1, "uid": "C123", "id.orig_h": "192.168.1.2", "id.orig_p": 51515,
            "id.resp_h": "10.0.0.8", "id.resp_p": 443, "proto": "tcp", "service": "ssl",
            "duration": 1.2, "orig_bytes": 100, "resp_bytes": 200, "conn_state": "SF",
            "orig_pkts": 2, "resp_pkts": 3,
        }))
        self.assertEqual(event["uid"], "C123")
        self.assertEqual(event["resp_p"], 443)
        self.assertEqual(event["resp_bytes"], 200)

    def test_parses_tsv_and_empty_values(self):
        parser = ZeekParser()
        parser.parse_line("#separator \\x09")
        parser.parse_line("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts")
        event = parser.parse_line("1784160000.1\tC456\t192.168.1.4\t51000\t10.0.0.9\t53\tudp\tdns\t-\t20\t40\tSF\t1\t1")
        self.assertEqual(event["service"], "dns")
        self.assertIsNone(event["duration"])
        self.assertEqual(event["orig_pkts"], 1)

    def test_rejects_incomplete_rows(self):
        self.assertIsNone(ZeekParser().parse_line("not-a-zeek-row"))


class SpoolTests(unittest.TestCase):
    def test_round_trip_and_replace(self):
        with tempfile.TemporaryDirectory() as directory:
            spool = Spool(Path(directory) / "spool.ndjson")
            spool.append({"uid": "one"})
            spool.append({"uid": "two"})
            self.assertEqual([row["uid"] for row in spool.load()], ["one", "two"])
            spool.replace([{"uid": "two"}])
            self.assertEqual(spool.load(), [{"uid": "two"}])


class TailerTests(unittest.TestCase):
    def test_detects_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "conn.log"
            first = json.dumps({"ts": 1784160000, "uid": "A", "id.orig_h": "1.1.1.1", "id.orig_p": 1, "id.resp_h": "2.2.2.2", "id.resp_p": 80, "proto": "tcp", "conn_state": "SF"})
            second = json.dumps({"ts": 1784160001, "uid": "B", "id.orig_h": "1.1.1.1", "id.orig_p": 2, "id.resp_h": "3.3.3.3", "id.resp_p": 443, "proto": "tcp", "conn_state": "SF"})
            path.write_text(first + "\n", encoding="utf-8")
            tailer = ZeekTailer(path, from_start=True)
            self.assertEqual(tailer.poll()[0]["uid"], "A")
            path.rename(Path(directory) / "conn.log.1")
            path.write_text(second + "\n", encoding="utf-8")
            self.assertEqual(tailer.poll()[0]["uid"], "B")
            tailer.close()


if __name__ == "__main__":
    unittest.main()
