import tempfile
import unittest
from datetime import datetime, timedelta

from sla import db, detectors, parser, sample_data
from sla.config import Config
from sla.parser import Event

YEAR = 2026
_counter = iter(range(1, 10**9))


def fails(ip, user, n, start=datetime(YEAR, 10, 1, 12, 0, 0), gap=2):
    return [Event(start + timedelta(seconds=i * gap), "auth", "h", "ssh_failed", user, ip,
                  raw="x", source_file="t", line_no=next(_counter))
            for i in range(n)]


def load(events):
    conn = db.connect(":memory:")
    db.insert_events(conn, events)
    return conn


class ParserTests(unittest.TestCase):
    def test_failed_password_invalid_user(self):
        e = parser.parse_line("Oct  4 10:15:32 h sshd[1]: Failed password for invalid user admin "
                              "from 203.0.113.5 port 5234 ssh2", YEAR)
        self.assertEqual((e.event_type, e.username, e.src_ip), ("ssh_failed", "admin", "203.0.113.5"))

    def test_accepted(self):
        e = parser.parse_line("Oct  4 10:15:32 h sshd[1]: Accepted publickey for bob from 10.0.0.2 "
                              "port 22 ssh2", YEAR)
        self.assertEqual(e.event_type, "ssh_success")

    def test_ufw_block(self):
        e = parser.parse_line("Oct  4 10:20:01 h kernel: [1.2] [UFW BLOCK] IN=eth0 SRC=1.2.3.4 "
                              "DST=10.0.0.5 PROTO=TCP SPT=1 DPT=445", YEAR)
        self.assertEqual((e.event_type, e.dst_port), ("fw_block", 445))

    def test_irrelevant_line_ignored(self):
        self.assertIsNone(parser.parse_line("Oct  4 10:20:01 h cron[1]: job done", YEAR))


class DetectorTests(unittest.TestCase):
    def test_brute_force_detected(self):
        a = detectors.detect_brute_force(load(fails("1.1.1.1", "root", 12)), Config())
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0].technique_id, "T1110.001")

    def test_below_threshold_is_quiet(self):
        self.assertEqual(detectors.detect_brute_force(load(fails("1.1.1.1", "root", 3)), Config()), [])

    def test_slow_attempts_not_flagged(self):
        conn = load(fails("1.1.1.1", "root", 12, gap=300))   # 1 try / 5 minutes
        self.assertEqual(detectors.detect_brute_force(conn, Config()), [])

    def test_spraying_not_brute_force(self):
        ev = []
        for i in range(12):
            ev += fails("2.2.2.2", f"user{i}", 1, datetime(YEAR, 10, 1, 12, 0, i * 5))
        conn = load(ev)
        self.assertEqual(detectors.detect_brute_force(conn, Config()), [])
        self.assertEqual(len(detectors.detect_password_spraying(conn, Config())), 1)

    def test_port_scan(self):
        ev = [Event(datetime(YEAR, 10, 1, 12, 0, i % 30), "firewall", "h", "fw_block", None,
                    "3.3.3.3", "10.0.0.5", 1000 + i, raw="x", source_file="t", line_no=i)
              for i in range(40)]
        a = detectors.detect_network_scans(load(ev), Config())
        self.assertEqual([x.rule for x in a], ["Port scan"])


class EndToEndTest(unittest.TestCase):
    def test_demo_logs_trigger_every_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(":memory:")
            for p in sample_data.generate(tmp, YEAR):
                events, _ = parser.parse_file(p, YEAR)
                db.insert_events(conn, events)
            rules = {a.rule for a in detectors.detect_all(conn)}
        for expected in ("SSH brute-force attack", "Password spraying",
                         "Successful login after repeated failures", "Root login from external IP",
                         "Login from new source IP", "Off-hours login", "Port scan", "Host sweep"):
            self.assertIn(expected, rules)


if __name__ == "__main__":
    unittest.main()
