"""Turn raw log lines into structured Event objects.

Supported formats
  * Linux SSH auth log  (/var/log/auth.log or /var/log/secure)
  * UFW / iptables firewall log (/var/log/ufw.log or kern.log)
"""
import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

# "Oct  4 10:15:32 host proc[123]: message"
SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
IP = r"[0-9A-Fa-f:.]+"
FAILED_RE = re.compile(
    rf"Failed (?P<method>[\w-]+) for (?P<invalid>invalid user )?(?P<user>\S+) "
    rf"from (?P<ip>{IP}) port (?P<port>\d+)")
ACCEPTED_RE = re.compile(
    rf"Accepted (?P<method>[\w-]+) for (?P<user>\S+) from (?P<ip>{IP}) port (?P<port>\d+)")
INVALID_RE = re.compile(rf"Invalid user (?P<user>\S*) from (?P<ip>{IP})")
KV_RE = re.compile(r"(\w+)=(\S*)")   # SRC=1.2.3.4 DPT=22 ...


@dataclass
class Event:
    ts: datetime
    source: str                  # "auth" or "firewall"
    host: str
    event_type: str              # ssh_failed | ssh_success | ssh_invalid_user | fw_block
    username: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    raw: str = ""
    source_file: str = ""
    line_no: int = 0

    def as_row(self):
        return (self.ts.isoformat(), self.source, self.source_file, self.line_no,
                self.host, self.event_type, self.username, self.src_ip,
                self.dst_ip, self.dst_port, self.raw)


def parse_line(line: str, year: int, source: str = "auto") -> Optional[Event]:
    """Parse one log line. Returns None for lines we don't care about."""
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    try:
        # syslog timestamps have no year, so the caller supplies it
        ts = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    host, proc, msg = m["host"], m["proc"], m["msg"]

    if source in ("auto", "auth") and proc.startswith("sshd"):
        if (a := ACCEPTED_RE.search(msg)):
            return Event(ts, "auth", host, "ssh_success", a["user"], a["ip"], raw=line)
        if (f := FAILED_RE.search(msg)):
            return Event(ts, "auth", host, "ssh_failed", f["user"], f["ip"], raw=line)
        if (i := INVALID_RE.search(msg)):
            return Event(ts, "auth", host, "ssh_invalid_user", i["user"], i["ip"], raw=line)
        return None

    if source in ("auto", "firewall") and "SRC=" in msg and ("BLOCK" in msg or "DROP" in msg):
        kv = dict(KV_RE.findall(msg))
        dpt = kv.get("DPT")
        return Event(ts, "firewall", host, "fw_block", None, kv.get("SRC"), kv.get("DST"),
                     int(dpt) if dpt and dpt.isdigit() else None, raw=line)
    return None


def parse_file(path: str, year: int, source: str = "auto"):
    """Parse a whole file. Returns (events, ignored_line_count)."""
    events, ignored = [], 0
    name = os.path.basename(path)
    with open(path, errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            ev = parse_line(line, year, source)
            if ev:
                ev.source_file, ev.line_no = name, n
                events.append(ev)
            else:
                ignored += 1
    return events, ignored
