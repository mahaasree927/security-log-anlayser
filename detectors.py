"""Detection rules. Each rule reads events from SQLite and returns Alert objects."""
import ipaddress
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from . import db
from .config import Config


@dataclass
class Alert:
    rule: str
    severity: str                 # low | medium | high | critical
    src_ip: Optional[str]
    username: Optional[str]
    first_seen: datetime
    last_seen: datetime
    event_count: int
    technique_id: str             # MITRE ATT&CK ID
    description: str


# ---------------------------------------------------------------- helpers
def _rows(conn, sql):
    return conn.execute(sql).fetchall()


def _t(s: str) -> datetime:
    return datetime.fromisoformat(s)


def _secs(a: datetime, b: datetime) -> float:
    return (b - a).total_seconds()


def _bursts(times, threshold, window):
    """Find bursts of >= `threshold` events within `window` seconds.

    `times` must be sorted. A burst keeps growing while consecutive events are
    no more than `window` seconds apart, so one attack = one alert (no flooding).
    Returns a list of (start, end, count).
    """
    found, i, n = [], 0, len(times)
    while i < n:
        if i + threshold - 1 < n and _secs(times[i], times[i + threshold - 1]) <= window:
            end = i + threshold - 1
            while end + 1 < n and _secs(times[end], times[end + 1]) <= window:
                end += 1
            found.append((times[i], times[end], end - i + 1))
            i = end + 1
        else:
            i += 1
    return found


def _distinct_windows(events, min_distinct, window, max_per_key=None):
    """events = sorted [(time, key)]. Find windows holding >= min_distinct different keys.

    If max_per_key is set, no single key may appear more than that many times
    (this is what separates password SPRAYING from plain brute force).
    Returns a list of (start, end, distinct_keys, total_events).
    """
    found, i, n = [], 0, len(events)
    while i < n:
        counts, j = Counter(), i
        while j < n and _secs(events[i][0], events[j][0]) <= window:
            counts[events[j][1]] += 1
            j += 1
        ok = len(counts) >= min_distinct and (max_per_key is None or max(counts.values()) <= max_per_key)
        if ok:
            found.append((events[i][0], events[j - 1][0], len(counts), j - i))
            i = j                  # skip past this attack
        else:
            i += 1
    return found


# Internal = RFC1918 + loopback + link-local (+ IPv6 equivalents). We list them explicitly
# because Python's is_private also treats documentation ranges (192.0.2.0/24 etc.) as private.
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10")]


def _is_external(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(addr in net for net in INTERNAL_NETS if net.version == addr.version)


# ------------------------------------------------------------------ rules
def detect_brute_force(conn, cfg: Config):
    """Many failed logins for ONE account from ONE IP.  MITRE T1110.001"""
    groups = defaultdict(list)
    for r in _rows(conn, "SELECT ts, src_ip, username FROM events "
                         "WHERE event_type='ssh_failed' ORDER BY ts"):
        groups[(r["src_ip"], r["username"])].append(_t(r["ts"]))

    alerts = []
    for (ip, user), times in groups.items():
        for start, end, n in _bursts(times, cfg.bf_threshold, cfg.bf_window):
            sev = "high" if n >= cfg.bf_threshold * 5 else "medium"
            alerts.append(Alert(
                "SSH brute-force attack", sev, ip, user, start, end, n, "T1110.001",
                f"{n} failed logins for '{user}' from {ip} "
                f"in {int(_secs(start, end))}s (threshold {cfg.bf_threshold}/{cfg.bf_window}s)."))
    return alerts


def detect_password_spraying(conn, cfg: Config):
    """One IP, many usernames, few tries each.  MITRE T1110.003"""
    groups = defaultdict(list)
    for r in _rows(conn, "SELECT ts, src_ip, username FROM events "
                         "WHERE event_type='ssh_failed' ORDER BY ts"):
        groups[r["src_ip"]].append((_t(r["ts"]), r["username"]))

    alerts = []
    for ip, events in groups.items():
        for start, end, users, total in _distinct_windows(
                events, cfg.spray_min_users, cfg.spray_window, cfg.spray_max_tries_per_user):
            alerts.append(Alert(
                "Password spraying", "high", ip, None, start, end, total, "T1110.003",
                f"{ip} tried {users} different accounts ({total} attempts, max "
                f"{cfg.spray_max_tries_per_user} per account) in {int(_secs(start, end))}s."))
    return alerts


def detect_suspicious_auth(conn, cfg: Config):
    """Successful logins that look wrong.  MITRE T1078 / T1078.003"""
    failed = defaultdict(list)           # ip -> sorted failure times
    for r in _rows(conn, "SELECT ts, src_ip FROM events WHERE event_type='ssh_failed' ORDER BY ts"):
        failed[r["src_ip"]].append(_t(r["ts"]))

    alerts, known_ips = [], defaultdict(set)
    for r in _rows(conn, "SELECT ts, src_ip, username FROM events "
                         "WHERE event_type='ssh_success' ORDER BY ts"):
        t, ip, user = _t(r["ts"]), r["src_ip"], r["username"]
        flagged = False

        # 1) success right after a pile of failures -> account probably guessed
        times = failed.get(ip, [])
        lo = bisect_left(times, t - timedelta(seconds=cfg.success_lookback))
        n_fail = bisect_right(times, t) - lo
        if n_fail >= cfg.success_after_failures:
            flagged = True
            alerts.append(Alert(
                "Successful login after repeated failures", "critical", ip, user, t, t, n_fail + 1,
                "T1078", f"'{user}' logged in from {ip} after {n_fail} failed attempts in "
                         f"{cfg.success_lookback // 60} min - possible compromised account."))

        # 2) direct root login from the internet
        if user == "root" and _is_external(ip):
            alerts.append(Alert(
                "Root login from external IP", "high", ip, user, t, t, 1, "T1078.003",
                f"root logged in over SSH from public address {ip}."))

        # 3) account seen from a brand-new IP (baseline = earlier logins in the DB)
        if not flagged and user in known_ips and ip not in known_ips[user]:
            alerts.append(Alert(
                "Login from new source IP", "medium", ip, user, t, t, 1, "T1078",
                f"'{user}' logged in from {ip}, never seen before for this account."))
        known_ips[user].add(ip)

        # 4) login at unusual hours
        if cfg.off_hours_start <= t.hour < cfg.off_hours_end:
            alerts.append(Alert(
                "Off-hours login", "low", ip, user, t, t, 1, "T1078",
                f"'{user}' logged in at {t:%H:%M}, outside normal working hours."))
    return alerts


def detect_network_scans(conn, cfg: Config):
    """Port scans and host sweeps from firewall blocks.  MITRE T1046"""
    ports, hosts = defaultdict(list), defaultdict(list)
    for r in _rows(conn, "SELECT ts, src_ip, dst_ip, dst_port FROM events "
                         "WHERE event_type='fw_block' ORDER BY ts"):
        t = _t(r["ts"])
        if r["dst_port"] is not None:
            ports[r["src_ip"]].append((t, r["dst_port"]))
        if r["dst_ip"]:
            hosts[r["src_ip"]].append((t, r["dst_ip"]))

    alerts = []
    for ip, ev in ports.items():
        for start, end, n_ports, total in _distinct_windows(ev, cfg.scan_min_ports, cfg.scan_window):
            alerts.append(Alert(
                "Port scan", "high" if n_ports >= 100 else "medium", ip, None, start, end, total,
                "T1046", f"{ip} was blocked on {n_ports} distinct ports in {int(_secs(start, end))}s."))
    for ip, ev in hosts.items():
        for start, end, n_hosts, total in _distinct_windows(ev, cfg.sweep_min_hosts, cfg.sweep_window):
            alerts.append(Alert(
                "Host sweep", "medium", ip, None, start, end, total, "T1046",
                f"{ip} probed {n_hosts} different hosts in {int(_secs(start, end))}s."))
    return alerts


def detect_all(conn, cfg: Config = None):
    """Run every rule, store results in the alerts table, return them."""
    cfg = cfg or Config()
    alerts = []
    for rule in (detect_brute_force, detect_password_spraying,
                 detect_suspicious_auth, detect_network_scans):
        alerts.extend(rule(conn, cfg))
    alerts.sort(key=lambda a: a.first_seen)
    db.clear_alerts(conn)          # alerts are rebuilt from events on every run
    db.insert_alerts(conn, alerts)
    return alerts
