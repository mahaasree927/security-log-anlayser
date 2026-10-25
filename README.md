# Security Log Analyzer & Threat Detection Platform

Python | Linux | SQLite | MITRE ATT&CK  -  no third-party dependencies (Python 3.8+).

Parses Linux SSH auth logs and UFW/iptables firewall logs, stores them in SQLite,
runs detection rules, and maps every alert to a MITRE ATT&CK technique.

## How it works

    logs --> parser.py --> SQLite (events) --> detectors.py --> SQLite (alerts) --> report.py
                                                     |
                                                 mitre.py (technique + tactic)

| File | Job |
|------|-----|
| `sla/parser.py`     | Regex parsing of raw lines into `Event` objects |
| `sla/db.py`         | SQLite schema, indexes, idempotent inserts |
| `sla/detectors.py`  | The detection rules (sliding-window logic) |
| `sla/mitre.py`      | ATT&CK technique / tactic lookup |
| `sla/report.py`     | Text, JSON, CSV reports + ATT&CK Navigator layer |
| `sla/config.py`     | All thresholds in one place |
| `sla/sample_data.py`| Fake logs containing every attack (for demo/tests) |

## Detections

| Rule | Logic | Severity | MITRE |
|------|-------|----------|-------|
| SSH brute-force | >= 8 failures, same IP + same user, within 120 s | medium / high | T1110.001 |
| Password spraying | one IP, >= 8 different users, <= 3 tries each, within 10 min | high | T1110.003 |
| Success after failures | login success after >= 5 failures from same IP in 10 min | critical | T1078 |
| Root login from internet | `root` accepted from a non-internal IP | high | T1078.003 |
| Login from new IP | user seen from an IP not in their login history | medium | T1078 |
| Off-hours login | successful login 00:00-04:59 | low | T1078 |
| Port scan | one IP blocked on >= 15 distinct ports within 60 s | medium / high | T1046 |
| Host sweep | one IP blocked on >= 10 distinct hosts within 120 s | medium | T1046 |

Brute force vs spraying: brute force = many tries on ONE account; spraying = a few tries on MANY accounts
(used to dodge account lockouts). The spraying rule caps tries per account to tell them apart.

## Quick start

    python3 main.py demo                         # generate sample logs, analyse, print report
    python3 -m unittest discover -v              # run the tests

On real logs:

    python3 main.py --year 2026 ingest /var/log/auth.log /var/log/ufw.log   # may need sudo to read
    python3 main.py detect
    python3 main.py report
    python3 main.py report --format json -o alerts.json
    python3 main.py navigator -o layer.json      # open at mitre-attack.github.io/attack-navigator

Query the database directly:

    sqlite3 sla.db "SELECT src_ip, COUNT(*) FROM events WHERE event_type='ssh_failed' GROUP BY 1 ORDER BY 2 DESC LIMIT 5;"

## Limitations (be upfront about these in interviews)

* Syslog has no year, so you pass `--year`. Logs spanning New Year need splitting.
* Rules are threshold-based; thresholds need tuning per environment (`sla/config.py`).
* "New IP" baseline is built only from logs already ingested.
* Batch analysis, not real-time streaming.

## Ideas to extend

* Add a `tail -f` follow mode for live detection
* GeoIP / AbuseIPDB enrichment of attacker IPs
* Web server logs (Apache/Nginx): SQL injection and directory-scan rules
* Auto-block via `ufw deny from <ip>` or fail2ban export
* HTML dashboard
