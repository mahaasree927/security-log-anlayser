"""Reports: terminal text, JSON, CSV and an ATT&CK Navigator layer."""
import csv
import io
import json
from collections import Counter

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def fetch_alerts(conn):
    rows = [dict(r) for r in conn.execute("SELECT * FROM alerts")]
    rows.sort(key=lambda r: (SEV_ORDER[r["severity"]], r["first_seen"]))
    return rows


def text_report(conn) -> str:
    alerts = fetch_alerts(conn)
    out = ["=" * 72, " SECURITY LOG ANALYZER - THREAT REPORT", "=" * 72]

    ev = conn.execute("SELECT event_type, COUNT(*) c FROM events GROUP BY event_type ORDER BY c DESC")
    out.append("\nEvents analysed")
    for r in ev:
        out.append(f"  {r['event_type']:<18}{r['c']:>7}")

    sev = Counter(a["severity"] for a in alerts)
    out.append(f"\nAlerts: {len(alerts)}   " + "  ".join(
        f"{s}={sev[s]}" for s in ("critical", "high", "medium", "low")))

    out.append("\nMITRE ATT&CK coverage")
    by_tech = Counter((a["technique_id"], a["technique_name"], a["tactic"]) for a in alerts)
    for (tid, name, tactic), c in sorted(by_tech.items()):
        out.append(f"  {tid:<10} {name:<36} {tactic:<18} x{c}")

    out.append("\nTop offending IPs")
    for ip, c in Counter(a["src_ip"] for a in alerts).most_common(5):
        out.append(f"  {ip:<18}{c} alert(s)")

    out.append("\n" + "-" * 72 + "\nALERTS (most severe first)\n" + "-" * 72)
    for a in alerts:
        out.append(f"\n[{a['severity'].upper()}] #{a['id']}  {a['rule']}")
        out.append(f"  Source IP : {a['src_ip']}   User: {a['username'] or '-'}   Events: {a['event_count']}")
        out.append(f"  Window    : {a['first_seen'].replace('T', ' ')}  ->  {a['last_seen'].replace('T', ' ')}")
        out.append(f"  MITRE     : {a['technique_id']} {a['technique_name']} ({a['tactic']})")
        out.append(f"  Detail    : {a['description']}")
    return "\n".join(out)


def json_report(conn) -> str:
    return json.dumps(fetch_alerts(conn), indent=2)


def csv_report(conn) -> str:
    alerts = fetch_alerts(conn)
    buf = io.StringIO()
    if alerts:
        w = csv.DictWriter(buf, fieldnames=alerts[0].keys())
        w.writeheader()
        w.writerows(alerts)
    return buf.getvalue()


def navigator_layer(conn) -> str:
    """Layer file you can load at https://mitre-attack.github.io/attack-navigator/"""
    counts = Counter(r["technique_id"] for r in conn.execute("SELECT technique_id FROM alerts"))
    layer = {
        "name": "Security Log Analyzer detections",
        "versions": {"attack": "15", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques detected in analysed logs (score = number of alerts)",
        "gradient": {"colors": ["#ffe766", "#ff6666"], "minValue": 0,
                     "maxValue": max(counts.values(), default=1)},
        "techniques": [{"techniqueID": t, "score": c, "comment": f"{c} alert(s)"}
                       for t, c in counts.items()],
    }
    return json.dumps(layer, indent=2)
