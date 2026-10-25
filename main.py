#!/usr/bin/env python3
"""Security Log Analyzer & Threat Detection Platform - command line interface.

  python main.py demo                         # generate sample logs, analyse, print report
  python main.py ingest auth.log ufw.log      # load logs into SQLite
  python main.py detect                       # run detection rules
  python main.py report [--format json|csv]   # show results
  python main.py navigator -o layer.json      # export MITRE ATT&CK Navigator layer
"""
import argparse
import os
import sys
from datetime import datetime

from sla import db, detectors, parser, report, sample_data


def cmd_ingest(args):
    conn = db.connect(args.db)
    for path in args.files:
        events, ignored = parser.parse_file(path, args.year, args.type)
        added = db.insert_events(conn, events)
        print(f"{path}: {len(events)} security events parsed, {added} new, {ignored} lines ignored")


def cmd_detect(args):
    conn = db.connect(args.db)
    alerts = detectors.detect_all(conn)
    print(f"{len(alerts)} alert(s) raised. Run 'report' to view them.")


def cmd_report(args):
    conn = db.connect(args.db)
    fmt = {"text": report.text_report, "json": report.json_report, "csv": report.csv_report}[args.format]
    _emit(fmt(conn), args.output)


def cmd_navigator(args):
    _emit(report.navigator_layer(db.connect(args.db)), args.output)


def cmd_demo(args):
    if os.path.exists(args.db):
        os.remove(args.db)
    paths = sample_data.generate("sample_logs", args.year)
    print("Generated:", ", ".join(paths), "\n")
    conn = db.connect(args.db)
    for p in paths:
        events, ignored = parser.parse_file(p, args.year)
        db.insert_events(conn, events)
    detectors.detect_all(conn)
    print(report.text_report(conn))


def _emit(text, path):
    if path:
        with open(path, "w") as fh:
            fh.write(text)
        print(f"Wrote {path}")
    else:
        print(text)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="sla.db", help="SQLite database file (default: sla.db)")
    ap.add_argument("--year", type=int, default=datetime.now().year,
                    help="year of the logs (syslog lines have no year)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("ingest", help="parse log files into the database")
    p.add_argument("files", nargs="+")
    p.add_argument("--type", choices=["auto", "auth", "firewall"], default="auto")
    p.set_defaults(func=cmd_ingest)

    sub.add_parser("detect", help="run detection rules").set_defaults(func=cmd_detect)

    p = sub.add_parser("report", help="show alerts")
    p.add_argument("--format", choices=["text", "json", "csv"], default="text")
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("navigator", help="export MITRE ATT&CK Navigator layer")
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_navigator)

    sub.add_parser("demo", help="end-to-end demo with generated logs").set_defaults(func=cmd_demo)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
