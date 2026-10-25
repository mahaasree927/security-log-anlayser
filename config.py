"""All detection thresholds live here so they are easy to tune."""
from dataclasses import dataclass


@dataclass
class Config:
    # Brute force: N failed logins, same IP + same username, inside the window
    bf_threshold: int = 8
    bf_window: int = 120              # seconds

    # Password spraying: one IP tries MANY usernames, only a FEW times each
    spray_min_users: int = 8
    spray_max_tries_per_user: int = 3
    spray_window: int = 600

    # Suspicious authentication
    success_after_failures: int = 5   # failures from same IP before a success
    success_lookback: int = 600
    off_hours_start: int = 0          # 00:00 ...
    off_hours_end: int = 5            # ... up to 04:59

    # Network scanning (firewall blocks)
    scan_min_ports: int = 15          # one IP hitting many ports  -> port scan
    scan_window: int = 60
    sweep_min_hosts: int = 10         # one IP hitting many hosts  -> host sweep
    sweep_window: int = 120
