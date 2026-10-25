"""Generate realistic fake logs containing every attack type (for demos and tests)."""
import os
import random
from datetime import datetime, timedelta

HOST = "webserver01"


def _line(dt, rest):
    return dt, f"{dt:%b} {dt.day:2d} {dt:%H:%M:%S} {HOST} {rest}"


def _ssh_fail(dt, user, ip, valid, rng):
    port = rng.randint(40000, 65000)
    inv = "" if valid else "invalid user "
    out = []
    if not valid:
        out.append(_line(dt, f"sshd[{rng.randint(1000, 9999)}]: Invalid user {user} from {ip} port {port}"))
    out.append(_line(dt, f"sshd[{rng.randint(1000, 9999)}]: Failed password for {inv}{user} from {ip} port {port} ssh2"))
    return out


def _ssh_ok(dt, user, ip, rng, method="password"):
    return [_line(dt, f"sshd[{rng.randint(1000, 9999)}]: Accepted {method} for {user} from {ip} "
                      f"port {rng.randint(40000, 65000)} ssh2")]


def _ufw(dt, src, dst, dport, rng):
    return _line(dt, f"kernel: [{rng.uniform(1e5, 9e5):.6f}] [UFW BLOCK] IN=eth0 OUT= "
                     f"MAC=00:16:3e:aa:bb:cc SRC={src} DST={dst} LEN=44 TOS=0x00 TTL=52 "
                     f"ID={rng.randint(1, 65000)} PROTO=TCP SPT={rng.randint(1024, 65000)} "
                     f"DPT={dport} WINDOW=1024 SYN URGP=0")


def generate(out_dir: str, year: int):
    rng = random.Random(42)
    d = lambda day, h, m, s=0: datetime(year, 10, day, h, m, s)
    auth, fw = [], []

    # --- normal behaviour (3 days) ---
    users = {"alice": "10.0.0.21", "bob": "10.0.0.22", "deploy": "10.0.0.12"}
    for day in (1, 2, 3):
        for user, ip in users.items():
            t = d(day, rng.randint(9, 11), rng.randint(0, 59))
            if rng.random() < 0.4:                       # occasional typo
                auth += _ssh_fail(t, user, ip, True, rng)
                t += timedelta(seconds=8)
            auth += _ssh_ok(t, user, ip, rng, rng.choice(["password", "publickey"]))

    # --- 1. brute force: 40 guesses at 'admin' ---
    t = d(2, 14, 5)
    for _ in range(40):
        auth += _ssh_fail(t, "admin", "203.0.113.50", False, rng)
        t += timedelta(seconds=rng.uniform(1, 3))

    # --- 2. password spraying: 25 usernames, 1 try each ---
    names = ["root", "ubuntu", "alice", "test", "oracle", "postgres", "git", "ftp", "guest", "user",
             "www-data", "jenkins", "ansible", "pi", "admin1", "support", "info", "backup", "mysql",
             "tomcat", "hadoop", "nagios", "vagrant", "dev", "student"]
    t = d(2, 16, 30)
    for n in names:
        auth += _ssh_fail(t, n, "198.51.100.23", n in ("root", "alice"), rng)
        t += timedelta(seconds=rng.uniform(5, 15))

    # --- 3. success after failures (account compromised) ---
    t = d(3, 9, 40)
    for _ in range(8):
        auth += _ssh_fail(t, "deploy", "192.0.2.77", True, rng)
        t += timedelta(seconds=rng.uniform(10, 25))
    auth += _ssh_ok(t, "deploy", "192.0.2.77", rng)

    # --- 4. root from internet, new IP for alice, off-hours login ---
    auth += _ssh_ok(d(3, 11, 15), "root", "203.0.113.99", rng, "publickey")
    auth += _ssh_ok(d(3, 20, 10), "alice", "198.51.100.200", rng)
    auth += _ssh_ok(d(3, 3, 12), "bob", "10.0.0.22", rng)

    # --- 5. port scan: 200 ports in ~30s ---
    t = d(2, 18, 0)
    for p in rng.sample(range(1, 1025), 200):
        fw.append(_ufw(t, "198.51.100.7", "10.0.0.5", p, rng))
        t += timedelta(seconds=rng.uniform(0.05, 0.25))

    # --- 6. host sweep on port 22 ---
    t = d(3, 2, 0)
    for h in range(1, 61):
        fw.append(_ufw(t, "203.0.113.8", f"10.0.0.{h}", 22, rng))
        t += timedelta(seconds=1)

    # --- background firewall noise ---
    for _ in range(60):
        t = d(rng.randint(1, 3), rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59))
        src = f"45.{rng.randint(1, 250)}.{rng.randint(1, 250)}.{rng.randint(1, 250)}"
        fw.append(_ufw(t, src, "10.0.0.5", rng.choice([22, 23, 80, 443, 3389]), rng))

    os.makedirs(out_dir, exist_ok=True)
    paths = []
    for name, lines in (("auth.log", auth), ("ufw.log", fw)):
        path = os.path.join(out_dir, name)
        with open(path, "w") as fh:
            fh.write("\n".join(line for _, line in sorted(lines, key=lambda x: x[0])) + "\n")
        paths.append(path)
    return paths
