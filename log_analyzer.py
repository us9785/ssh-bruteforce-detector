"""Finds brute-force login attacks in an SSH auth log.

Usage: python log_analyzer.py sample_auth.log [--threshold 10] [--window 5]
An IP is flagged if it fails `threshold` logins within `window` minutes.
"""
import argparse
import re
from collections import defaultdict
from datetime import datetime, timedelta

# Matches lines like: "Nov  2 03:00:09 server sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 5 ssh2"
LINE = re.compile(
    r"^(?P<time>\w{3}\s+\d+ \d\d:\d\d:\d\d) \S+ sshd\[\d+\]: "
    r"(?P<result>Failed|Accepted) password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)


def parse(path, year=None):
    """Yield (time, result, user, ip) for every login line we understand."""
    year = year or datetime.now().year  # syslog lines have no year
    with open(path) as f:
        for line in f:
            m = LINE.match(line)
            if m:
                t = datetime.strptime(f"{year} {m['time']}", "%Y %b %d %H:%M:%S")
                yield t, m["result"], m["user"], m["ip"]


def analyze(events, threshold=10, window_min=5):
    """Return one dict per flagged IP, worst first."""
    fails = defaultdict(list)       # ip -> failure times
    users = defaultdict(set)        # ip -> usernames tried
    successes = defaultdict(list)   # ip -> success times
    for t, result, user, ip in sorted(events):
        if result == "Failed":
            fails[ip].append(t)
            users[ip].add(user)
        else:
            successes[ip].append(t)

    window, flagged = timedelta(minutes=window_min), []
    for ip, times in fails.items():
        # slide through the failures: is there a burst of `threshold` inside the window?
        burst = any(times[i + threshold - 1] - times[i] <= window for i in range(len(times) - threshold + 1))
        if burst:
            flagged.append({
                "ip": ip,
                "failures": len(times),
                "users": sorted(users[ip]),
                "first": times[0],
                "last": times[-1],
                "got_in": any(s > times[0] for s in successes[ip]),  # success after failing = possible breach
            })
    return sorted(flagged, key=lambda r: r["failures"], reverse=True)


def report(flagged):
    if not flagged:
        print("No brute-force activity found.")
        return
    print(f"{len(flagged)} suspicious IP(s) found\n")
    for r in flagged:
        print(f"IP: {r['ip']}")
        print(f"  Failed logins : {r['failures']} ({r['first']:%H:%M:%S} to {r['last']:%H:%M:%S})")
        print(f"  Usernames     : {', '.join(r['users'])}")
        if r["got_in"]:
            print("  !! A login SUCCEEDED from this IP after the failures. Treat as compromised.")
        print()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("logfile")
    p.add_argument("--threshold", type=int, default=10, help="failed logins that count as an attack")
    p.add_argument("--window", type=int, default=5, help="minutes the failures must fall within")
    a = p.parse_args()
    report(analyze(parse(a.logfile), a.threshold, a.window))
