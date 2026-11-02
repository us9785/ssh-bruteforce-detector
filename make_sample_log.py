"""Creates sample_auth.log: fake SSH login attempts (safe, no real data)."""
import random
from datetime import datetime, timedelta

random.seed(7)  # same output every run
start = datetime(2026, 11, 2, 0, 0, 0)
lines = []  # (time, text)

def add(t, text):
    lines.append((t, f"{t.strftime('%b %e %H:%M:%S')} server sshd[{random.randint(1000, 9999)}]: {text}"))

# Normal users: logins, plus the odd typo
for _ in range(25):
    t = start + timedelta(minutes=random.randint(0, 600))
    user = random.choice(["uzair", "sara", "dev"])
    ip = random.choice(["192.168.1.10", "192.168.1.22"])
    if random.random() < 0.2:
        add(t, f"Failed password for {user} from {ip} port {random.randint(40000, 60000)} ssh2")
    add(t + timedelta(seconds=5), f"Accepted password for {user} from {ip} port {random.randint(40000, 60000)} ssh2")

# Attacker 1: fast brute force (40 tries in ~2 minutes), then gets in
t = start + timedelta(hours=3)
for i in range(40):
    user = random.choice(["root", "admin", "test", "ubuntu"])
    prefix = "invalid user " if user != "root" else ""
    add(t + timedelta(seconds=i * 3), f"Failed password for {prefix}{user} from 203.0.113.5 port {random.randint(40000, 60000)} ssh2")
add(t + timedelta(seconds=125), "Accepted password for root from 203.0.113.5 port 51234 ssh2")

# Attacker 2: slow and quiet (6 tries spread over hours), should NOT be flagged
for i in range(6):
    add(start + timedelta(hours=i * 2), f"Failed password for invalid user guest from 198.51.100.23 port {random.randint(40000, 60000)} ssh2")

lines.sort(key=lambda x: x[0])
with open("sample_auth.log", "w") as f:
    f.write("\n".join(text for _, text in lines) + "\n")
print(f"Wrote sample_auth.log ({len(lines)} lines)")
