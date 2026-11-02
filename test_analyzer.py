"""Run: python test_analyzer.py"""
from datetime import datetime, timedelta
from log_analyzer import analyze

T0 = datetime(2026, 11, 2, 3, 0, 0)

def fails(ip, n, gap_seconds):
    return [(T0 + timedelta(seconds=i * gap_seconds), "Failed", "root", ip) for i in range(n)]

# Fast burst is flagged; slow trickle is not
assert [r["ip"] for r in analyze(fails("1.1.1.1", 12, 3) + fails("2.2.2.2", 12, 3600))] == ["1.1.1.1"]

# A success after failures marks the IP as possibly compromised
ev = fails("1.1.1.1", 12, 3) + [(T0 + timedelta(minutes=2), "Accepted", "root", "1.1.1.1")]
assert analyze(ev)[0]["got_in"] is True

# Too few failures: nothing flagged
assert analyze(fails("3.3.3.3", 5, 1)) == []
print("All tests passed")
