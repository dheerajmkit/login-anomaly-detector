"""Detect brute-force attacks: bursts of failed logins for one (user, src_ip)."""

from collections import defaultdict
from datetime import timedelta


def detect_bruteforce(events, max_attempts=5, window_minutes=10):
    """Find failed-login bursts inside a sliding time window per (user, src_ip).

    Returns a list of alert dicts: type, user, src_ip, count, window_start,
    window_end, severity.
    """
    failed = [e for e in events if e["result"] == "failed"]
    groups = defaultdict(list)
    for e in failed:
        groups[(e["user"], e["src_ip"])].append(e)

    window = timedelta(minutes=window_minutes)
    alerts = []
    for (user, src_ip), evs in groups.items():
        evs.sort(key=lambda e: e["timestamp"])
        best, best_start = 0, None
        for i, e in enumerate(evs):
            j = i
            while j < len(evs) and evs[j]["timestamp"] - e["timestamp"] <= window:
                j += 1
            if j - i > best:
                best, best_start = j - i, e["timestamp"]
        if best >= max_attempts:
            alerts.append(
                {
                    "type": "bruteforce",
                    "user": user,
                    "src_ip": src_ip,
                    "count": best,
                    "window_start": best_start.isoformat(),
                    "window_end": (best_start + window).isoformat(),
                    "severity": "high" if best >= max_attempts * 2 else "medium",
                }
            )
    return sorted(alerts, key=lambda a: a["window_start"])
