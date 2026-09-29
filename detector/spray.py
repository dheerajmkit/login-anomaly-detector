"""Detect password spraying: one src_ip failing against many usernames."""

from collections import defaultdict
from datetime import timedelta


def detect_spray(events, min_users=5, window_minutes=10):
    """Find source IPs probing distinct usernames inside a sliding window.

    Returns a list of alert dicts: type, src_ip, users, count, window_start,
    window_end, severity.
    """
    failed = [e for e in events if e["result"] == "failed"]
    by_ip = defaultdict(list)
    for e in failed:
        by_ip[e["src_ip"]].append(e)

    window = timedelta(minutes=window_minutes)
    alerts = []
    for src_ip, evs in by_ip.items():
        evs.sort(key=lambda e: e["timestamp"])
        best_users, best_start = set(), None
        for i, e in enumerate(evs):
            users, j = set(), i
            while j < len(evs) and evs[j]["timestamp"] - e["timestamp"] <= window:
                users.add(evs[j]["user"])
                j += 1
            if len(users) > len(best_users):
                best_users, best_start = users, e["timestamp"]
        if len(best_users) >= min_users:
            alerts.append(
                {
                    "type": "spray",
                    "src_ip": src_ip,
                    "users": sorted(best_users),
                    "count": len(best_users),
                    "window_start": best_start.isoformat(),
                    "window_end": (best_start + window).isoformat(),
                    "severity": "high",
                }
            )
    return sorted(alerts, key=lambda a: a["window_start"])
