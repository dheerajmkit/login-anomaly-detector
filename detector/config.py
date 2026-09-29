"""Detection tuning. Override by editing these defaults."""

DEFAULTS = {
    "bruteforce": {
        "max_attempts": 5,  # failed logins per (user, src_ip) to trigger
        "window_minutes": 10,  # sliding window in minutes
    },
    "spray": {
        "min_users": 5,  # distinct usernames per src_ip to trigger
        "window_minutes": 10,  # sliding window in minutes
    },
}
