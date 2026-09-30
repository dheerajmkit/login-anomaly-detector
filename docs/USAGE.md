# Usage guide

## Supported log formats

**Syslog-style** (parsed with a regex):
```
Sep 28 10:15:01 web-01 sshd[1234]: Failed password for root from 203.0.113.5 port 22
Sep 28 10:16:44 web-01 sshd[1290]: Accepted password for alice from 10.0.1.20 port 51102
```
Both `Failed` and `Accepted` password lines are handled, including
`Failed password for invalid user <name>` variants.

**CSV** (header must be exactly `timestamp,user,src_ip,result`):
```
timestamp,user,src_ip,result
2026-09-28T10:00:12,alice,10.0.1.20,success
2026-09-28T10:03:44,root,203.0.113.5,failed
```
Timestamps accept `YYYY-MM-DDTHH:MM:SS`, `YYYY-MM-DD HH:MM:SS`, or
`MMM DD HH:MM:SS`. Unparseable lines are skipped and reported in the count.

## Running

```bash
python3 run.py <logfile>          # human-readable alert summary
python3 run.py --json <logfile>   # alerts as JSON
```

## Tuning thresholds

Edit `detector/config.py`:

- `bruteforce.max_attempts` — failed logins per `(user, src_ip)` to alert (default 5)
- `bruteforce.window_minutes` — sliding window in minutes (default 10)
- `spray.min_users` — distinct usernames per `src_ip` to alert (default 5)
- `spray.window_minutes` — sliding window in minutes (default 10)

Severity is `medium` for a threshold-level burst and `high` once the count
reaches twice the threshold; spray alerts are always `high`.

## SIEM-forwarding notes

The `--json` output is one JSON document with an `alerts` array, which is
easy to ship to a SIEM:

- Pipe it to `logger` to land in local syslog, then collect with your
  normal log forwarder.
- Write it to a file and ingest with a forwarder (e.g. Splunk UF,
  Filebeat) on a schedule.
- Alert fields — `type`, `src_ip`, `user` (bruteforce), `users` (spray),
  `count`, `window_start`, `window_end`, `severity` — map directly onto
  common alert schemas for correlation.
