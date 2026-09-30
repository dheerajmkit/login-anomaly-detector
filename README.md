# login-anomaly-detector

A portfolio security-automation project: a small Python 3 tool that parses
authentication logs and flags brute-force and password-spray attacks.

## Quickstart

```bash
python3 run.py samples/auth-sample.log      # human-readable alert summary
python3 run.py samples/auth-sample.csv      # CSV format works too
python3 run.py --json samples/auth-spray.log # alerts as JSON
```

## Features

- **Log parsing** (`detector/parser.py`): syslog-style `sshd` lines and
  `timestamp,user,src_ip,result` CSV rows become normalized event dicts
  (`timestamp`, `user`, `src_ip`, `result`).
- **Brute-force detection** (`detector/bruteforce.py`): flags bursts of failed
  logins for one `(user, src_ip)` pair inside a sliding window
  (default: 5 failures in 10 minutes).
- **Password-spray detection** (`detector/spray.py`): flags one source IP
  failing against many distinct usernames in a sliding window
  (default: 5 users in 10 minutes).
- **JSON alert output** (`--json`): machine-readable alerts for piping into
  SIEM or log forwarders.
- **Markdown incident reports** (`detector/reporter.py`): `to_markdown(alerts)`
  renders per-alert details (type, source IP, targeted users, counts, window,
  severity).
- **Tunable thresholds**: edit `detector/config.py` (`DEFAULTS` dict).
- **Tests**: `tests/test_detector.py` covers the parser (both formats) and
  both detectors (firing and quiet cases).

## Layout

- `run.py` — CLI entry point
- `detector/` — parser, detectors, config, reporter
- `tests/` — pytest suite
- `samples/` — example logs (`auth-sample.log`, `auth-sample.csv`,
  `auth-spray.log`)
- `docs/USAGE.md` — usage guide (formats, tuning, SIEM notes)

Standard library only — no third-party dependencies (pytest only for tests).
