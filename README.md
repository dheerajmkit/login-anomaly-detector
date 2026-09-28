# login-anomaly-detector

A portfolio security-automation project: a small Python 3 tool that parses
authentication logs and flags brute-force and password-spray attacks.

## Quickstart

```bash
python3 run.py samples/auth-sample.log
python3 run.py samples/auth-sample.csv
python3 run.py --json samples/auth-spray.log
```

## How it works

1. `detector/parser.py` reads syslog-style `sshd` lines and simple
   `timestamp,user,src_ip,result` CSV rows into normalized event dicts.
2. `detector/bruteforce.py` flags bursts of failed logins for one
   `(user, src_ip)` pair inside a sliding window.
3. `detector/spray.py` flags one source IP failing against many distinct
   usernames inside a sliding window.
4. Alerts print in human-readable form, or as JSON with `--json`.
5. `detector/reporter.py` renders alerts as a Markdown incident report.

## Layout

- `run.py` — CLI entry point
- `detector/` — parser, detectors, config, reporter
- `tests/` — pytest suite
- `samples/` — example logs to try the tool on
- `docs/USAGE.md` — usage guide (formats, tuning, SIEM notes)

Standard library only — no third-party dependencies.
