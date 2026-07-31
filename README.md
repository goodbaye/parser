# LogSentinel

A small CLI tool that parses Linux SSH authentication logs (`auth.log` / `secure`)
and flags suspicious activity: brute-force attempts, successful logins that
follow a string of failures, and logins during off-hours.

This was built as a self-contained learning project to practice log parsing
and detection logic similar in spirit to SIEM correlation rules — implemented
from scratch in Python rather than relying on an existing SIEM.

## Features

- Parses standard OpenSSH syslog lines (`Failed password`, `Accepted password` /
  `Accepted publickey`, `Invalid user`)
- Detection rules:
  - **Brute force** — N or more failed logins from the same IP within a sliding time window
  - **Success after failures** — a successful login from an IP that had several
    recent failed attempts (classic "attacker eventually got in" pattern)
  - **Off-hours login** — a successful login during a configurable off-hours window
- Console report, plus optional JSON / CSV export
- Unit tests (pytest) and a GitHub Actions CI workflow

## Installation

```bash
git clone https://github.com/<your-username>/logsentinel.git
cd logsentinel
pip install -r requirements.txt
```

No external dependencies are required to run the tool itself — `requirements.txt`
only pulls in `pytest` for running the test suite.

## Usage

```bash
python3 -m logsentinel.cli sample_logs/auth.log --year 2026
```

Export findings:

```bash
python3 -m logsentinel.cli sample_logs/auth.log --year 2026 --json findings.json --csv findings.csv
```

Options:

| Flag | Description |
|---|---|
| `--year YEAR` | Year to assume for log timestamps (syslog lines don't include a year). Defaults to the current year. |
| `--json PATH` | Write findings as JSON to PATH |
| `--csv PATH` | Write findings as CSV to PATH |
| `--quiet` | Suppress the console report |

### Example output

```
Parsed 12 recognized log lines from sample_logs/auth.log

Findings: 4  (high=2, medium=2, low=0)
----------------------------------------------------------------------------------------------------
[HIGH  ] 2026-01-10T03:14:08  rule=brute_force              ip=203.0.113.5     user=root
          5 failed login attempts from 203.0.113.5 within 60s (threshold=5)
[HIGH  ] 2026-01-10T03:14:20  rule=success_after_failures   ip=203.0.113.5     user=root
          Successful login for user 'root' from 203.0.113.5 after 7 prior failed attempt(s)
[MEDIUM] 2026-01-10T02:47:33  rule=off_hours_login          ip=198.51.100.77   user=backup_svc
          Successful login for user 'backup_svc' from 198.51.100.77 at 02:47:33 (off-hours window)
[MEDIUM] 2026-01-10T03:14:20  rule=off_hours_login          ip=203.0.113.5     user=root
          Successful login for user 'root' from 203.0.113.5 at 03:14:20 (off-hours window)
----------------------------------------------------------------------------------------------------
```

## Running tests

```bash
pip install -r requirements.txt
pytest -v
```

## Project structure

```
logsentinel/
├── logsentinel/
│   ├── __init__.py
│   ├── parser.py      # log line parsing into LogEvent objects
│   ├── detectors.py   # detection rules -> Finding objects
│   ├── report.py      # console / JSON / CSV output
│   └── cli.py         # argparse-based CLI entry point
├── tests/
│   ├── test_parser.py
│   └── test_detectors.py
├── sample_logs/
│   └── auth.log       # synthetic example log for demoing the tool
└── .github/workflows/ci.yml
```

## Possible extensions

- Support for `journalctl` / `.evtx` (Windows Event Log) input
- A rule for detecting distributed brute force (many IPs, same target account)
- Config file for tuning thresholds instead of hardcoded defaults
- Packaging as a pip-installable CLI (`pyproject.toml`, `logsentinel` entry point)

## License

MIT — see [LICENSE](LICENSE).
