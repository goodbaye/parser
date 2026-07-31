"""
Parser for Linux SSH authentication logs (auth.log / secure).

Supports the standard syslog format produced by OpenSSH, e.g.:

    Jan 10 03:14:15 host sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51515 ssh2
    Jan 10 03:14:20 host sshd[1234]: Accepted password for root from 203.0.113.5 port 51516 ssh2
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator, Optional

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# e.g. "Jan 10 03:14:15 host sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51515 ssh2"
_LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(\[\d+\])?:\s+(?P<message>.*)$"
)

_FAILED_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)
_ACCEPTED_RE = re.compile(
    r"Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)
_INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"
)


@dataclass
class LogEvent:
    timestamp: datetime
    host: str
    event_type: str  # "failed", "accepted", "invalid_user"
    user: str
    ip: str
    raw: str


def _parse_timestamp(month: str, day: str, time_str: str, year: int) -> datetime:
    month_num = _MONTHS.get(month, 1)
    hour, minute, second = (int(p) for p in time_str.split(":"))
    return datetime(year, month_num, int(day), hour, minute, second)


def parse_line(line: str, year: Optional[int] = None) -> Optional[LogEvent]:
    """Parse a single auth.log line into a LogEvent, or None if it doesn't match."""
    line = line.rstrip("\n")
    if not line:
        return None

    m = _LINE_RE.match(line)
    if not m:
        return None

    message = m.group("message")
    year = year or datetime.now().year
    ts = _parse_timestamp(m.group("month"), m.group("day"), m.group("time"), year)
    host = m.group("host")

    fm = _FAILED_RE.search(message)
    if fm:
        return LogEvent(ts, host, "failed", fm.group("user"), fm.group("ip"), line)

    am = _ACCEPTED_RE.search(message)
    if am:
        return LogEvent(ts, host, "accepted", am.group("user"), am.group("ip"), line)

    im = _INVALID_USER_RE.search(message)
    if im:
        return LogEvent(ts, host, "invalid_user", im.group("user"), im.group("ip"), line)

    return None


def parse_file(path: str, year: Optional[int] = None) -> Iterator[LogEvent]:
    """Parse an auth.log file, yielding LogEvent objects for recognized lines."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_line(line, year=year)
            if event is not None:
                yield event
