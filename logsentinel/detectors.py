"""
Detection rules applied to a stream of parsed LogEvent objects.

Each detector returns a list of Finding objects. Findings are intentionally
simple/serializable so they can be exported to JSON or CSV.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import List

from .parser import LogEvent

DEFAULT_BRUTE_FORCE_THRESHOLD = 5
DEFAULT_BRUTE_FORCE_WINDOW_SECONDS = 60
DEFAULT_OFF_HOURS_START = 0   # 00:00
DEFAULT_OFF_HOURS_END = 5     # 05:00 (exclusive)


@dataclass
class Finding:
    rule: str
    severity: str  # "low" | "medium" | "high"
    ip: str
    user: str
    timestamp: str
    detail: str


def detect_brute_force(
    events: List[LogEvent],
    threshold: int = DEFAULT_BRUTE_FORCE_THRESHOLD,
    window_seconds: int = DEFAULT_BRUTE_FORCE_WINDOW_SECONDS,
) -> List[Finding]:
    """Flag IPs with >= threshold failed logins within a sliding time window."""
    findings: List[Finding] = []
    by_ip = defaultdict(list)
    for e in events:
        if e.event_type in ("failed", "invalid_user"):
            by_ip[e.ip].append(e)

    window = timedelta(seconds=window_seconds)
    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e.timestamp)
        start = 0
        for end in range(len(ip_events)):
            while ip_events[end].timestamp - ip_events[start].timestamp > window:
                start += 1
            count = end - start + 1
            if count >= threshold:
                findings.append(
                    Finding(
                        rule="brute_force",
                        severity="high",
                        ip=ip,
                        user=ip_events[end].user,
                        timestamp=ip_events[end].timestamp.isoformat(),
                        detail=(
                            f"{count} failed login attempts from {ip} "
                            f"within {window_seconds}s (threshold={threshold})"
                        ),
                    )
                )
                # avoid flooding findings for every single event past threshold
                start = end + 1
    return findings


def detect_success_after_failures(
    events: List[LogEvent],
    min_prior_failures: int = 3,
) -> List[Finding]:
    """Flag an accepted login from an IP that had several prior failures."""
    findings: List[Finding] = []
    fail_counts = defaultdict(int)

    for e in sorted(events, key=lambda e: e.timestamp):
        if e.event_type in ("failed", "invalid_user"):
            fail_counts[e.ip] += 1
        elif e.event_type == "accepted":
            prior_fails = fail_counts[e.ip]
            if prior_fails >= min_prior_failures:
                findings.append(
                    Finding(
                        rule="success_after_failures",
                        severity="high",
                        ip=e.ip,
                        user=e.user,
                        timestamp=e.timestamp.isoformat(),
                        detail=(
                            f"Successful login for user '{e.user}' from {e.ip} "
                            f"after {prior_fails} prior failed attempt(s)"
                        ),
                    )
                )
            fail_counts[e.ip] = 0
    return findings


def detect_off_hours_logins(
    events: List[LogEvent],
    start_hour: int = DEFAULT_OFF_HOURS_START,
    end_hour: int = DEFAULT_OFF_HOURS_END,
) -> List[Finding]:
    """Flag accepted logins that occur between start_hour and end_hour (local log time)."""
    findings: List[Finding] = []
    for e in events:
        if e.event_type == "accepted" and start_hour <= e.timestamp.hour < end_hour:
            findings.append(
                Finding(
                    rule="off_hours_login",
                    severity="medium",
                    ip=e.ip,
                    user=e.user,
                    timestamp=e.timestamp.isoformat(),
                    detail=(
                        f"Successful login for user '{e.user}' from {e.ip} "
                        f"at {e.timestamp.strftime('%H:%M:%S')} (off-hours window)"
                    ),
                )
            )
    return findings


def run_all_detectors(events: List[LogEvent]) -> List[Finding]:
    findings: List[Finding] = []
    findings += detect_brute_force(events)
    findings += detect_success_after_failures(events)
    findings += detect_off_hours_logins(events)
    return findings
