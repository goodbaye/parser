from datetime import datetime, timedelta

from logsentinel.parser import LogEvent
from logsentinel.detectors import (
    detect_brute_force,
    detect_success_after_failures,
    detect_off_hours_logins,
)


def make_event(event_type, user, ip, ts, host="host"):
    return LogEvent(timestamp=ts, host=host, event_type=event_type, user=user, ip=ip, raw="")


def test_detect_brute_force_triggers_above_threshold():
    base = datetime(2026, 1, 10, 3, 0, 0)
    events = [
        make_event("failed", "root", "203.0.113.5", base + timedelta(seconds=i * 5))
        for i in range(6)
    ]
    findings = detect_brute_force(events, threshold=5, window_seconds=60)
    assert len(findings) == 1
    assert findings[0].rule == "brute_force"
    assert findings[0].ip == "203.0.113.5"


def test_detect_brute_force_no_trigger_below_threshold():
    base = datetime(2026, 1, 10, 3, 0, 0)
    events = [
        make_event("failed", "root", "203.0.113.5", base + timedelta(seconds=i * 5))
        for i in range(3)
    ]
    findings = detect_brute_force(events, threshold=5, window_seconds=60)
    assert findings == []


def test_detect_success_after_failures():
    base = datetime(2026, 1, 10, 3, 0, 0)
    events = [
        make_event("failed", "root", "203.0.113.5", base),
        make_event("failed", "root", "203.0.113.5", base + timedelta(seconds=3)),
        make_event("failed", "root", "203.0.113.5", base + timedelta(seconds=6)),
        make_event("accepted", "root", "203.0.113.5", base + timedelta(seconds=9)),
    ]
    findings = detect_success_after_failures(events, min_prior_failures=3)
    assert len(findings) == 1
    assert findings[0].rule == "success_after_failures"


def test_detect_off_hours_logins():
    events = [
        make_event("accepted", "backup_svc", "198.51.100.77", datetime(2026, 1, 10, 2, 47, 33)),
        make_event("accepted", "deploy", "198.51.100.20", datetime(2026, 1, 10, 9, 5, 11)),
    ]
    findings = detect_off_hours_logins(events, start_hour=0, end_hour=5)
    assert len(findings) == 1
    assert findings[0].user == "backup_svc"
