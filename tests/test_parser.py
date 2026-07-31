from logsentinel.parser import parse_line


def test_parse_failed_password():
    line = "Jan 10 03:14:03 webserver sshd[1201]: Failed password for invalid user admin from 203.0.113.5 port 51501 ssh2"
    event = parse_line(line, year=2026)
    assert event is not None
    assert event.event_type == "failed"
    assert event.user == "admin"
    assert event.ip == "203.0.113.5"
    assert event.timestamp.hour == 3
    assert event.timestamp.minute == 14


def test_parse_accepted_password():
    line = "Jan 10 03:14:20 webserver sshd[1206]: Accepted password for root from 203.0.113.5 port 51506 ssh2"
    event = parse_line(line, year=2026)
    assert event is not None
    assert event.event_type == "accepted"
    assert event.user == "root"
    assert event.ip == "203.0.113.5"


def test_parse_invalid_user():
    line = "Jan 10 03:14:02 webserver sshd[1201]: Invalid user admin from 203.0.113.5"
    event = parse_line(line, year=2026)
    assert event is not None
    assert event.event_type == "invalid_user"
    assert event.user == "admin"


def test_parse_unrecognized_line_returns_none():
    line = "Jan 10 03:14:02 webserver CRON[999]: some unrelated cron message"
    assert parse_line(line, year=2026) is None


def test_parse_empty_line_returns_none():
    assert parse_line("", year=2026) is None
