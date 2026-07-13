"""Starter tests for lidas/parser.py (Week 1 scaffold).

Week 3 tasks: extend these with fuzz cases (null bytes, 1 MB lines, mixed
unicode, empty/whitespace) and add tests/test_rules.py and
tests/test_audit_log.py. See LIDAS_Intern_Guide for the full checklist.
"""

from lidas.parser import parse_line


def test_parses_valid_ssh_failed_login():
    line = (
        "Jun 30 09:00:02 webhost sshd[1234]: Failed password for invalid "
        "user admin from 10.0.0.5 port 51514 ssh2"
    )
    event = parse_line(line)
    assert event.source == "ssh"
    assert event.status == "failed"
    assert event.source_ip == "10.0.0.5"
    assert event.user == "admin"


def test_parses_valid_ssh_accepted_login():
    line = (
        "Jun 30 09:00:01 webhost sshd[1233]: Accepted password for samuel "
        "from 192.168.1.10 port 51000 ssh2"
    )
    event = parse_line(line)
    assert event.source == "ssh"
    assert event.status == "accepted"
    assert event.user == "samuel"


def test_parses_valid_http_line_with_user_agent():
    line = (
        '203.0.113.7 - - [30/Jun/2026:09:01:00 +0000] '
        '"GET /login?user=admin HTTP/1.1" 401 128 "-" "sqlmap/1.6.12"'
    )
    event = parse_line(line)
    assert event.source == "http"
    assert event.source_ip == "203.0.113.7"
    assert event.status == "401"
    assert "user=admin" in (event.path or "")
    assert event.user_agent == "sqlmap/1.6.12"


def test_parses_http_line_without_user_agent():
    line = (
        '10.0.0.20 - - [30/Jun/2026:09:00:01 +0000] '
        '"GET /api/v1/pets HTTP/1.1" 200 512'
    )
    event = parse_line(line)
    assert event.source == "http"
    assert event.status == "200"
    assert event.user_agent is None


def test_unrecognized_line_returns_unknown_not_exception():
    event = parse_line("This is not a valid log line at all")
    assert event.source == "unknown"
