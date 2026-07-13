"""Log line parser — the ONLY component that touches untrusted data.

Core design principle: never raise on bad input. A line that cannot be
parsed becomes an UNKNOWN event rather than crashing the pipeline. This
matters for security: a malformed log line crafted by an attacker could
otherwise be a DoS against the IDS itself — if the parser throws, detection
stops for every subsequent line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass(frozen=True)
class LogEvent:
    """Normalised representation of a single log line."""

    # always the original line, never modified — used as evidence in alerts
    raw: str
    # always timezone-aware (UTC) so correlations across sources are safe
    timestamp: datetime
    # one of "ssh", "http", "unknown" — never any other value
    source: str
    source_ip: Optional[str] = None
    user: Optional[str] = None  # SSH username attempt
    # "failed"/"accepted" for SSH, HTTP status code string for HTTP
    status: Optional[str] = None
    path: Optional[str] = None  # HTTP request path including query string
    user_agent: Optional[str] = None
    # extensibility slot for future parsers without changing the dataclass shape
    extra: dict = field(default_factory=dict)


# Matches an IPv4 address; used as a named group in both SSH and HTTP regexes.
# Four dotted octets (0–255 loosely — we accept any 1–3 digit group for speed;
# a malformed IP still becomes usable evidence rather than a parse failure).
_IP_RE = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"

# OpenSSH syslog line. Optional "invalid user " handles both:
#   Failed password for admin from 10.0.0.5 ...
#   Failed password for invalid user admin from 10.0.0.5 ...
# Example match:
#   Jun 30 09:00:02 host sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 51514 ssh2
_SSH_RE = re.compile(
    rf"^(?P<ts>\w{{3}}\s+\d{{1,2}}\s+\d{{2}}:\d{{2}}:\d{{2}})\s+"
    rf"\S+\s+sshd\[\d+\]:\s+"
    rf"(?P<result>Failed|Accepted)\s+password\s+for\s+"
    rf"(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+{_IP_RE}"
    rf"(?:\s+port\s+\d+)?",
    re.IGNORECASE,
)

# Combined Log Format. User agent is optional — some configs omit it.
# Path uses .+? (not \S+) so injection payloads with spaces inside the
# quoted request still parse — real CLF encodes spaces, but attack fixtures
# often leave them raw and the IDS must still see the signature text.
# Example match:
#   10.0.0.20 - - [30/Jun/2026:09:00:01 +0000] "GET /api/v1/pets HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
_HTTP_RE = re.compile(
    rf"^{_IP_RE}\s+\S+\s+\S+\s+"
    rf"\[(?P<ts>[^\]]+)\]\s+"
    rf'"(?P<method>\S+)\s+(?P<path>.+?)(?:\s+HTTP/[\d.]+)?"\s+'
    rf"(?P<status>\d{{3}})"
    rf'(?:\s+\S+(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?)?',
)

_SSH_TS_FMT = "%b %d %H:%M:%S"
_HTTP_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _safe_year_ssh_ts(ts_str: str) -> datetime:
    """Parse a syslog timestamp that omits the year.

    Assumption: use the current UTC year. Limitation: at the Dec/Jan year
    boundary a log from December processed in January may be stamped with
    the wrong year (off by ~1 year). Acceptable for a learning IDS; a
    production system would carry year from the file mtime or rotatelogs.
    """
    try:
        # syslog has no year — assume current year and treat as UTC
        parsed = datetime.strptime(ts_str.strip(), _SSH_TS_FMT)
        now = datetime.now(timezone.utc)
        return parsed.replace(year=now.year, tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def parse_line(line: str) -> LogEvent:
    """Parse a single log line into a LogEvent. Never raises."""
    # preserve the original content for evidence, but drop trailing newline
    # so comparisons and HMAC payloads are stable
    raw = line.rstrip("\r\n")

    # empty / whitespace-only: no signal — UNKNOWN rather than guessing
    if not raw.strip():
        return LogEvent(
            raw=raw,
            timestamp=datetime.now(timezone.utc),
            source="unknown",
        )

    # try SSH first — most structured of our formats; a mistaken HTTP match
    # on an SSH line would be worse than UNKNOWN on a rare hybrid
    ssh_m = _SSH_RE.search(raw)
    if ssh_m:
        result = ssh_m.group("result").lower()
        status = "failed" if result == "failed" else "accepted"
        return LogEvent(
            raw=raw,
            timestamp=_safe_year_ssh_ts(ssh_m.group("ts")),
            source="ssh",
            source_ip=ssh_m.group("ip"),
            user=ssh_m.group("user"),
            status=status,
        )

    # then Combined Log Format HTTP
    http_m = _HTTP_RE.search(raw)
    if http_m:
        ts_str = http_m.group("ts")
        try:
            ts = datetime.strptime(ts_str, _HTTP_TS_FMT)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except ValueError:
            ts = datetime.now(timezone.utc)
        return LogEvent(
            raw=raw,
            timestamp=ts,
            source="http",
            source_ip=http_m.group("ip"),
            status=http_m.group("status"),
            path=http_m.group("path"),
            user_agent=http_m.group("ua"),
        )

    # fallback: attacker-crafted or unrelated lines must not crash the pipeline
    return LogEvent(
        raw=raw,
        timestamp=datetime.now(timezone.utc),
        source="unknown",
    )


def parse_lines(lines) -> list[LogEvent]:
    """Parse an iterable of strings into one LogEvent each.

    Every line yields an event — we never skip or drop lines so the event
    count remains auditable against the input line count.
    """
    return [parse_line(line) for line in lines]
