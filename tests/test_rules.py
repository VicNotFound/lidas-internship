"""Week 3 deliverable: detection rule tests.

Write at least two tests per rule (positive + negative). Start from the
pattern in LIDAS_Intern_Guide Week 3, then cover every rule in rules.py.

TODO (Week 3):
- SSHBruteForceRule (SSH-001)
- SQLInjectionRule (HTTP-001)
- SuspiciousUserAgentRule (HTTP-002)
- CanaryTokenRule (CANARY-001)
- PortScanHintRule (HTTP-003)
- RuleEngine confidence threshold and error isolation
"""

from datetime import datetime, timedelta, timezone

from lidas.parser import LogEvent
from lidas.rules import SSHBruteForceRule

FIXED_TS = datetime(2026, 6, 30, 9, 0, 0, tzinfo=timezone.utc)


def _ssh_failed(ip: str, offset_secs: int = 0) -> LogEvent:
    return LogEvent(
        raw="...",
        timestamp=FIXED_TS + timedelta(seconds=offset_secs),
        source="ssh",
        source_ip=ip,
        status="failed",
        user="admin",
    )


def test_ssh_brute_force_example_positive():
    """Example positive test — replace/extend with your full Week 3 suite."""
    rule = SSHBruteForceRule(threshold=5, window=timedelta(seconds=60))
    alerts = []
    for i in range(5):
        alerts.extend(rule.process(_ssh_failed("10.0.0.5", offset_secs=i * 2)))
    assert len(alerts) == 1
    assert alerts[0].rule_id == "SSH-001"


def test_ssh_brute_force_example_negative():
    """Example negative test — extend with below-threshold and accepted-login cases."""
    rule = SSHBruteForceRule(threshold=5, window=timedelta(seconds=60))
    alerts = []
    for i in range(4):
        alerts.extend(rule.process(_ssh_failed("10.0.0.5", offset_secs=i * 2)))
    assert alerts == []
