"""Core data models shared between the rule engine and the alert emitter.
Keeping models in their own module prevents circular imports and lets tests
import them without pulling in rule logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    """Alert severity levels.

    Inheriting from (str, Enum) means each member is also a plain string
    (e.g. Severity.HIGH == "HIGH"). That lets json.dumps serialise severity
    without a custom encoder — critical for the audit log HMAC which must
    hash a deterministic JSON representation.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class Alert:
    """Immutable detection alert produced by a rule.

    frozen=True: once an alert is emitted it must not be mutated. The audit
    log hashes the alert payload; any in-place change after emission would
    desync what operators see from what was recorded.
    """

    rule_id: str
    rule_name: str
    severity: Severity
    timestamp: datetime
    source_ip: str | None
    # confidence is a float in [0.0, 1.0]: 0.0 means the rule has no belief
    # this is an attack; 1.0 means the event is unambiguously malicious
    # (e.g. a canary token hit). The engine suppresses alerts below the
    # global threshold so low-confidence noise never reaches operators.
    confidence: float
    summary: str
    # evidence is a list because one alert can be backed by multiple log
    # lines — e.g. a brute-force burst of five failed SSH attempts.
    evidence: list[str] = field(default_factory=list)
