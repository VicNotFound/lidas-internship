"""Alert emitters — separated from the rule engine on purpose.

In production the emitter may run in a different process (or container)
from the engine, so a broken emitter cannot affect detection. This module
expresses that boundary as a clean class hierarchy with no access to
engine internals.

A rule engine that cannot emit alerts must still keep running and continue
detection — the alerts will be lost but detection will not stop. This is
fail-open for detection.
"""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod

from .audit_log import AuditLogWriter
from .models import Alert, Severity

# ANSI escape codes colourise severity in terminals that support them.
# Pass use_color=False to strip colours (e.g. redirected logs / CI).
_SEVERITY_COLOR: dict[Severity, str] = {
    Severity.LOW: "\033[36m",  # cyan
    Severity.MEDIUM: "\033[33m",  # yellow
    Severity.HIGH: "\033[31m",  # red
    Severity.CRITICAL: "\033[41m\033[97m",  # white on red
}
_RESET = "\033[0m"


class AlertEmitter(ABC):
    """All emitters must implement this. Must never raise — a broken
    emitter must not crash the engine or stop other emitters.
    """

    @abstractmethod
    def emit(self, alert: Alert) -> None:
        ...


class ConsoleEmitter(AlertEmitter):
    """Print colour-coded alert lines to stdout. Safe in Docker — the
    container captures stdout.
    """

    def __init__(self, use_color: bool = True, stream=None) -> None:
        self.use_color = use_color
        # Accepting a stream in __init__ makes this testable without mocking
        # sys.stdout — tests pass io.StringIO().
        self.stream = stream or sys.stdout

    def emit(self, alert: Alert) -> None:
        try:
            line = (
                f"[{alert.severity.value:8s}] {alert.timestamp.isoformat()} "
                f"{alert.rule_id} ({alert.rule_name}) — {alert.summary} "
                f"[confidence={alert.confidence:.2f}]"
            )
            if self.use_color:
                color = _SEVERITY_COLOR.get(alert.severity, "")
                line = f"{color}{line}{_RESET}"
            print(line, file=self.stream)
        except Exception:
            # A print failure — broken pipe, closed stream — must never
            # surface to the engine.
            pass


class AuditLogEmitter(AlertEmitter):
    """Write every alert to the HMAC-chained audit log.

    This is the security-critical emitter — ConsoleEmitter is for operator
    convenience only.
    """

    def __init__(self, writer: AuditLogWriter) -> None:
        self.writer = writer

    def emit(self, alert: Alert) -> None:
        try:
            self.writer.write(alert)
        except Exception:
            # In production, a write failure here should itself trigger an
            # out-of-band operational alert (e.g. PagerDuty). For now, we
            # fail silently to keep the engine running.
            pass


class MultiEmitter(AlertEmitter):
    """Fan-out — one alert goes to all registered emitters.

    Each emitter runs independently; a failure in one does not skip the
    others (each has its own try/except in its own emit()).
    """

    def __init__(self, emitters: list[AlertEmitter]) -> None:
        self.emitters = emitters

    def emit(self, alert: Alert) -> None:
        for emitter in self.emitters:
            emitter.emit(alert)
