"""
cir — Confidential Inference Runtime monitor
============================================

Quick start:

    import cir

    cir.patch()          # instrument LangChain + CrewAI (skips if not installed)
    cir.start_logging()  # write raw events  → cir_events.jsonl
    cir.enable()         # activate detectors + alert system

    # … run your agent …

    cir.stop()           # flush and tear down
    cir.summary()        # print finding counts
"""

from __future__ import annotations

from .bus             import bus, EventBus
from .instrumentation import (
    instrument,
    patch_langchain,
    patch_crewai,
    patch_all as patch,
)
from .logger          import EventLogger
from .models          import EventKind, Finding, Severity, ToolEvent
from .detectors       import (
    FileReadAfterErrorDetector,
    OutputTypeMismatchDetector,
    SensitivePathDetector,
    build_all as _build_detectors,
    findings_bus,
)
from .alerts          import AlertSystem, CIRHaltException

__version__ = "0.1.0"

__all__ = [
    "ToolEvent", "Finding", "Severity", "EventKind",
    "bus", "EventBus", "findings_bus",
    "instrument", "patch", "patch_langchain", "patch_crewai",
    "FileReadAfterErrorDetector", "OutputTypeMismatchDetector", "SensitivePathDetector",
    "AlertSystem", "CIRHaltException",
    "EventLogger",
    "start_logging", "enable", "stop", "summary",
]

_logger:     EventLogger  | None = None
_detectors:  list                = []
_alert_sys:  AlertSystem  | None = None


def start_logging(path: str = "cir_events.jsonl", *, echo_stdout: bool = False) -> EventLogger:
    global _logger
    if _logger is not None:
        _logger.stop()
    _logger = EventLogger(path, echo_stdout=echo_stdout).start()
    return _logger


def enable(
    *,
    halt_on:        set[str] | None = None,
    warn_only:      set[str] | None = None,
    audit_log:      str | None = "cir_findings.jsonl",
    quiet:          bool = False,
    window_seconds: float = 5.0,
    expected_types: dict | None = None,
) -> AlertSystem:
    """
    Activate all three behavioral detectors and the alert system.

    halt_on        : detector IDs that raise CIRHaltException, e.g. {"D3_sensitive_path_in_params"}
    warn_only      : detector IDs that only warn, never halt
    audit_log      : path for the findings JSONL log (None = no file)
    quiet          : suppress console output
    window_seconds : D1 look-back window in seconds
    expected_types : override D2 expected output types per tool name
    """
    global _detectors, _alert_sys
    _teardown_detectors()

    _detectors = _build_detectors(window_seconds=window_seconds, expected_types=expected_types)
    for det in _detectors:
        det.start()

    _alert_sys = AlertSystem(
        halt_on=halt_on, warn_only=warn_only, audit_log=audit_log, quiet=quiet,
    ).start()
    return _alert_sys


def stop() -> None:
    global _logger
    if _logger is not None:
        _logger.stop()
        _logger = None
    _teardown_detectors()


def summary() -> None:
    if _alert_sys is not None:
        _alert_sys.print_summary()
    else:
        print("CIR: alert system not active — call cir.enable() first.")


def _teardown_detectors() -> None:
    global _detectors, _alert_sys
    for det in _detectors:
        det.stop()
    _detectors = []
    if _alert_sys is not None:
        _alert_sys.stop()
        _alert_sys = None
