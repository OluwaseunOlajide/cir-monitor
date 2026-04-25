"""
tests/test_stage3.py
Tests for the alert system.
"""

import json
import time
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from rich.console import Console
from io import StringIO

from cir.alerts  import AlertSystem, CIRHaltException
from cir.bus     import EventBus
from cir.detectors import (
    FileReadAfterErrorDetector,
    OutputTypeMismatchDetector,
    SensitivePathDetector,
    findings_bus,
)
import cir.detectors as det_mod
from cir.models  import EventKind, Finding, Severity, ToolEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_finding(
    detector_id: str = "D3_sensitive_path_in_params",
    severity: Severity = Severity.CRITICAL,
    message: str = "test finding",
    tool_name: str = "read_file",
) -> Finding:
    event = ToolEvent(
        tool_name  = tool_name,
        kind       = EventKind.CALL_START,
        parameters = {"path": "/etc/passwd"},
    )
    return Finding(
        detector_id = detector_id,
        severity    = severity,
        message     = message,
        event       = event,
    )


def make_event(tool_name, kind, parameters=None, output=None, error=None, call_id="test"):
    return ToolEvent(
        tool_name=tool_name, kind=kind,
        parameters=parameters or {}, output=output,
        error=error, call_id=call_id,
    )


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------

class TestConsoleOutput:
    def test_finding_printed_to_console(self):
        buf     = StringIO()
        console = Console(file=buf, highlight=False)
        system  = AlertSystem(console=console, audit_log=None)
        system.start()

        finding = make_finding(severity=Severity.WARN, message="suspicious path access")
        findings_bus.publish(finding)  # type: ignore

        system.stop()
        output = buf.getvalue()
        assert "suspicious path access" in output
        assert "D3_sensitive_path_in_params" in output

    def test_severity_levels_all_render(self):
        for severity in (Severity.INFO, Severity.WARN, Severity.CRITICAL):
            buf     = StringIO()
            console = Console(file=buf, highlight=False)
            system  = AlertSystem(console=console, audit_log=None)
            system.start()
            findings_bus.publish(make_finding(severity=severity))  # type: ignore
            system.stop()
            assert severity.value in buf.getvalue()

    def test_quiet_mode_suppresses_console(self):
        buf     = StringIO()
        console = Console(file=buf, highlight=False)
        system  = AlertSystem(console=console, audit_log=None, quiet=True)
        system.start()
        findings_bus.publish(make_finding(message="should not appear"))  # type: ignore
        system.stop()
        assert "should not appear" not in buf.getvalue()


# ---------------------------------------------------------------------------
# Halt behaviour
# ---------------------------------------------------------------------------

class TestHaltBehaviour:
    def test_halt_raises_exception(self):
        system = AlertSystem(
            halt_on   = {"D3_sensitive_path_in_params"},
            audit_log = None,
            quiet     = True,
        )
        system.start()

        finding = make_finding(detector_id="D3_sensitive_path_in_params",
                               severity=Severity.CRITICAL)
        caught = []
        try:
            findings_bus.publish(finding)  # type: ignore
        except CIRHaltException as e:
            caught.append(e)
        finally:
            system.stop()

        assert len(caught) == 1
        assert caught[0].finding is finding

    def test_warn_only_overrides_halt(self):
        """A detector in both halt_on and warn_only should NOT halt."""
        system = AlertSystem(
            halt_on   = {"D3_sensitive_path_in_params"},
            warn_only = {"D3_sensitive_path_in_params"},
            audit_log = None,
            quiet     = True,
        )
        system.start()

        # Should not raise
        findings_bus.publish(make_finding(detector_id="D3_sensitive_path_in_params"))  # type: ignore
        system.stop()

    def test_non_halt_detector_does_not_halt(self):
        system = AlertSystem(
            halt_on   = {"D3_sensitive_path_in_params"},
            audit_log = None,
            quiet     = True,
        )
        system.start()
        # D1 is not in halt_on — should not raise
        findings_bus.publish(make_finding(detector_id="D1_file_read_after_error",
                                          severity=Severity.WARN))  # type: ignore
        system.stop()

    def test_halt_exception_contains_finding(self):
        system = AlertSystem(halt_on={"D3_sensitive_path_in_params"}, audit_log=None, quiet=True)
        system.start()
        finding = make_finding(detector_id="D3_sensitive_path_in_params",
                               message="sensitive path detected")
        try:
            findings_bus.publish(finding)  # type: ignore
        except CIRHaltException as e:
            assert e.finding.message == "sensitive path detected"
            assert "D3_sensitive_path_in_params" in str(e)
        finally:
            system.stop()


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

class TestAuditLog:
    def test_findings_written_to_jsonl(self, tmp_path):
        log = tmp_path / "findings.jsonl"
        system = AlertSystem(audit_log=log, quiet=True)
        system.start()

        findings_bus.publish(make_finding(message="audit test finding"))  # type: ignore
        system.stop()

        lines = log.read_text().strip().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["message"]     == "audit test finding"
        assert record["detector_id"] == "D3_sensitive_path_in_params"
        assert record["severity"]    == "CRITICAL"
        assert "finding_id"  in record
        assert "wall_time"   in record
        assert "tool_name"   in record

    def test_multiple_findings_appended(self, tmp_path):
        log = tmp_path / "findings.jsonl"
        system = AlertSystem(audit_log=log, quiet=True)
        system.start()

        findings_bus.publish(make_finding(message="first"))   # type: ignore
        findings_bus.publish(make_finding(message="second"))  # type: ignore
        system.stop()

        lines = log.read_text().strip().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["message"] == "first"
        assert json.loads(lines[1])["message"] == "second"

    def test_no_audit_log_when_path_is_none(self, tmp_path):
        system = AlertSystem(audit_log=None, quiet=True)
        system.start()
        findings_bus.publish(make_finding())  # type: ignore
        system.stop()
        # No files should be created
        assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# Counts and summary
# ---------------------------------------------------------------------------

class TestCountsAndSummary:
    def test_counts_tracked_per_severity(self):
        system = AlertSystem(audit_log=None, quiet=True)
        system.start()

        findings_bus.publish(make_finding(severity=Severity.CRITICAL))  # type: ignore
        findings_bus.publish(make_finding(severity=Severity.WARN))      # type: ignore
        findings_bus.publish(make_finding(severity=Severity.WARN))      # type: ignore
        system.stop()

        assert system.counts[Severity.CRITICAL] == 1
        assert system.counts[Severity.WARN]     == 2
        assert system.counts[Severity.INFO]     == 0

    def test_summary_string_contains_counts(self):
        system = AlertSystem(audit_log=None, quiet=True)
        system.start()
        findings_bus.publish(make_finding(severity=Severity.CRITICAL))  # type: ignore
        system.stop()

        summary = system.summary()
        assert "CRITICAL" in summary
        assert "1"        in summary


# ---------------------------------------------------------------------------
# End-to-end: full pipeline — instrumentation → detectors → alerts
# ---------------------------------------------------------------------------

class TestEndToEnd:
    def test_sensitive_path_triggers_halt_through_full_stack(self, tmp_path):
        """
        Simulate: agent calls a tool with /etc/passwd in parameters.
        D3 should fire → AlertSystem should halt.
        """
        log = tmp_path / "findings.jsonl"
        eb  = EventBus()

        captured_findings = []
        original_emit = det_mod._emit
        det_mod._emit = lambda f: (captured_findings.append(f),
                                   findings_bus.publish(f))  # type: ignore

        detector = SensitivePathDetector(event_bus=eb)
        system   = AlertSystem(
            halt_on   = {"D3_sensitive_path_in_params"},
            audit_log = log,
            quiet     = True,
        )
        detector.start()
        system.start()

        halted = []
        try:
            eb.publish(make_event(
                "read_file", EventKind.CALL_START,
                parameters={"path": "/etc/passwd"},
            ))
        except CIRHaltException as e:
            halted.append(e)
        finally:
            detector.stop()
            system.stop()
            det_mod._emit = original_emit

        assert len(halted) == 1
        assert len(captured_findings) >= 1
        assert log.exists()

    def test_warn_finding_does_not_halt_but_logs(self, tmp_path):
        log = tmp_path / "warn.jsonl"
        eb  = EventBus()

        original_emit = det_mod._emit
        det_mod._emit = lambda f: findings_bus.publish(f)  # type: ignore

        detector = FileReadAfterErrorDetector(window_seconds=5.0, event_bus=eb)
        system   = AlertSystem(audit_log=log, quiet=True)
        detector.start()
        system.start()

        # Trigger D1: error then file read
        eb.publish(make_event("api_call", EventKind.CALL_ERROR, error="Timeout"))
        eb.publish(make_event("read_file", EventKind.CALL_START,
                              parameters={"path": "/tmp/data.txt"}))

        detector.stop()
        system.stop()
        det_mod._emit = original_emit

        # Should have logged the finding but not raised
        lines = log.read_text().strip().splitlines()
        assert len(lines) >= 1
        assert json.loads(lines[0])["detector_id"] == "D1_file_read_after_error"
