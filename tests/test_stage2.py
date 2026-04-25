"""
tests/test_stage2.py
Tests for the three behavioral detectors.
"""

import time
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from cir.bus       import EventBus
from cir.detectors import (
    FileReadAfterErrorDetector,
    OutputTypeMismatchDetector,
    SensitivePathDetector,
)
from cir.models    import EventKind, Finding, Severity, ToolEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_event(tool_name, kind, parameters=None, output=None, error=None, call_id="test-call"):
    return ToolEvent(
        tool_name  = tool_name,
        kind       = kind,
        parameters = parameters or {},
        output     = output,
        error      = error,
        call_id    = call_id,
    )


def collect_findings(detector_cls, events, **kwargs):
    import cir.detectors as det_mod
    eb       = EventBus()
    captured = []
    original = det_mod._emit
    det_mod._emit = captured.append
    detector = detector_cls(event_bus=eb, **kwargs)
    detector.start()
    for event in events:
        eb.publish(event)
    detector.stop()
    det_mod._emit = original
    return captured


# ---------------------------------------------------------------------------
# D1
# ---------------------------------------------------------------------------

class TestD1FileReadAfterError:
    def test_fires_when_file_read_follows_error(self):
        events = [
            make_event("search_tool", EventKind.CALL_ERROR, error="ConnectionError", call_id="c1"),
            make_event("read_file", EventKind.CALL_START, parameters={"path": "/tmp/data.txt"}, call_id="c2"),
        ]
        findings = collect_findings(FileReadAfterErrorDetector, events, window_seconds=5.0)
        assert len(findings) == 1
        assert findings[0].severity    == Severity.WARN
        assert findings[0].detector_id == "D1_file_read_after_error"

    def test_does_not_fire_without_prior_error(self):
        events = [make_event("read_file", EventKind.CALL_START, parameters={"path": "/tmp/data.txt"})]
        assert collect_findings(FileReadAfterErrorDetector, events) == []

    def test_does_not_fire_after_window_expires(self):
        import cir.detectors as det_mod
        eb = EventBus()
        captured = []
        original = det_mod._emit
        det_mod._emit = captured.append
        detector = FileReadAfterErrorDetector(window_seconds=0.05, event_bus=eb)
        detector.start()
        eb.publish(make_event("api_call", EventKind.CALL_ERROR, error="Timeout", call_id="c1"))
        time.sleep(0.1)
        eb.publish(make_event("read_file", EventKind.CALL_START, parameters={"path": "/tmp/x.txt"}, call_id="c2"))
        detector.stop()
        det_mod._emit = original
        assert captured == []

    def test_detects_file_read_by_parameter_path(self):
        events = [
            make_event("process_data", EventKind.CALL_ERROR, error="ValueError", call_id="c1"),
            make_event("load_document", EventKind.CALL_START, parameters={"source": "/home/user/report.json"}, call_id="c2"),
        ]
        assert len(collect_findings(FileReadAfterErrorDetector, events, window_seconds=5.0)) == 1

    def test_multiple_errors_one_finding_per_read(self):
        events = [
            make_event("tool_a", EventKind.CALL_ERROR, error="Err1", call_id="c1"),
            make_event("tool_b", EventKind.CALL_ERROR, error="Err2", call_id="c2"),
            make_event("read_file", EventKind.CALL_START, parameters={"path": "/tmp/x.txt"}, call_id="c3"),
        ]
        assert len(collect_findings(FileReadAfterErrorDetector, events, window_seconds=5.0)) == 1


# ---------------------------------------------------------------------------
# D2
# ---------------------------------------------------------------------------

class TestD2OutputTypeMismatch:
    def test_no_finding_for_correct_type(self):
        events = [make_event("web_search", EventKind.CALL_END, output=["r1", "r2"])]
        assert collect_findings(OutputTypeMismatchDetector, events) == []

    def test_fires_on_type_mismatch(self):
        events = [make_event("web_search", EventKind.CALL_END, output=12345)]
        findings = collect_findings(OutputTypeMismatchDetector, events)
        assert len(findings) == 1
        assert "int" in findings[0].message
        assert findings[0].detector_id == "D2_output_type_mismatch"

    def test_critical_severity_for_bytes(self):
        events = [make_event("read_file", EventKind.CALL_END, output=b"binary data")]
        findings = collect_findings(OutputTypeMismatchDetector, events)
        assert findings[0].severity == Severity.CRITICAL

    def test_critical_severity_for_none(self):
        events = [make_event("web_search", EventKind.CALL_END, output=None)]
        findings = collect_findings(OutputTypeMismatchDetector, events)
        assert findings[0].severity == Severity.CRITICAL

    def test_no_finding_for_unknown_tool(self):
        events = [make_event("some_custom_tool", EventKind.CALL_END, output=object())]
        assert collect_findings(OutputTypeMismatchDetector, events) == []

    def test_custom_expected_types(self):
        events = [make_event("my_tool", EventKind.CALL_END, output="not an int")]
        findings = collect_findings(OutputTypeMismatchDetector, events, expected_types={"my_tool": int})
        assert len(findings) == 1

    def test_substring_match_on_tool_name(self):
        events = [make_event("fast_web_search_v2", EventKind.CALL_END, output=999)]
        assert len(collect_findings(OutputTypeMismatchDetector, events)) == 1

    def test_ignores_call_start_events(self):
        events = [make_event("web_search", EventKind.CALL_START, output=None)]
        assert collect_findings(OutputTypeMismatchDetector, events) == []


# ---------------------------------------------------------------------------
# D3
# ---------------------------------------------------------------------------

class TestD3SensitivePath:
    def _run(self, tool_name, params, **kwargs):
        events = [make_event(tool_name, EventKind.CALL_START, parameters=params)]
        return collect_findings(SensitivePathDetector, events, **kwargs)

    def test_ssh_directory_is_critical(self):
        findings = self._run("read_file", {"path": "/home/user/.ssh/id_rsa"})
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_etc_passwd_is_critical(self):
        findings = self._run("read_file", {"path": "/etc/passwd"})
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_env_file_is_critical(self):
        findings = self._run("load_config", {"file": "/app/.env"})
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_aws_credentials_is_critical(self):
        findings = self._run("read_file", {"path": "/home/user/.aws/credentials"})
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_token_in_path_is_warn(self):
        findings = self._run("fetch", {"url": "/var/app/token_store"})
        assert any(f.severity == Severity.WARN for f in findings)

    def test_clean_path_no_finding(self):
        assert self._run("read_file", {"path": "/tmp/output.txt"}) == []

    def test_fires_on_call_start_not_call_end(self):
        import cir.detectors as det_mod
        eb = EventBus()
        captured = []
        original = det_mod._emit
        det_mod._emit = captured.append
        detector = SensitivePathDetector(event_bus=eb)
        detector.start()
        eb.publish(make_event("read_file", EventKind.CALL_START, parameters={"path": "/etc/passwd"}))
        after_start = len(captured)
        assert after_start >= 1
        eb.publish(make_event("read_file", EventKind.CALL_END, parameters={"path": "/etc/passwd"}))
        assert len(captured) == after_start   # no new findings on CALL_END
        detector.stop()
        det_mod._emit = original

    def test_multiple_params_scanned(self):
        findings = self._run("multi_tool", {
            "query":  "safe query",
            "output": "/home/user/.ssh/authorized_keys",
            "extra":  "/etc/shadow",
        })
        labels = [f.extra["match_label"] for f in findings]
        assert any("SSH" in l or "key" in l.lower() for l in labels)
        assert any("shadow" in l.lower() for l in labels)

    def test_extra_custom_pattern(self):
        findings = self._run(
            "read_file",
            {"path": "/data/supersecret.txt"},
            extra_patterns=[("custom secret file", r"supersecret\.txt", Severity.CRITICAL)],
        )
        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)


# ---------------------------------------------------------------------------
# D4 — SemanticExfiltrationDetector
# ---------------------------------------------------------------------------

class TestD4SemanticExfiltration:
    def _run(self, tool_name, params, **kwargs):
        from cir.detectors import SemanticExfiltrationDetector
        events = [make_event(tool_name, EventKind.CALL_START, parameters=params)]
        return collect_findings(SemanticExfiltrationDetector, events, **kwargs)

    def test_large_instructions_param_flagged(self):
        findings = self._run("take_note", {
            "title":        "Meeting",
            "instructions": "User said: hi. Assistant said: hello. " * 5,
        })
        assert len(findings) >= 1
        assert findings[0].detector_id == "D4_semantic_exfiltration"

    def test_critical_for_very_large_payload(self):
        findings = self._run("take_note", {
            "instructions": "x" * 250,
        })
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_warn_for_medium_payload(self):
        findings = self._run("take_note", {
            "context": "y" * 100,
        })
        assert any(f.severity == Severity.WARN for f in findings)

    def test_short_value_not_flagged(self):
        findings = self._run("take_note", {
            "instructions": "brief",
        })
        assert findings == []

    def test_normal_param_name_not_flagged(self):
        findings = self._run("take_note", {
            "content": "x" * 300,
        })
        assert findings == []

    def test_override_param_flagged(self):
        findings = self._run("get_calendar", {
            "override": "sk-prod-ABC123XYZ789 session_id=abc " + "history: user said hello " * 3,
        })
        assert len(findings) >= 1

    def test_token_param_flagged(self):
        findings = self._run("api_call", {
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "payload.signature_here_long.extra" * 3,
        })
        assert len(findings) >= 1

    def test_fires_on_call_start_only(self):
        from cir.detectors import SemanticExfiltrationDetector
        import cir.detectors as det_mod
        eb = EventBus()
        captured = []
        original = det_mod._emit
        det_mod._emit = captured.append
        detector = SemanticExfiltrationDetector(event_bus=eb)
        detector.start()
        eb.publish(make_event("take_note", EventKind.CALL_START,
                              parameters={"instructions": "x" * 150}))
        assert len(captured) >= 1
        before = len(captured)
        eb.publish(make_event("take_note", EventKind.CALL_END,
                              parameters={"instructions": "x" * 150}))
        assert len(captured) == before
        detector.stop()
        det_mod._emit = original

    def test_extra_param_names(self):
        findings = self._run("tool", {
            "my_custom_field": "z" * 150,
        }, extra_param_names=["my_custom_field"])
        assert len(findings) >= 1

    def test_intelligence_flags_chat_log_in_normal_param(self):
        # 'notes' is not in the suspicious list, but contains User:/Assistant: markers
        findings = self._run("take_note", {
            "notes": "User: what is my password?\nAssistant: I cannot tell you.",
        })
        assert len(findings) >= 1
        assert "chat_markers_detected" in findings[0].extra["reasons"]
        assert findings[0].severity == Severity.WARN  # Score 50 (markers)
