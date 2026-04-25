"""
cir.detectors
-------------
Behavioral detectors. Each subscribes to the event bus and emits Findings
onto a findings bus when suspicious patterns are observed.

Detector IDs:
  D1 — file_read_after_error   : file read within N seconds of a tool error
  D2 — output_type_mismatch    : actual output type differs from expected
  D3 — sensitive_path_in_params: tool parameters contain sensitive file paths
"""

from __future__ import annotations

import re
import time
from collections import deque
from typing import Callable

from .bus    import EventBus, bus as default_bus
from .models import EventKind, Finding, Severity, ToolEvent

# ---------------------------------------------------------------------------
# Findings bus — separate from the event bus so detectors don't feed back
# into themselves
# ---------------------------------------------------------------------------

from .bus import EventBus as _EventBus

findings_bus = _EventBus(history_size=500)

_FindingSubscriber = Callable[[Finding], None]


def subscribe_findings(fn: _FindingSubscriber) -> None:
    findings_bus.subscribe(fn)          # type: ignore[arg-type]


def _emit(finding: Finding) -> None:
    findings_bus.publish(finding)       # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Base detector
# ---------------------------------------------------------------------------

class BaseDetector:
    detector_id: str = "base"

    def __init__(self, event_bus: EventBus | None = None) -> None:
        self._bus = event_bus or default_bus

    def start(self) -> "BaseDetector":
        self._bus.subscribe(self.process)
        return self

    def stop(self) -> None:
        self._bus.unsubscribe(self.process)

    def process(self, event: ToolEvent) -> None:
        raise NotImplementedError

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()


# ---------------------------------------------------------------------------
# D1 — File read after error
# ---------------------------------------------------------------------------

# Tool names that constitute a "file read" operation
_FILE_READ_TOOL_NAMES = re.compile(
    r"(read_file|open_file|file_read|read|load_file|get_file"
    r"|readfile|file_get|read_document|fetch_file)",
    re.IGNORECASE,
)

# Also flag if parameters contain a recognisable file path
_FILE_PATH_IN_PARAMS = re.compile(
    r'[a-zA-Z]:\\|/[a-z]|\.txt|\.json|\.yaml|\.yml|\.csv|\.log|\.py|\.env',
)


def _looks_like_file_read(event: ToolEvent) -> bool:
    if _FILE_READ_TOOL_NAMES.search(event.tool_name):
        return True
    # Check parameter values for file-path-like strings
    for v in event.parameters.values():
        if isinstance(v, str) and _FILE_PATH_IN_PARAMS.search(v):
            return True
    return False


class FileReadAfterErrorDetector(BaseDetector):
    """
    D1: Flag a file-read tool call that occurs within *window_seconds*
    of any CALL_ERROR event.
    """
    detector_id = "D1_file_read_after_error"

    def __init__(
        self,
        window_seconds: float = 5.0,
        event_bus: EventBus | None = None,
    ) -> None:
        super().__init__(event_bus)
        self.window_seconds = window_seconds
        # Store (wall_time, event) for recent errors
        self._recent_errors: deque[tuple[float, ToolEvent]] = deque(maxlen=50)

    def process(self, event: ToolEvent) -> None:
        now = time.time()

        if event.kind == EventKind.CALL_ERROR:
            self._recent_errors.append((now, event))
            return

        if event.kind != EventKind.CALL_START:
            return

        if not _looks_like_file_read(event):
            return

        # Purge expired errors
        cutoff = now - self.window_seconds
        while self._recent_errors and self._recent_errors[0][0] < cutoff:
            self._recent_errors.popleft()

        if not self._recent_errors:
            return

        # There is at least one recent error — this is suspicious
        prior_error = self._recent_errors[-1][1]
        _emit(Finding(
            detector_id = self.detector_id,
            severity    = Severity.WARN,
            message     = (
                f"File-read tool '{event.tool_name}' called "
                f"{now - self._recent_errors[-1][0]:.2f}s after error in "
                f"'{prior_error.tool_name}' "
                f"({prior_error.error})"
            ),
            event       = event,
            extra       = {
                "triggering_error_tool": prior_error.tool_name,
                "triggering_error":      prior_error.error,
                "seconds_after_error":   now - self._recent_errors[-1][0],
            },
        ))


# ---------------------------------------------------------------------------
# D2 — Output type mismatch
# ---------------------------------------------------------------------------

# Default expected output types per tool name pattern.
# Users can override via the detector's `expected_types` dict.
_DEFAULT_EXPECTED: dict[str, type | tuple[type, ...]] = {
    "search":      (list, dict, str),
    "web_search":  (list, dict, str),
    "read_file":   str,
    "read":        str,
    "calculator":  (int, float, str),
    "run_code":    (str, dict),
    "execute":     (str, dict),
    "http_request":(dict, str),
    "fetch":       (dict, str),
}


class OutputTypeMismatchDetector(BaseDetector):
    """
    D2: Flag tool calls where the returned output type differs from
    what is expected for that tool.

    Severity is WARN for unexpected-but-harmless types (e.g. None),
    CRITICAL when bytes or unknown objects are returned from text tools.
    """
    detector_id = "D2_output_type_mismatch"

    def __init__(
        self,
        expected_types: dict[str, type | tuple[type, ...]] | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        super().__init__(event_bus)
        self.expected_types: dict[str, type | tuple[type, ...]] = {
            **_DEFAULT_EXPECTED,
            **(expected_types or {}),
        }

    def _expected_for(self, tool_name: str) -> type | tuple[type, ...] | None:
        # Exact match first
        if tool_name in self.expected_types:
            return self.expected_types[tool_name]
        # Substring match
        tl = tool_name.lower()
        for key, typ in self.expected_types.items():
            if key in tl:
                return typ
        return None

    def process(self, event: ToolEvent) -> None:
        if event.kind != EventKind.CALL_END:
            return

        expected = self._expected_for(event.tool_name)
        if expected is None:
            return   # no expectation registered for this tool

        actual = type(event.output)

        if isinstance(event.output, expected):
            return  # all good

        # Determine severity
        severity = (
            Severity.CRITICAL
            if actual in (bytes, bytearray) or event.output is None
            else Severity.WARN
        )

        expected_names = (
            expected.__name__
            if isinstance(expected, type)
            else " | ".join(t.__name__ for t in expected)
        )

        _emit(Finding(
            detector_id = self.detector_id,
            severity    = severity,
            message     = (
                f"Tool '{event.tool_name}' returned {actual.__name__!r} "
                f"but expected {expected_names!r}"
            ),
            event       = event,
            extra       = {
                "expected_types": expected_names,
                "actual_type":    actual.__name__,
                "output_repr":    repr(event.output)[:200],
            },
        ))


# ---------------------------------------------------------------------------
# D3 — Sensitive path in parameters
# ---------------------------------------------------------------------------

_SENSITIVE_PATTERNS: list[tuple[re.Pattern, str, Severity]] = [
    # (pattern, label, severity)
    (re.compile(r'[/\\]\.ssh[/\\]',          re.IGNORECASE), "SSH directory",          Severity.CRITICAL),
    (re.compile(r'id_rsa|id_ed25519|id_ecdsa',re.IGNORECASE), "SSH private key",        Severity.CRITICAL),
    (re.compile(r'[/\\]etc[/\\]passwd',       re.IGNORECASE), "/etc/passwd",             Severity.CRITICAL),
    (re.compile(r'[/\\]etc[/\\]shadow',       re.IGNORECASE), "/etc/shadow",             Severity.CRITICAL),
    (re.compile(r'\.env$|[/\\]\.env[/\\$]',  re.IGNORECASE), ".env file",               Severity.CRITICAL),
    (re.compile(r'credentials',               re.IGNORECASE), "credentials file/dir",    Severity.CRITICAL),
    (re.compile(r'[/\\]\.aws[/\\]',           re.IGNORECASE), "AWS credentials dir",     Severity.CRITICAL),
    (re.compile(r'[/\\]\.config[/\\]',        re.IGNORECASE), ".config directory",       Severity.WARN),
    (re.compile(r'secret',                    re.IGNORECASE), "secret in path",          Severity.WARN),
    (re.compile(r'token',                     re.IGNORECASE), "token in path",           Severity.WARN),
    (re.compile(r'password|passwd',           re.IGNORECASE), "password in path",        Severity.WARN),
    (re.compile(r'private[_\-.]?key',         re.IGNORECASE), "private key reference",   Severity.CRITICAL),
    (re.compile(r'[/\\]proc[/\\]',            re.IGNORECASE), "/proc filesystem",        Severity.WARN),
    (re.compile(r'[/\\]sys[/\\]',             re.IGNORECASE), "/sys filesystem",         Severity.WARN),
]


def _scan_value(value: object) -> list[tuple[str, Severity]]:
    """Return list of (label, severity) for any sensitive patterns found."""
    if not isinstance(value, str):
        value = repr(value)
    hits = []
    for pattern, label, severity in _SENSITIVE_PATTERNS:
        if pattern.search(value):
            hits.append((label, severity))
    return hits


class SensitivePathDetector(BaseDetector):
    """
    D3: Flag tool calls whose parameters reference sensitive file system
    locations — SSH keys, credential files, /etc/passwd, .env, etc.

    Runs on CALL_START so the finding is raised *before* the tool executes,
    giving the halt controller a chance to stop it.

    Pass extra_patterns to extend the built-in list:
        extra_patterns=[("my label", r"supersecret\\.txt", Severity.CRITICAL)]
    """
    detector_id = "D3_sensitive_path_in_params"

    def __init__(
        self,
        extra_patterns: list[tuple[str, str, Severity]] | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        super().__init__(event_bus)
        self._patterns = list(_SENSITIVE_PATTERNS)
        for label, pattern_str, severity in (extra_patterns or []):
            self._patterns.append(
                (re.compile(pattern_str, re.IGNORECASE), label, severity)
            )

    def _scan_value(self, value: object) -> list[tuple[str, Severity]]:
        if not isinstance(value, str):
            value = repr(value)
        return [
            (label, severity)
            for pattern, label, severity in self._patterns
            if pattern.search(value)
        ]

    def process(self, event: ToolEvent) -> None:
        if event.kind != EventKind.CALL_START:
            return

        for param_name, param_value in event.parameters.items():
            hits = self._scan_value(param_value)
            for label, severity in hits:
                _emit(Finding(
                    detector_id = self.detector_id,
                    severity    = severity,
                    message     = (
                        f"Tool '{event.tool_name}' parameter '{param_name}' "
                        f"references sensitive location: {label} "
                        f"(value: {str(param_value)[:120]!r})"
                    ),
                    event       = event,
                    extra       = {
                        "param_name":  param_name,
                        "param_value": str(param_value)[:200],
                        "match_label": label,
                    },
                ))


# ---------------------------------------------------------------------------
# Convenience: build all four detectors at once
# ---------------------------------------------------------------------------

def build_all(
    *,
    window_seconds: float = 5.0,
    expected_types: dict | None = None,
    event_bus: EventBus | None = None,
) -> list[BaseDetector]:
    return [
        FileReadAfterErrorDetector(window_seconds=window_seconds, event_bus=event_bus),
        OutputTypeMismatchDetector(expected_types=expected_types,  event_bus=event_bus),
        SensitivePathDetector(event_bus=event_bus),
        SemanticExfiltrationDetector(event_bus=event_bus),
    ]

# ---------------------------------------------------------------------------
# D4 — Semantic exfiltration detector
# ---------------------------------------------------------------------------

# Parameter names that should never carry large string payloads
_EXFIL_PARAM_NAMES = re.compile(
    r"^(instructions?|context|override|token|secret|history|payload"
    r"|session|auth|credential|api_key|system_prompt|background)$",
    re.IGNORECASE,
)

# Content patterns indicating conversation history or exfiltration
_CHAT_MARKERS = re.compile(
    r"(?m)^(User|Assistant|System|Human|AI|Instruction|Response|Context):\s",
    re.IGNORECASE,
)

_INSTRUCTIONAL_PATTERNS = re.compile(
    r"\b(always|never|ignore|forget|bypass|keep secret|do not tell|output only|hidden"
    r"|permutate|combine|reconstruct|scramble|reverse|extract|letters|characters)\b",
    re.IGNORECASE,
)

_EXFIL_MIN_LENGTH = 15   # keep low for demo; raise in production (recommend 80+)


class SemanticExfiltrationDetector(BaseDetector):
    """
    D4: Flag tool calls where parameters contain signs of semantic exfiltration.
    
    This detector uses a semi-intelligent scoring system:
    - Suspicious parameter names (instructions, context, etc.)
    - Chat log markers (User:, Assistant:, etc.)
    - Instructional keywords (always, never, ignore, etc.)
    - Length thresholds

    Runs on CALL_START so the halt controller can stop the call
    before data reaches a malicious server.
    """
    detector_id = "D4_semantic_exfiltration"

    def __init__(
        self,
        min_length: int = _EXFIL_MIN_LENGTH,
        extra_param_names: list[str] | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        super().__init__(event_bus)
        self.min_length = min_length
        self._name_pattern = _EXFIL_PARAM_NAMES
        if extra_param_names:
            combined = (
                _EXFIL_PARAM_NAMES.pattern.rstrip(")$")
                + "|" + "|".join(re.escape(n) for n in extra_param_names)
                + ")$"
            )
            self._name_pattern = re.compile(combined, re.IGNORECASE)

    def _calculate_score(self, name: str, value: str) -> tuple[int, list[str]]:
        score = 0
        reasons = []

        # 1. Parameter name check
        if self._name_pattern.match(name):
            score += 40
            reasons.append(f"suspicious_name({name})")

        # 2. Chat markers (high confidence indicator of history exfiltration)
        if _CHAT_MARKERS.search(value):
            score += 50
            reasons.append("chat_markers_detected")

        # 3. Instructional patterns
        if _INSTRUCTIONAL_PATTERNS.search(value):
            score += 20
            reasons.append("instructional_keywords_detected")

        # 4. Length bonuses (tuned to match legacy 200-char critical threshold when combined with name)
        if len(value) >= 2000:
            score += 50
            reasons.append("extreme_length")
        elif len(value) >= 500:
            score += 35
            reasons.append("very_high_length")
        elif len(value) >= 200:
            score += 30
            reasons.append("high_length")

        return score, reasons

    def process(self, event: ToolEvent) -> None:
        if event.kind != EventKind.CALL_START:
            return

        for param_name, param_value in event.parameters.items():
            if not isinstance(param_value, str):
                continue
            if len(param_value) < self.min_length:
                continue

            score, reasons = self._calculate_score(param_name, param_value)

            if score < 40:
                continue

            severity = Severity.CRITICAL if score >= 70 else Severity.WARN

            _emit(Finding(
                detector_id = self.detector_id,
                severity    = severity,
                message     = (
                    f"Tool '{event.tool_name}' parameter '{param_name}' "
                    f"flagged for semantic exfiltration (score: {score}). "
                    f"Reasons: {', '.join(reasons)}"
                ),
                event       = event,
                extra       = {
                    "param_name":     param_name,
                    "score":          score,
                    "reasons":        reasons,
                    "payload_length": len(param_value),
                    "preview":        param_value[:120],
                },
            ))