"""
cir.alerts
----------
The alert system. Subscribes to findings_bus and routes each Finding to:
  1. Console — rich-formatted, colour-coded by severity (always on)
  2. Halt controller — raises CIRHaltException if the detector is configured to halt
  3. Audit log — appends every finding to a JSONL file

Usage:

    from cir.alerts import AlertSystem

    system = AlertSystem(
        halt_on={"D3_sensitive_path_in_params"},          # halt for D3
        warn_only={"D1_file_read_after_error"},           # warn only for D1
        audit_log="cir_findings.jsonl",
    )
    system.start()
    # ... run agent ...
    system.stop()

Or via the cir top-level API after Stage 2 is wired in:

    import cir
    cir.patch()
    cir.enable(halt_on={"D3_sensitive_path_in_params"})
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import IO

from rich.console import Console
from rich.panel   import Panel
from rich.text    import Text

from .detectors import findings_bus, subscribe_findings
from .models    import Finding, Severity


# ---------------------------------------------------------------------------
# Custom exception — raised when a detector triggers a halt
# ---------------------------------------------------------------------------

class CIRHaltException(RuntimeError):
    """
    Raised when a finding matches a detector configured for halt.
    Catch this in your agent loop to abort the run cleanly.
    """
    def __init__(self, finding: Finding) -> None:
        self.finding = finding
        super().__init__(
            f"[CIR HALT] {finding.detector_id} — {finding.message}"
        )


# ---------------------------------------------------------------------------
# Severity styling
# ---------------------------------------------------------------------------

_SEVERITY_STYLE: dict[Severity, tuple[str, str]] = {
    # (panel border colour, label text)
    Severity.INFO:     ("bright_blue",  "ℹ INFO"),
    Severity.WARN:     ("yellow",       "⚠ WARN"),
    Severity.CRITICAL: ("bold red",     "✖ CRITICAL"),
}


# ---------------------------------------------------------------------------
# Alert system
# ---------------------------------------------------------------------------

class AlertSystem:
    """
    Wires findings from the findings_bus to console, halt, and audit log.

    Parameters
    ----------
    halt_on     : set of detector_ids that should raise CIRHaltException
    warn_only   : set of detector_ids that should only print (never halt),
                  even if also listed in halt_on (warn_only takes precedence)
    audit_log   : path to the JSONL audit log file (None = no file)
    console     : rich Console instance (defaults to stderr so it doesn't
                  pollute stdout pipelines)
    quiet       : suppress console output (audit log still written)
    """

    def __init__(
        self,
        halt_on:   set[str] | None = None,
        warn_only: set[str] | None = None,
        audit_log: str | Path | None = "cir_findings.jsonl",
        console:   Console | None = None,
        quiet:     bool = False,
    ) -> None:
        self.halt_on   = halt_on   or set()
        self.warn_only = warn_only or set()
        self.audit_log = Path(audit_log) if audit_log else None
        self.quiet     = quiet

        self._console  = console or Console(stderr=True, highlight=False)
        self._lock     = threading.Lock()
        self._log_file: IO | None = None
        self._running  = False

        # Stats — useful for post-run summaries
        self.counts: dict[Severity, int] = {s: 0 for s in Severity}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> "AlertSystem":
        if self.audit_log:
            self.audit_log.parent.mkdir(parents=True, exist_ok=True)
            self._log_file = open(self.audit_log, "a", encoding="utf-8")
        findings_bus.subscribe(self._handle)   # type: ignore[arg-type]
        self._running = True
        return self

    def stop(self) -> None:
        findings_bus.unsubscribe(self._handle) # type: ignore[arg-type]
        self._running = False
        with self._lock:
            if self._log_file:
                self._log_file.flush()
                self._log_file.close()
                self._log_file = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()

    # ------------------------------------------------------------------
    # Core handler — called for every Finding
    # ------------------------------------------------------------------

    def _handle(self, finding: Finding) -> None:
        with self._lock:
            self.counts[finding.severity] += 1
            self._write_audit(finding)

        if not self.quiet:
            self._print_console(finding)

        # Halt check — outside lock so the exception propagates cleanly
        should_halt = (
            finding.detector_id in self.halt_on
            and finding.detector_id not in self.warn_only
        )
        if should_halt:
            raise CIRHaltException(finding)

    # ------------------------------------------------------------------
    # Console output
    # ------------------------------------------------------------------

    def _print_console(self, finding: Finding) -> None:
        style, label = _SEVERITY_STYLE[finding.severity]

        # Build the panel body
        body = Text()
        body.append(f"{label}\n", style=style)
        body.append(f"Detector : ", style="bold")
        body.append(f"{finding.detector_id}\n")
        body.append(f"Tool     : ", style="bold")
        body.append(f"{finding.event.tool_name}\n")
        body.append(f"Message  : ", style="bold")
        body.append(f"{finding.message}\n")

        if finding.extra:
            body.append(f"Details  : ", style="bold")
            for k, v in finding.extra.items():
                body.append(f"\n  {k}: {v}")

        ts = time.strftime("%H:%M:%S", time.localtime(finding.wall_time))
        panel = Panel(
            body,
            title        = f"[{style}]CIR Alert — {ts}[/{style}]",
            border_style = style,
            expand       = False,
        )
        self._console.print(panel)

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def _write_audit(self, finding: Finding) -> None:
        if not self._log_file:
            return
        record = {
            "finding_id":  finding.finding_id,
            "wall_time":   finding.wall_time,
            "detector_id": finding.detector_id,
            "severity":    finding.severity.value,
            "message":     finding.message,
            "tool_name":   finding.event.tool_name,
            "tool_params": _safe(finding.event.parameters),
            "extra":       finding.extra,
        }
        self._log_file.write(json.dumps(record, default=str) + "\n")
        self._log_file.flush()

    # ------------------------------------------------------------------
    # Summary — call after agent run
    # ------------------------------------------------------------------

    def summary(self) -> str:
        lines = ["CIR run summary:"]
        total = sum(self.counts.values())
        for sev in (Severity.CRITICAL, Severity.WARN, Severity.INFO):
            lines.append(f"  {sev.value:10s}: {self.counts[sev]}")
        lines.append(f"  {'TOTAL':10s}: {total}")
        return "\n".join(lines)

    def print_summary(self) -> None:
        self._console.print(self.summary())


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _safe(value) -> object:
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return repr(value)
