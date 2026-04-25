"""
cir.models
----------
Shared data structures. Everything in the pipeline is built on ToolEvent
and Finding — keep this file dependency-free.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    CRITICAL = "CRITICAL"


class EventKind(str, Enum):
    CALL_START = "call_start"   # captured before the tool runs
    CALL_END   = "call_end"     # captured after the tool returns
    CALL_ERROR = "call_error"   # tool raised an exception


@dataclass
class ToolEvent:
    """One instrumented tool invocation (or error)."""

    tool_name:   str
    kind:        EventKind
    parameters:  dict[str, Any]

    # populated on CALL_END / CALL_ERROR
    output:      Any            = None
    error:       str | None     = None

    # timing
    wall_time:   float          = field(default_factory=time.time)
    mono_time:   float          = field(default_factory=time.monotonic)

    # identity
    event_id:    str            = field(default_factory=lambda: str(uuid.uuid4()))
    call_id:     str            = field(default_factory=lambda: str(uuid.uuid4()))
    # call_id is shared between the CALL_START and its matching CALL_END/ERROR


@dataclass
class Finding:
    """A detection result emitted by a behavioral detector."""

    detector_id: str
    severity:    Severity
    message:     str
    event:       ToolEvent
    extra:       dict[str, Any] = field(default_factory=dict)

    finding_id:  str            = field(default_factory=lambda: str(uuid.uuid4()))
    wall_time:   float          = field(default_factory=time.time)
