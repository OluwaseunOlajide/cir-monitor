"""
cir.logger
----------
Subscribes to the event bus and writes every ToolEvent to a JSONL log file.
One JSON object per line, easy to stream with `tail -f` or parse with jq.

Usage:

    from cir.logger import EventLogger
    logger = EventLogger("cir_events.jsonl")
    logger.start()   # subscribes to bus
    # … run agent …
    logger.stop()    # unsubscribes, flushes, closes file
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import IO

from .bus import bus
from .models import ToolEvent


class EventLogger:
    """
    Writes ToolEvents as newline-delimited JSON to *path*.

    Thread-safe. Uses a background thread + queue so the agent's hot path
    is never blocked by I/O.
    """

    def __init__(
        self,
        path: str | Path = "cir_events.jsonl",
        *,
        echo_stdout: bool = False,
    ) -> None:
        self._path        = Path(path)
        self._echo        = echo_stdout
        self._file: IO | None = None
        self._lock        = threading.Lock()
        self._running     = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> "EventLogger":
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file   = open(self._path, "a", encoding="utf-8")
        self._running = True
        bus.subscribe(self._handle)
        return self

    def stop(self) -> None:
        bus.unsubscribe(self._handle)
        self._running = False
        with self._lock:
            if self._file:
                self._file.flush()
                self._file.close()
                self._file = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _handle(self, event: ToolEvent) -> None:
        record = _serialise(event)
        line   = json.dumps(record, default=str) + "\n"

        with self._lock:
            if self._file:
                self._file.write(line)
                self._file.flush()   # flush per-event for tail -f friendliness

        if self._echo:
            print(line, end="", flush=True)


# ---------------------------------------------------------------------------
# Serialisation helper
# ---------------------------------------------------------------------------

def _serialise(event: ToolEvent) -> dict:
    return {
        "event_id":   event.event_id,
        "call_id":    event.call_id,
        "kind":       event.kind.value,
        "tool_name":  event.tool_name,
        "parameters": _safe(event.parameters),
        "output":     _safe(event.output),
        "error":      event.error,
        "wall_time":  event.wall_time,
        "mono_time":  event.mono_time,
    }


def _safe(value) -> object:
    """Best-effort convert a value to a JSON-safe form."""
    if value is None:
        return None
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return repr(value)
