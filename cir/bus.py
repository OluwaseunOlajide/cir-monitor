"""
cir.bus
-------
A lightweight publish/subscribe event bus.

Instrumentation publishes ToolEvents here.
Detectors and the audit logger subscribe to receive them.

Thread-safe: uses a threading.Lock so the bus works both in synchronous
agent loops and in threaded/async contexts that call sync wrappers.
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Callable

from .models import ToolEvent

_Subscriber = Callable[[ToolEvent], None]


class EventBus:
    def __init__(self, history_size: int = 1000) -> None:
        self._lock        = threading.Lock()
        self._subscribers: list[_Subscriber] = []
        # Keep a rolling window of recent events so detectors can look back
        self._history: deque[ToolEvent] = deque(maxlen=history_size)

    # ------------------------------------------------------------------
    # Subscription
    # ------------------------------------------------------------------

    def subscribe(self, fn: _Subscriber) -> None:
        """Register a callable that will be invoked for every new event."""
        with self._lock:
            self._subscribers.append(fn)

    def unsubscribe(self, fn: _Subscriber) -> None:
        with self._lock:
            self._subscribers = [s for s in self._subscribers if s != fn]

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------

    def publish(self, event: ToolEvent) -> None:
        """Push an event to history and notify all subscribers."""
        with self._lock:
            self._history.append(event)
            subscribers = list(self._subscribers)   # snapshot under lock

        # Call subscribers outside the lock so they can safely publish too
        for fn in subscribers:
            try:
                fn(event)
            except Exception as exc:
                # CIRHaltException must propagate — it is an intentional stop signal.
                # All other subscriber exceptions are swallowed so they never
                # crash the agent under observation.
                from cir.alerts import CIRHaltException
                if isinstance(exc, CIRHaltException):
                    raise
                pass

    # ------------------------------------------------------------------
    # History access (for detectors that need a look-back window)
    # ------------------------------------------------------------------

    def recent(self, n: int | None = None) -> list[ToolEvent]:
        """Return up to *n* most-recent events (newest last)."""
        with self._lock:
            events = list(self._history)
        return events if n is None else events[-n:]

    def clear(self) -> None:
        with self._lock:
            self._history.clear()


# Module-level default bus — importable directly as `from cir.bus import bus`
bus = EventBus()
