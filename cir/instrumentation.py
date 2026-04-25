"""
cir.instrumentation
-------------------
Wraps LangChain and CrewAI tool calls to publish ToolEvents onto the bus.

Usage — automatic patching (recommended):

    import cir
    cir.patch()          # patches both frameworks if installed
    # … run your agent …

Usage — manual / generic decorator:

    from cir.instrumentation import instrument

    @instrument
    def my_tool(query: str) -> str:
        return search(query)

The wrappers are non-invasive: if LangChain or CrewAI are not installed,
patching those frameworks is silently skipped.
"""

from __future__ import annotations

import functools
import time
import traceback
import uuid
from typing import Any, Callable

from .bus import bus
from .models import EventKind, ToolEvent

# ---------------------------------------------------------------------------
# Generic decorator — wraps any callable
# ---------------------------------------------------------------------------

def instrument(fn: Callable | None = None, *, tool_name: str | None = None):
    """
    Decorator that wraps a plain Python callable and publishes ToolEvents.

    Can be used with or without arguments:

        @instrument
        def search(q): ...

        @instrument(tool_name="web_search")
        def search(q): ...
    """
    def decorator(func: Callable) -> Callable:
        name = tool_name or func.__name__

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            call_id = str(uuid.uuid4())
            params  = _extract_params(func, args, kwargs)

            start_event = ToolEvent(
                tool_name  = name,
                kind       = EventKind.CALL_START,
                parameters = params,
                call_id    = call_id,
            )
            bus.publish(start_event)

            t0 = time.monotonic()
            try:
                result = func(*args, **kwargs)
                bus.publish(ToolEvent(
                    tool_name  = name,
                    kind       = EventKind.CALL_END,
                    parameters = params,
                    output     = result,
                    mono_time  = time.monotonic() - t0,
                    call_id    = call_id,
                ))
                return result
            except Exception as exc:
                bus.publish(ToolEvent(
                    tool_name  = name,
                    kind       = EventKind.CALL_ERROR,
                    parameters = params,
                    error      = f"{type(exc).__name__}: {exc}",
                    mono_time  = time.monotonic() - t0,
                    call_id    = call_id,
                ))
                raise

        # Async variant
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            call_id = str(uuid.uuid4())
            params  = _extract_params(func, args, kwargs)

            bus.publish(ToolEvent(
                tool_name  = name,
                kind       = EventKind.CALL_START,
                parameters = params,
                call_id    = call_id,
            ))

            t0 = time.monotonic()
            try:
                result = await func(*args, **kwargs)
                bus.publish(ToolEvent(
                    tool_name  = name,
                    kind       = EventKind.CALL_END,
                    parameters = params,
                    output     = result,
                    mono_time  = time.monotonic() - t0,
                    call_id    = call_id,
                ))
                return result
            except Exception as exc:
                bus.publish(ToolEvent(
                    tool_name  = name,
                    kind       = EventKind.CALL_ERROR,
                    parameters = params,
                    error      = f"{type(exc).__name__}: {exc}",
                    mono_time  = time.monotonic() - t0,
                    call_id    = call_id,
                ))
                raise

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    if fn is not None:
        # Used as @instrument (no parentheses)
        return decorator(fn)
    return decorator


# ---------------------------------------------------------------------------
# LangChain patcher
# ---------------------------------------------------------------------------

def patch_langchain() -> bool:
    """
    Monkey-patch LangChain's BaseTool.run and BaseTool.arun.
    Returns True if patching succeeded, False if LangChain is not installed.
    """
    try:
        from langchain_core.tools import BaseTool  # type: ignore
    except ImportError:
        try:
            from langchain.tools import BaseTool   # type: ignore
        except ImportError:
            return False

    if getattr(BaseTool, "_cir_patched", False):
        return True  # already patched this session

    original_run  = BaseTool.run
    original_arun = BaseTool.arun

    def patched_run(self, tool_input: Any, *args, **kwargs):
        call_id = str(uuid.uuid4())
        params  = _normalise_tool_input(tool_input)

        bus.publish(ToolEvent(
            tool_name  = self.name,
            kind       = EventKind.CALL_START,
            parameters = params,
            call_id    = call_id,
        ))

        t0 = time.monotonic()
        try:
            result = original_run(self, tool_input, *args, **kwargs)
            bus.publish(ToolEvent(
                tool_name  = self.name,
                kind       = EventKind.CALL_END,
                parameters = params,
                output     = result,
                mono_time  = time.monotonic() - t0,
                call_id    = call_id,
            ))
            return result
        except Exception as exc:
            bus.publish(ToolEvent(
                tool_name  = self.name,
                kind       = EventKind.CALL_ERROR,
                parameters = params,
                error      = f"{type(exc).__name__}: {exc}",
                mono_time  = time.monotonic() - t0,
                call_id    = call_id,
            ))
            raise

    async def patched_arun(self, tool_input: Any, *args, **kwargs):
        call_id = str(uuid.uuid4())
        params  = _normalise_tool_input(tool_input)

        bus.publish(ToolEvent(
            tool_name  = self.name,
            kind       = EventKind.CALL_START,
            parameters = params,
            call_id    = call_id,
        ))

        t0 = time.monotonic()
        try:
            result = await original_arun(self, tool_input, *args, **kwargs)
            bus.publish(ToolEvent(
                tool_name  = self.name,
                kind       = EventKind.CALL_END,
                parameters = params,
                output     = result,
                mono_time  = time.monotonic() - t0,
                call_id    = call_id,
            ))
            return result
        except Exception as exc:
            bus.publish(ToolEvent(
                tool_name  = self.name,
                kind       = EventKind.CALL_ERROR,
                parameters = params,
                error      = f"{type(exc).__name__}: {exc}",
                mono_time  = time.monotonic() - t0,
                call_id    = call_id,
            ))
            raise

    BaseTool.run   = patched_run
    BaseTool.arun  = patched_arun
    BaseTool._cir_patched = True
    return True


# ---------------------------------------------------------------------------
# CrewAI patcher
# ---------------------------------------------------------------------------

def patch_crewai() -> bool:
    """
    Monkey-patch CrewAI's Tool._run.
    Returns True if patching succeeded, False if CrewAI is not installed.
    """
    try:
        from crewai.tools import BaseTool as CrewBaseTool  # type: ignore
    except ImportError:
        try:
            from crewai import Tool as CrewBaseTool        # type: ignore
        except ImportError:
            return False

    if getattr(CrewBaseTool, "_cir_patched", False):
        return True

    original_run = CrewBaseTool._run

    def patched_run(self, *args, **kwargs):
        call_id = str(uuid.uuid4())
        params  = {"args": list(args), **kwargs}

        bus.publish(ToolEvent(
            tool_name  = getattr(self, "name", type(self).__name__),
            kind       = EventKind.CALL_START,
            parameters = params,
            call_id    = call_id,
        ))

        t0 = time.monotonic()
        try:
            result = original_run(self, *args, **kwargs)
            bus.publish(ToolEvent(
                tool_name  = getattr(self, "name", type(self).__name__),
                kind       = EventKind.CALL_END,
                parameters = params,
                output     = result,
                mono_time  = time.monotonic() - t0,
                call_id    = call_id,
            ))
            return result
        except Exception as exc:
            bus.publish(ToolEvent(
                tool_name  = getattr(self, "name", type(self).__name__),
                kind       = EventKind.CALL_ERROR,
                parameters = params,
                error      = f"{type(exc).__name__}: {exc}",
                mono_time  = time.monotonic() - t0,
                call_id    = call_id,
            ))
            raise

    CrewBaseTool._run       = patched_run
    CrewBaseTool._cir_patched = True
    return True


# ---------------------------------------------------------------------------
# Convenience: patch both at once
# ---------------------------------------------------------------------------

def patch_all() -> dict[str, bool]:
    return {
        "langchain": patch_langchain(),
        "crewai":    patch_crewai(),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise_tool_input(tool_input: Any) -> dict[str, Any]:
    if isinstance(tool_input, dict):
        return tool_input
    return {"input": tool_input}


def _extract_params(func: Callable, args: tuple, kwargs: dict) -> dict[str, Any]:
    import inspect
    try:
        sig    = inspect.signature(func)
        bound  = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except Exception:
        return {"args": list(args), **kwargs}
