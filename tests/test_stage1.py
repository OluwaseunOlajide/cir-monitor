"""
tests/test_stage1.py
Tests for the instrumentation layer.
"""

import asyncio
import json
import time
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from cir.bus           import EventBus
from cir.instrumentation import instrument
from cir.logger        import EventLogger
from cir.models        import EventKind, ToolEvent


# ---------------------------------------------------------------------------
# EventBus
# ---------------------------------------------------------------------------

class TestEventBus:
    def test_publish_and_receive(self):
        eb     = EventBus()
        received = []
        eb.subscribe(received.append)

        event = ToolEvent(tool_name="search", kind=EventKind.CALL_START, parameters={})
        eb.publish(event)

        assert len(received) == 1
        assert received[0] is event

    def test_history_is_bounded(self):
        eb = EventBus(history_size=3)
        for i in range(5):
            eb.publish(ToolEvent(tool_name=f"t{i}", kind=EventKind.CALL_END, parameters={}))

        assert len(eb.recent()) == 3
        assert eb.recent()[0].tool_name == "t2"
        assert eb.recent()[-1].tool_name == "t4"

    def test_unsubscribe(self):
        eb       = EventBus()
        received = []
        eb.subscribe(received.append)
        eb.unsubscribe(received.append)

        eb.publish(ToolEvent(tool_name="x", kind=EventKind.CALL_START, parameters={}))
        assert received == []

    def test_bad_subscriber_doesnt_crash_publisher(self):
        eb = EventBus()
        def bad(_): raise RuntimeError("boom")
        eb.subscribe(bad)

        # Should not raise
        eb.publish(ToolEvent(tool_name="x", kind=EventKind.CALL_END, parameters={}))


# ---------------------------------------------------------------------------
# @instrument decorator — sync
# ---------------------------------------------------------------------------

class TestInstrumentSync:
    def test_call_start_and_end_published(self):
        eb       = EventBus()
        received = []
        eb.subscribe(received.append)

        # Temporarily swap the global bus
        import cir.instrumentation as instr_mod
        original_bus = instr_mod.bus
        instr_mod.bus = eb

        @instrument
        def add(a, b):
            return a + b

        result = add(2, 3)

        instr_mod.bus = original_bus   # restore

        assert result == 5
        kinds = [e.kind for e in received]
        assert EventKind.CALL_START in kinds
        assert EventKind.CALL_END   in kinds

    def test_error_event_on_exception(self):
        eb       = EventBus()
        received = []
        eb.subscribe(received.append)

        import cir.instrumentation as instr_mod
        original_bus = instr_mod.bus
        instr_mod.bus = eb

        @instrument
        def boom():
            raise ValueError("test error")

        with pytest.raises(ValueError):
            boom()

        instr_mod.bus = original_bus

        error_events = [e for e in received if e.kind == EventKind.CALL_ERROR]
        assert len(error_events) == 1
        assert "ValueError" in error_events[0].error

    def test_parameters_captured(self):
        eb       = EventBus()
        received = []
        eb.subscribe(received.append)

        import cir.instrumentation as instr_mod
        original_bus = instr_mod.bus
        instr_mod.bus = eb

        @instrument(tool_name="my_search")
        def search(query, limit=10):
            return []

        search("python", limit=5)

        instr_mod.bus = original_bus

        start = next(e for e in received if e.kind == EventKind.CALL_START)
        assert start.tool_name    == "my_search"
        assert start.parameters["query"] == "python"
        assert start.parameters["limit"] == 5


# ---------------------------------------------------------------------------
# @instrument decorator — async
# ---------------------------------------------------------------------------

class TestInstrumentAsync:
    async def test_async_call_produces_events(self):
        eb       = EventBus()
        received = []
        eb.subscribe(received.append)

        import cir.instrumentation as instr_mod
        original_bus = instr_mod.bus
        instr_mod.bus = eb

        @instrument
        async def fetch(url):
            await asyncio.sleep(0)
            return {"status": 200}

        result = await fetch("https://example.com")

        instr_mod.bus = original_bus

        assert result == {"status": 200}
        kinds = [e.kind for e in received]
        assert EventKind.CALL_START in kinds
        assert EventKind.CALL_END   in kinds


# ---------------------------------------------------------------------------
# EventLogger
# ---------------------------------------------------------------------------

class TestEventLogger:
    def test_writes_jsonl(self, tmp_path):
        log_file = tmp_path / "events.jsonl"
        eb       = EventBus()

        logger = EventLogger(log_file)
        # Inject test bus
        import cir.logger as logger_mod
        original_bus = logger_mod.bus
        logger_mod.bus = eb
        logger.start()

        eb.publish(ToolEvent(
            tool_name  = "read_file",
            kind       = EventKind.CALL_END,
            parameters = {"path": "/tmp/x.txt"},
            output     = "hello",
        ))

        logger.stop()
        logger_mod.bus = original_bus

        lines = log_file.read_text().strip().splitlines()
        assert len(lines) == 1

        record = json.loads(lines[0])
        assert record["tool_name"] == "read_file"
        assert record["kind"]      == "call_end"
        assert record["output"]    == "hello"

    def test_context_manager(self, tmp_path):
        log_file = tmp_path / "ctx.jsonl"
        import cir.logger as logger_mod
        eb = EventBus()
        original_bus = logger_mod.bus
        logger_mod.bus = eb

        with EventLogger(log_file):
            eb.publish(ToolEvent(tool_name="x", kind=EventKind.CALL_START, parameters={}))

        logger_mod.bus = original_bus

        lines = log_file.read_text().strip().splitlines()
        assert len(lines) == 1
