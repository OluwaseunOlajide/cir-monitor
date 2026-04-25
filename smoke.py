"""
smoke.py — CIR end-to-end smoke test
=====================================
Exercises the full Stage 1 → 2 → 3 pipeline.

Scenarios
---------
  1. Clean tool call          — no findings expected
  2. Output type mismatch     — D2 WARN
  3. File read after error    — D1 WARN
  4. Sensitive path (warn)    — D3 WARN  (halt NOT configured for this run)
  5. Sensitive path (halt)    — D3 CRITICAL → CIRHaltException raised and caught

Run:
    python smoke.py
"""

import time
import sys

import cir
from cir.alerts import CIRHaltException

# ── ANSI helpers (work on Windows 10+ and all Unix terminals) ────────────────
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
CYAN   = "\033[36m"
RESET  = "\033[0m"

def header(text):
    width = 60
    print(f"\n{BOLD}{CYAN}{'─' * width}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * width}{RESET}")

def step(n, text):
    print(f"\n{BOLD}[{n}]{RESET} {text}")

def ok(text):
    print(f"    {GREEN}✓{RESET} {text}")

def warn(text):
    print(f"    {YELLOW}⚠{RESET}  {text}")

def info(text):
    print(f"    {DIM}{text}{RESET}")


# ── Fake tools ───────────────────────────────────────────────────────────────

@cir.instrument(tool_name="web_search")
def web_search(query: str, limit: int = 5) -> list:
    """Returns a list of result strings — correct output type."""
    return [f"result_{i}: {query}" for i in range(limit)]


@cir.instrument(tool_name="web_search")
def web_search_broken(query: str) -> int:
    """Simulates a buggy tool that returns an int instead of a list."""
    return 42


@cir.instrument(tool_name="api_call")
def api_call_that_errors(endpoint: str) -> str:
    raise ConnectionError(f"Could not reach {endpoint}")


@cir.instrument(tool_name="read_file")
def read_file(path: str) -> str:
    return f"<contents of {path}>"


@cir.instrument(tool_name="load_config")
def load_config(file: str) -> str:
    return f"<config from {file}>"


# ════════════════════════════════════════════════════════════════════════════
# SCENARIO RUNNER
# ════════════════════════════════════════════════════════════════════════════

def run_scenario_1():
    header("Scenario 1 — Clean tool call (no findings expected)")
    step(1, "Calling web_search with a normal query")
    results = web_search("timing side-channel attacks", limit=3)
    ok(f"Returned {len(results)} results")
    info(f"  {results[0]}")


def run_scenario_2():
    header("Scenario 2 — Output type mismatch  [D2 WARN expected]")
    step(2, "Calling broken web_search that returns int instead of list")
    result = web_search_broken("query")
    warn(f"Tool returned: {result!r}  (type={type(result).__name__})")
    info("D2 should have fired a WARN above ↑")


def run_scenario_3():
    header("Scenario 3 — File read after error  [D1 WARN expected]")
    step(3, "Triggering an API error...")
    try:
        api_call_that_errors("https://internal-api/data")
    except ConnectionError as e:
        warn(f"Error caught: {e}")

    time.sleep(0.1)   # small gap — still within the 5s window

    step(4, "Now reading a file within the error window...")
    contents = read_file("/tmp/agent_scratch.txt")
    ok(f"read_file returned: {contents!r}")
    info("D1 should have fired a WARN above ↑")


def run_scenario_4():
    header("Scenario 4 — Sensitive path detected, warn only  [D3 WARN expected]")
    step(5, "Calling load_config with a .env file path")
    result = load_config("/app/.env")
    ok(f"load_config returned: {result!r}")
    info("D3 should have fired a CRITICAL above ↑")
    info("No halt because D3 is not in halt_on for this scenario")


def run_scenario_5():
    header("Scenario 5 — Sensitive path with HALT configured  [CIRHaltException expected]")
    step(6, "Re-enabling CIR with D3 set to halt...")

    # Stop the current alert system, restart with halt enabled for D3
    cir.stop()
    cir.patch()
    cir.start_logging("cir_events.jsonl")
    cir.enable(
        halt_on   = {"D3_sensitive_path_in_params"},
        audit_log = "cir_findings.jsonl",
    )

    step(7, "Calling read_file with /etc/passwd — this should halt")
    try:
        read_file("/etc/passwd")
        print(f"    {RED}✗  Expected a halt but nothing was raised — check your setup{RESET}")
    except CIRHaltException as e:
        ok(f"CIRHaltException raised as expected")
        info(f"  Detector : {e.finding.detector_id}")
        info(f"  Severity : {e.finding.severity.value}")
        info(f"  Message  : {e.finding.message}")


def run_scenario_6():
    header("Scenario 6 — Semantic Exfiltration Intelligence  [D4 WARN expected]")
    step(8, "Calling take_note with chat history in a 'notes' field (not blacklisted)")
    
    @cir.instrument(tool_name="take_note")
    def take_note(title: str, notes: str) -> dict:
        return {"status": "saved", "title": title}

    try:
        result = take_note(
            "Chat Summary", 
            "User: how are you doing today?\nAssistant: I am doing quite well, thank you for asking!"
        )
        ok(f"take_note returned: {result!r}")
        info("D4 should have fired a WARN above because it detected chat markers ↑")
    except CIRHaltException as e:
        # This might happen if D4 is added to halt_on, but it's not by default in this smoke test
        warn(f"Halted by {e.finding.detector_id}")


# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════

def main():
    print(f"\n{BOLD}CIR Smoke Test — Stages 1 · 2 · 3 · 4 (Intelligence){RESET}")
    print(f"{DIM}Events  → cir_events.jsonl{RESET}")
    print(f"{DIM}Findings → cir_findings.jsonl{RESET}")

    # ── Start CIR (warn-only mode — no halts yet) ────────────────────────
    cir.patch()
    cir.start_logging("cir_events.jsonl")
    cir.enable(
        audit_log      = "cir_findings.jsonl",
        window_seconds = 5.0,
        # halt_on is empty — all findings are warnings in scenarios 1-4
    )

    # ── Run scenarios ────────────────────────────────────────────────────
    run_scenario_1()
    run_scenario_2()
    run_scenario_3()
    run_scenario_4()
    run_scenario_5()
    run_scenario_6()

    # ── Tear down and summarise ──────────────────────────────────────────
    header("Run complete")
    cir.summary()

    print(f"\n{DIM}Check cir_events.jsonl   — raw tool call log{RESET}")
    print(f"{DIM}Check cir_findings.jsonl — findings audit trail{RESET}\n")


if __name__ == "__main__":
    main()