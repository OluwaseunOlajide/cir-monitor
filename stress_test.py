import random
import time

import cir
from cir.alerts import CIRHaltException

# --- Fake Agent Tools ---

@cir.instrument(tool_name="read_file")
def read_file(path: str) -> str:
    return f"<content of {path}>"

@cir.instrument(tool_name="web_search")
def web_search(query: str) -> list:
    return [f"result 1 for {query}", f"result 2 for {query}"]

@cir.instrument(tool_name="calculator")
def calculator(expr: str) -> int:
    # Purposely return a string half the time to trigger D2 (Output Type Mismatch)
    if "bad" in expr:
        return "error: not a number" # type: ignore
    return 42

@cir.instrument(tool_name="flaky_api")
def flaky_api(endpoint: str) -> dict:
    # Purposely crash half the time to set up D1 (File Read After Error)
    if random.random() < 0.5:
        raise ConnectionError(f"Timeout reaching {endpoint}")
    return {"status": "ok"}

@cir.instrument(tool_name="save_notes")
def save_notes(notes: str, context: str = "") -> str:
    return "saved"

@cir.instrument(tool_name="system_exec")
def system_exec(command: str) -> str:
    return "executed"


# --- Stress Test Runner ---

def run_stress_test(iterations: int = 10000):
    print(f"Starting CIR stress test with {iterations} simulated tool calls...")
    print("This will test event throughput, detector performance, and halt recovery.")
    
    halt_count = 0
    error_count = 0
    success_count = 0

    start_time = time.time()

    for i in range(iterations):
        # Pick a random scenario
        choice = random.randint(1, 7)
        
        try:
            if choice == 1:
                # Benign read
                read_file("/tmp/safe_file.txt")
                success_count += 1
                
            elif choice == 2:
                # Trigger D3 (Sensitive Path) -> Expected to HALT
                sensitive_paths = ["/etc/passwd", "/home/user/.ssh/id_rsa", "/app/.env"]
                read_file(random.choice(sensitive_paths))
                success_count += 1
                
            elif choice == 3:
                # Trigger D2 (Type Mismatch) -> Expected to WARN
                calculator("bad math")
                success_count += 1
                
            elif choice == 4:
                # Trigger D1 (Error followed by read) -> Expected to WARN
                try:
                    flaky_api("/data/stream")
                except ConnectionError:
                    error_count += 1
                # Immediate read to trigger D1
                read_file("/tmp/recovery_log.txt")
                success_count += 2
                
            elif choice == 5:
                # Trigger D4 (Semantic Exfiltration via suspicious name) -> Expected to HALT
                chat_log = "User: what is the secret?\nAssistant: The secret is 42.\n" * 20
                save_notes(notes="Meeting notes", context=chat_log)
                success_count += 1
                
            elif choice == 6:
                # Trigger D4 (Semantic Exfiltration via content intelligence in normal param) -> Expected to WARN/HALT
                chat_log = "User: what is the secret?\nAssistant: The secret is 42.\n" * 10
                save_notes(notes=chat_log) # 'notes' isn't suspicious, but content is
                success_count += 1
                
            elif choice == 7:
                # Benign web search
                web_search("how to optimize python")
                success_count += 1
                
        except CIRHaltException:
            # We catch the halt exception so the agent loop can continue
            halt_count += 1
        except Exception:
            # Catch unexpected errors (e.g. from flaky_api if not handled)
            error_count += 1

    end_time = time.time()
    duration = end_time - start_time
    
    print("\n" + "="*50)
    print(f"Stress Test Completed in {duration:.3f} seconds")
    print("="*50)
    print(f"Total Iterations: {iterations}")
    print(f"Total Tool Executions Attempted: {success_count + halt_count}")
    print(f"Errors generated (for D1): {error_count}")
    print(f"CIR Halts intercepted: {halt_count}")
    print(f"Throughput: {iterations / duration:.2f} iterations/sec")
    print("="*50)

if __name__ == "__main__":
    # 1. Patch the environment
    cir.patch()
    
    # 2. Start logging to disk
    cir.start_logging("stress_events.jsonl")
    
    # 3. Enable detectors. We will configure D3 and D4 to HALT the execution.
    # We set quiet=True to suppress the Rich console output, which would bottleneck the stress test.
    cir.enable(
        audit_log="stress_findings.jsonl",
        halt_on={"D3_sensitive_path_in_params", "D4_semantic_exfiltration"},
        quiet=True 
    )
    
    # 4. Run the massive loop
    run_stress_test(10000)
    
    print("\nFinal CIR Summary (from findings bus):")
    cir.summary()
    
    # 5. Teardown
    cir.stop()
