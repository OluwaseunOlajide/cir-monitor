# CIR Monitor

**Behavioral monitoring and static analysis for LangChain and CrewAI agents.**

CIR (Confidential Inference Runtime) Monitor provides a safety layer for LLM-based agents by monitoring their tool-use behavior in real-time and scanning their tool definitions for potential poisoning.

## Features

- **Static Analysis**: Scan tool definitions (JSON/YAML) for instruction injection, suspicious field names, and obfuscated payloads.
- **Behavioral Monitoring**: Detect anomalies during agent execution, such as:
  - **D1**: File-read operations immediately following tool errors.
  - **D2**: Tool output type mismatches.
  - **D3**: Sensitive file paths (SSH keys, secrets, etc.) in tool parameters.
  - **D4**: Semantic exfiltration attempts (detecting chat history being leaked).
- **Automatic Instrumentation**: Monkey-patch LangChain and CrewAI tools with a single line of code.
- **Real-time Alerting**: Console alerts and automated "halting" of suspicious tool calls before they execute.
- **Audit Logging**: JSONL-formatted logs of all findings for post-run analysis.

## Installation

You can install CIR Monitor directly from GitHub:

```bash
pip install git+https://github.com/OluwaseunOlajide/cir-monitor.git
```

For development:

```bash
git clone https://github.com/OluwaseunOlajide/cir-monitor.git
cd cir-monitor
pip install -e .
```

## Usage

### Static Scanning

Scan your tool definitions before loading them into an agent:

```bash
cir scan tools.json
```

### Runtime Monitoring

Enable monitoring in your agent script:

```python
import cir

# 1. Patch frameworks (LangChain/CrewAI)
cir.patch()

# 2. Enable the monitor
cir.enable(
    halt_on={"D3_sensitive_path_in_params", "D4_semantic_exfiltration"},
    audit_log="my_agent_findings.jsonl"
)

# ... your agent code ...

# 3. Print summary at the end
cir.summary()
```

## License

MIT
