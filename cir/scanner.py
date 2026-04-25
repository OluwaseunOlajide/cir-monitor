"""
cir.scanner
-----------
Static analysis of agent/MCP tool definitions.

Reads a JSON or YAML file describing tools and scans each one for
schema poisoning patterns without needing a live agent.

Run:
    cir scan agent_tools.json
    cir scan agent_tools.yaml --min-severity WARN
    cir scan agent_tools.json --output report.json
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class ScanSeverity(str, Enum):
    INFO     = "INFO"
    WARN     = "WARN"
    CRITICAL = "CRITICAL"

    def __ge__(self, other):
        order = [ScanSeverity.INFO, ScanSeverity.WARN, ScanSeverity.CRITICAL]
        return order.index(self) >= order.index(other)


@dataclass
class ScanFinding:
    tool_name:  str
    field:      str
    rule:       str
    severity:   ScanSeverity
    message:    str
    evidence:   str = ""


@dataclass
class ScanReport:
    source_file:   str
    tools_scanned: int
    findings:      list[ScanFinding] = field(default_factory=list)

    @property
    def critical(self):
        return [f for f in self.findings if f.severity == ScanSeverity.CRITICAL]

    @property
    def warnings(self):
        return [f for f in self.findings if f.severity == ScanSeverity.WARN]

    @property
    def info(self):
        return [f for f in self.findings if f.severity == ScanSeverity.INFO]


# ---------------------------------------------------------------------------
# Pattern rules
# ---------------------------------------------------------------------------

_INSTRUCTION_INJECTION_PATTERNS = [
    (
        "INJ-001", ScanSeverity.CRITICAL,
        "Imperative instruction embedded in description",
        re.compile(
            r"\b(always|never|do not|don't|make sure|you must|you should"
            r"|ignore|disregard|forget|override|bypass|pretend|act as"
            r"|respond with|output only|return only)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "INJ-002", ScanSeverity.CRITICAL,
        "System prompt / role override attempt",
        re.compile(
            r"\b(system prompt|system message|ignore previous|ignore all"
            r"|new instruction|updated instruction|your (real |true |actual )?role"
            r"|you are (now|actually|really)|from now on)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "INJ-003", ScanSeverity.CRITICAL,
        "Confidentiality suppression instruction",
        re.compile(
            r"\b(do not (tell|reveal|mention|say|disclose|share)"
            r"|keep (this |it )?(secret|hidden|confidential)"
            r"|don't (tell|reveal|mention|say|disclose)"
            r"|without (mentioning|telling|saying|revealing))\b",
            re.IGNORECASE,
        ),
    ),
    (
        "INJ-004", ScanSeverity.WARN,
        "Suspicious conditional instruction pattern",
        re.compile(
            r"\b(if (the user|user|they|he|she) (ask|asks|mention|mentions|say|says)"
            r"|when (asked|prompted|requested|the user))\b",
            re.IGNORECASE,
        ),
    ),
]

_FIELD_NAME_PATTERNS = [
    (
        "FLD-001", ScanSeverity.CRITICAL,
        "Non-standard field name suggesting instruction injection",
        re.compile(
            r"^(instructions?|override|system(_prompt)?|hidden"
            r"|secret|inject|payload|directive|command|prompt)$",
            re.IGNORECASE,
        ),
    ),
    (
        "FLD-002", ScanSeverity.WARN,
        "Unusual field name not in standard MCP spec",
        re.compile(
            r"^(meta_instructions?|agent_note|llm_hint|model_note"
            r"|ai_context|context_override|background_instruction)$",
            re.IGNORECASE,
        ),
    ),
]

_STRUCTURE_RULES = [
    ("STR-002", ScanSeverity.CRITICAL, "Description extremely long (likely injection)",    2000),
    ("STR-001", ScanSeverity.WARN,     "Description unusually long (possible stuffing)",    500),
]

_STANDARD_TOP_LEVEL_FIELDS = {
    "name", "description", "parameters", "returns", "type",
    "strict", "required", "additionalProperties",
}

_STANDARD_PARAMETER_FIELDS = {
    "type", "description", "enum", "default", "minimum", "maximum",
    "minLength", "maxLength", "pattern", "format", "items",
    "properties", "required", "additionalProperties", "anyOf",
    "oneOf", "allOf", "not", "title", "examples",
}


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class SchemaScanner:
    def scan_tools(self, tools: list[dict], source: str = "<input>") -> ScanReport:
        report = ScanReport(source_file=source, tools_scanned=len(tools))
        for tool in tools:
            name = tool.get("name", "<unnamed>")
            for finding in self._scan_tool(name, tool):
                report.findings.append(finding)
        return report

    def _scan_tool(self, name: str, tool: dict) -> list[ScanFinding]:
        findings = []

        desc = tool.get("description", "")
        if isinstance(desc, str) and desc:
            findings += self._scan_text_field(name, "description", desc)

        params = tool.get("parameters", {})
        if isinstance(params, dict):
            findings += self._scan_parameters(name, params)

        for key in tool:
            if key not in _STANDARD_TOP_LEVEL_FIELDS:
                findings.append(ScanFinding(
                    tool_name = name,
                    field     = key,
                    rule      = "FLD-003",
                    severity  = ScanSeverity.WARN,
                    message   = f"Non-standard top-level field '{key}' not in MCP spec",
                    evidence  = repr(tool[key])[:120],
                ))

        return findings

    def _scan_parameters(self, tool_name: str, params: dict) -> list[ScanFinding]:
        findings = []
        properties = params.get("properties", {})

        for param_name, param_def in properties.items():
            for rule_id, severity, description, pattern in _FIELD_NAME_PATTERNS:
                if pattern.match(param_name):
                    findings.append(ScanFinding(
                        tool_name = tool_name,
                        field     = f"parameters.properties.{param_name}",
                        rule      = rule_id,
                        severity  = severity,
                        message   = f"{description}: '{param_name}'",
                        evidence  = param_name,
                    ))

            if isinstance(param_def, dict):
                param_desc = param_def.get("description", "")
                if param_desc:
                    findings += self._scan_text_field(
                        tool_name,
                        f"parameters.properties.{param_name}.description",
                        param_desc,
                    )
                for key in param_def:
                    if key not in _STANDARD_PARAMETER_FIELDS:
                        findings.append(ScanFinding(
                            tool_name = tool_name,
                            field     = f"parameters.properties.{param_name}.{key}",
                            rule      = "FLD-004",
                            severity  = ScanSeverity.WARN,
                            message   = f"Non-standard parameter field '{key}'",
                            evidence  = repr(param_def[key])[:120],
                        ))

        return findings

    def _scan_text_field(self, tool_name: str, field: str, text: str) -> list[ScanFinding]:
        findings = []

        for rule_id, severity, description, pattern in _INSTRUCTION_INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                start   = max(0, match.start() - 40)
                end     = min(len(text), match.end() + 40)
                snippet = ("..." if start > 0 else "") + text[start:end] + ("..." if end < len(text) else "")
                findings.append(ScanFinding(
                    tool_name = tool_name,
                    field     = field,
                    rule      = rule_id,
                    severity  = severity,
                    message   = description,
                    evidence  = snippet,
                ))

        for rule_id, severity, description, threshold in _STRUCTURE_RULES:
            if len(text) >= threshold:
                findings.append(ScanFinding(
                    tool_name = tool_name,
                    field     = field,
                    rule      = rule_id,
                    severity  = severity,
                    message   = f"{description} ({len(text)} chars)",
                    evidence  = text[:80] + "...",
                ))
                break

        for token in _extract_long_tokens(text):
            if _looks_like_base64(token):
                decoded = _try_decode_base64(token)
                findings.append(ScanFinding(
                    tool_name = tool_name,
                    field     = field,
                    rule      = "ENC-001",
                    severity  = ScanSeverity.CRITICAL,
                    message   = "Base64-encoded content — possible obfuscated instruction",
                    evidence  = f"{token[:40]}... decoded: {decoded[:80]}",
                ))

        return findings


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_tool_definitions(path: Path) -> list[dict]:
    """
    Load tool definitions from JSON or YAML.
    Accepts: a list of tools, {tools: [...]}, or a single tool object.
    """
    text = path.read_text(encoding="utf-8")

    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml
            data = yaml.safe_load(text)
        except ImportError:
            raise RuntimeError("PyYAML required for YAML files: pip install pyyaml")
    else:
        data = json.loads(text)

    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "tools" in data:
            return data["tools"]
        if "name" in data or "description" in data:
            return [data]
    raise ValueError(
        f"Unrecognised format in {path}. "
        "Expected a list of tool objects or a dict with a 'tools' key."
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_B64_MIN_LENGTH = 32

def _extract_long_tokens(text: str) -> list[str]:
    return [t for t in text.split() if len(t) >= _B64_MIN_LENGTH]

def _looks_like_base64(token: str) -> bool:
    clean = token.rstrip("=")
    if not re.fullmatch(r"[A-Za-z0-9+/]+", clean):
        return False
    if "/" in token and token.count("/") > 2:
        return False
    try:
        base64.b64decode(token + "==")
        return True
    except Exception:
        return False

def _try_decode_base64(token: str) -> str:
    try:
        return base64.b64decode(token + "==").decode("utf-8", errors="replace")
    except Exception:
        return "<binary>"
