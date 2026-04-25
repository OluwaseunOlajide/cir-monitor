"""
cir.cli — CLI entry point for the cir scan command.

Usage:
  cir scan <file>
  cir scan <file> --min-severity WARN
  cir scan <file> --output report.json
  cir scan <file> --quiet
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from rich.console import Console
from rich.panel   import Panel
from rich.table   import Table
from rich.text    import Text
from rich         import box

from .scanner import SchemaScanner, ScanReport, ScanSeverity, load_tool_definitions

console = Console(highlight=False)

_SEVERITY_STYLE = {
    ScanSeverity.INFO:     ("bright_blue", "INFO"),
    ScanSeverity.WARN:     ("yellow",      "WARN"),
    ScanSeverity.CRITICAL: ("bold red",    "CRIT"),
}


def render_report(report: ScanReport, min_severity: ScanSeverity) -> None:
    visible = [f for f in report.findings if f.severity >= min_severity]

    console.print()
    console.print(Panel(
        f"[bold]CIR Static Scan[/bold]  —  {report.source_file}\n"
        f"Tools scanned : [bold]{report.tools_scanned}[/bold]\n"
        f"Findings      : "
        f"[bold red]{len(report.critical)} CRITICAL[/bold red]  "
        f"[yellow]{len(report.warnings)} WARN[/yellow]  "
        f"[bright_blue]{len(report.info)} INFO[/bright_blue]",
        border_style="bold white",
        expand=False,
    ))

    if not visible:
        console.print(f"\n[bold green]✓  No findings at or above {min_severity.value} severity.[/bold green]\n")
        return

    table = Table(box=box.ROUNDED, show_lines=True, header_style="bold", expand=False)
    table.add_column("SEV",      width=6,  no_wrap=True)
    table.add_column("RULE",     width=8,  no_wrap=True)
    table.add_column("TOOL",     width=20, no_wrap=True)
    table.add_column("FIELD",    width=28, no_wrap=False)
    table.add_column("MESSAGE",  width=38, no_wrap=False)
    table.add_column("EVIDENCE", width=48, no_wrap=False)

    for f in visible:
        style, label = _SEVERITY_STYLE[f.severity]
        table.add_row(
            Text(label, style=style), f.rule, f.tool_name,
            f.field, f.message, Text(f.evidence, style="dim"),
        )

    console.print(table)
    console.print()


def write_json_report(report: ScanReport, output_path: Path,
                      min_severity: ScanSeverity = ScanSeverity.INFO) -> None:
    visible = [f for f in report.findings if f.severity >= min_severity]
    data = {
        "source_file":   report.source_file,
        "tools_scanned": report.tools_scanned,
        "summary": {
            "critical": len([f for f in visible if f.severity == ScanSeverity.CRITICAL]),
            "warn":     len([f for f in visible if f.severity == ScanSeverity.WARN]),
            "info":     len([f for f in visible if f.severity == ScanSeverity.INFO]),
            "total":    len(visible),
        },
        "findings": [
            {
                "severity":  f.severity.value,
                "rule":      f.rule,
                "tool_name": f.tool_name,
                "field":     f.field,
                "message":   f.message,
                "evidence":  f.evidence,
            }
            for f in visible
        ],
    }
    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    console.print(f"[dim]JSON report written to {output_path}[/dim]")


def cmd_scan(args: list[str]) -> int:
    if not args:
        console.print("[red]Usage: cir scan <tool-definition-file>[/red]")
        return 2

    path_str    = None
    min_sev     = ScanSeverity.INFO
    output_path = None
    quiet       = False

    it = iter(args)
    for tok in it:
        if tok in ("--min-severity", "-s"):
            val = next(it, None)
            if val not in ScanSeverity._value2member_map_:
                console.print(f"[red]Invalid severity '{val}'. Use INFO, WARN, or CRITICAL.[/red]")
                return 2
            min_sev = ScanSeverity(val)
        elif tok in ("--output", "-o"):
            output_path = Path(next(it, "report.json"))
        elif tok == "--quiet":
            quiet = True
        elif not tok.startswith("-"):
            path_str = tok

    if not path_str:
        console.print("[red]No input file specified.[/red]")
        return 2

    input_path = Path(path_str)
    if not input_path.exists():
        console.print(f"[red]File not found: {input_path}[/red]")
        return 2

    try:
        tools = load_tool_definitions(input_path)
    except Exception as exc:
        console.print(f"[red]Failed to load {input_path}: {exc}[/red]")
        return 2

    report = SchemaScanner().scan_tools(tools, source=str(input_path))

    if not quiet:
        render_report(report, min_severity=min_sev)

    if output_path:
        write_json_report(report, output_path, min_severity=min_sev)

    return 1 if report.findings else 0


def main() -> None:
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        console.print(
            "\n[bold]cir[/bold] — Confidential Inference Runtime monitor\n\n"
            "Commands:\n"
            "  [bold]cir scan[/bold] <file>                    Scan tool definitions\n"
            "    --min-severity INFO|WARN|CRITICAL  Filter output (default: INFO)\n"
            "    --output <report.json>             Write JSON report to file\n"
            "    --quiet                            Suppress output, exit code only\n"
        )
        sys.exit(0)

    command, rest = args[0], args[1:]

    if command == "scan":
        sys.exit(cmd_scan(rest))
    else:
        console.print(f"[red]Unknown command: {command}[/red]")
        sys.exit(2)
