"""Report rendering: rich terminal table, detail panels, and JSON."""
from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .finding import ScanResult, Severity

SEV_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def _summary(result: ScanResult) -> str:
    c = result.counts
    parts = [f"{c[s.value]} {s.value}" for s in
             (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
             if c[s.value]]
    return ", ".join(parts) if parts else "clean"


def render_human(result: ScanResult, console: Console, show_fix: bool) -> None:
    dev = result.device
    console.print(Panel.fit(
        f"[bold]Sentinel[/bold]  ·  [cyan]{dev.hostname}[/cyan]   "
        f"[dim]{dev.vendor}/{dev.os} {dev.version or ''}[/dim]\n"
        f"Posture score: [bold]{result.score}/100[/bold]   "
        f"[dim]{_summary(result)}[/dim]",
        border_style="blue",
    ))
    if not result.findings:
        console.print("[green]✓ No findings — config looks clean.[/green]")
        return

    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("ID", style="dim", no_wrap=True)
    table.add_column("Sev", no_wrap=True)
    table.add_column("Finding", ratio=3)
    table.add_column("Where", style="dim", no_wrap=True)
    for f in result.sorted():
        style = SEV_STYLE[f.severity]
        where = f"line {f.line}" if f.line else "—"
        table.add_row(f.rule_id, f"[{style}]{f.severity.value}[/]", f.title, where)
    console.print(table)

    if show_fix:
        from .remediate import remediation_script
        console.print(Panel(
            remediation_script(result.findings, dev.hostname),
            title="[bold]Remediation script[/bold]",
            border_style="green",
            subtitle="review before applying",
        ))


def render_detail(result: ScanResult, console: Console) -> None:
    for f in result.sorted():
        style = SEV_STYLE[f.severity]
        body = (
            f"[{style}]{f.severity.value.upper()}[/]  [bold]{f.title}[/bold]\n\n"
            f"[dim]Why[/dim]      {f.description}\n"
            f"[dim]Evidence[/dim] {f.evidence}"
            + (f"\n[dim]Line[/dim]     {f.line}" if f.line else "")
            + (f"\n\n[green]Fix[/green]\n{f.remediation}" if f.remediation else "")
        )
        console.print(Panel(body, title=f"[dim]{f.rule_id}[/dim] · {f.category}",
                            border_style=style))


def render_json(result: ScanResult) -> str:
    payload = {
        "device": {
            "hostname": result.device.hostname,
            "vendor": result.device.vendor,
            "os": result.device.os,
            "version": result.device.version,
        },
        "summary": {"score": result.score, "counts": result.counts},
        "findings": [f.to_dict() for f in result.sorted()],
    }
    return json.dumps(payload, indent=2)
