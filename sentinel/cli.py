"""Sentinel CLI."""
from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from .agent import ask, generate_remediation, summarize
from .finding import ScanResult, Severity
from .llm import LLMError, get_client, require_client
from .parsers import parse
from .report import render_detail, render_human, render_json
from .rules import run
from .topology import Flow, build_graph, reachability

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Sentinel — network config security auditor.",
)
console = Console()


def _load(config: Path):
    device = parse(config.read_text())
    return device, run(device)


def _need_client():
    try:
        return require_client()
    except LLMError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2)


@app.command()
def scan(
    config: Path = typer.Argument(..., exists=True, dir_okay=False,
                                  help="Device config file to audit."),
    fix: bool = typer.Option(False, "--fix", "-f",
                             help="Emit a config-mode remediation script."),
    detail: bool = typer.Option(False, "--detail", "-v",
                                help="Show full evidence + descriptions per finding."),
    summary_flag: bool = typer.Option(False, "--summary",
                            help="Summarize findings in plain language (needs an LLM endpoint)."),
    json_out: bool = typer.Option(False, "--json",
                                  help="Machine-readable JSON output (for CI)."),
) -> None:
    """Audit a network device configuration for security flaws."""
    device, findings = _load(config)
    result = ScanResult(device=device, findings=findings)

    if json_out:
        typer.echo(render_json(result))
    else:
        render_human(result, console, show_fix=fix)
        if detail:
            console.print()
            render_detail(result, console)
        if summary_flag:
            _summarize(device, findings)

    # CI-friendly: non-zero exit when critical/high issues are present.
    if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings):
        raise typer.Exit(code=1)


@app.command("ask")
def ask_cmd(
    config: Path = typer.Argument(..., exists=True, dir_okay=False,
                                  help="Device config file to query."),
    question: str = typer.Argument(..., help="Natural-language question."),
) -> None:
    """Ask a question about a device's security posture."""
    device, findings = _load(config)
    client = _need_client()
    answer = ask(device, findings, question, client)
    console.print(Panel(answer, title=f"[bold]Q:[/bold] {question}",
                        border_style="magenta", subtitle=device.hostname))


@app.command("remediate")
def remediate_cmd(
    config: Path = typer.Argument(..., exists=True, dir_okay=False,
                                  help="Device config file to change."),
    instruction: str = typer.Argument(..., help="Natural-language change request."),
) -> None:
    """Describe a change in plain language; get IOS config to review."""
    device, _ = _load(config)
    client = _need_client()
    delta, issues = generate_remediation(device, instruction, client)
    border = "red" if issues else "green"
    console.print(Panel(delta, title="[bold]Proposed config delta[/bold]",
                        border_style=border, subtitle="review before applying"))
    if issues:
        console.print("[yellow]⚠ Lint warning — these lines don't look like "
                      "valid IOS config (non-config text in output):[/yellow]")
        for n, line in issues:
            console.print(f"  [red]line {n}:[/red] {line}")


@app.command("topo")
def topo_cmd(
    configs: list[Path] = typer.Argument(..., exists=True, dir_okay=False,
                                         help="Two or more device config files."),
) -> None:
    """Infer and show the multi-device L3 topology (shared-subnet adjacencies)."""
    if len(configs) < 2:
        console.print("[yellow]Give 2+ configs to infer a topology.[/yellow]")
        raise typer.Exit(code=2)
    devices = [parse(c.read_text()) for c in configs]
    g = build_graph(devices)
    console.print(f"[bold]Topology[/bold] — {len(g.devices)} device(s), "
                  f"{len(g.segments)} segment(s)")
    console.print("\n[bold]Segments (shared subnets = inferred links):[/bold]")
    for seg in g.segments:
        members = ", ".join(f"{h}:{i}" for h, i in seg.members)
        link = " [green]<-link->[/green]" if len(seg.members) > 1 else ""
        console.print(f"  {seg.network}  [{members}]{link}")
    console.print("\n[bold]Adjacency:[/bold]")
    for dev in sorted(g.adj):
        nbs = sorted(g.adj[dev])
        console.print(f"  {dev} -> {', '.join(nbs) if nbs else '[isolated]'}")


@app.command("reach")
def reach_cmd(
    src: str = typer.Option(..., "--src", help="Source IP."),
    dst: str = typer.Option(..., "--dst", help="Destination IP."),
    proto: str = typer.Option("tcp", "--proto", help="Protocol (tcp/udp/ip/icmp)."),
    port: int = typer.Option(..., "--port", help="Destination port."),
    configs: list[Path] = typer.Argument(..., exists=True, dir_okay=False,
                                         help="Device config files composing the network."),
) -> None:
    """Answer: can src reach dst on proto/port, with a cited deciding rule?"""
    devices = [parse(c.read_text()) for c in configs]
    g = build_graph(devices)
    flow = Flow(src=src, dst=dst, proto=proto, port=port)
    r = reachability(g, flow)
    color = "green" if r.reachable else "red"
    verb = "PERMITTED" if r.reachable else "DENIED"
    console.print(Panel(
        f"[bold {color}]{verb}[/bold {color}]  "
        f"{src} -> {dst} ({proto}/{port})\n\n{r.detail}\n"
        + (_fmt_path(r.path) if r.path else ""),
        border_style=color,
    ))


def _fmt_path(hops) -> str:
    lines = ["\n[dim]Path:[/dim]"]
    for h in hops:
        acl = f"  acl:[{h.acl}]" if h.acl else "  [dim](no inbound ACL)[/dim]"
        lines.append(f"  {h.device} {h.interface}{acl}")
    return "\n".join(lines)

@app.command()
def rules() -> None:
    """List the detection rules registered for each known OS."""
    from .rules import registered
    for os_name in ("ios", "panos"):
        rule_fns = registered(os_name)
        console.print(f"[bold]{os_name}[/bold] — {len(rule_fns)} rule(s):")
        for fn in rule_fns:
            console.print(f"  • {fn.__name__}")

@app.command("web")
def web_cmd(
    port: int = typer.Option(8000, "--port", "-p", help="Port to serve on."),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address."),
) -> None:
    """Launch the web dashboard (needs the 'web' extra)."""
    try:
        from .web import serve as serve_web
    except ImportError:
        console.print("[red]Web UI needs the 'web' extra. Install with:[/red]")
        console.print("  [cyan]uv sync --extra web[/cyan]   (or: pip install -e .[web])")
        raise typer.Exit(code=2)
    console.print(f"[bold green]Sentinel dashboard:[/bold green] "
                  f"http://{host}:{port}  (Ctrl-C to stop)")
    serve_web(host=host, port=port)


def _summarize(device, findings) -> None:
    client = get_client()
    if client is None:
        console.print("\n[dim]--summary requested but no LLM endpoint configured "
                      "(SENTINEL_LLM_API_KEY); skipping summary.[/dim]")
        return
    console.print()
    try:
        summary = summarize(device, findings, client)
        console.print(Panel(summary, title="[bold]Summary[/bold]",
                            border_style="magenta"))
    except LLMError as exc:
        console.print(f"[red]Summary failed: {exc}[/red]")


if __name__ == "__main__":
    app()
