"""Console + manifest output for the local collection module."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..reporting import human_bytes, write_json
from .base import CollectionResult

__all__ = ["write_manifest", "write_collection_log", "render_collection"]


def write_manifest(result: CollectionResult, path: Path) -> None:
    write_json(result.to_manifest(), path)


def write_collection_log(result: CollectionResult, path: Path) -> None:
    lines: list[str] = []
    coc = result.chain_of_custody()
    lines.append("AABF local artifact collection log")
    lines.append("=" * 50)
    for k, v in coc.items():
        lines.append(f"{k:14}: {v}")
    lines.append("")
    for a in result.artifacts:
        tag = "ERROR" if a.error else "OK"
        lines.append(f"[{tag}] {a.browser} / {a.user} / {', '.join(a.categories)} "
                     f"({a.storage})")
        lines.append(f"       source: {a.source_path}")
        if a.error:
            lines.append(f"       error : {a.error}")
        for f in a.files:
            lines.append(f"       {f.sha256}  {f.size:>10}  {f.dest}")
        lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def render_collection(
    result: CollectionResult, *, console: Console | None = None, verbose: bool = False
) -> None:
    console = console or Console()
    header = Text("AABF · Local Artifact Collection", style="bold white")
    sub = Text(f"target: {result.target}\noutput: {result.output_dir}", style="dim")
    console.print(Panel(Text.assemble(header, "\n", sub), border_style="blue"))

    s = result.summary()
    if not result.artifacts:
        console.print("[yellow]Nothing collected.[/yellow] "
                      "No locally-available artifacts were found.")
    else:
        table = Table(title="Collected (by browser)", title_style="bold", expand=True)
        table.add_column("Browser", style="bold")
        table.add_column("User")
        table.add_column("Categories")
        table.add_column("Sources", justify="right")
        table.add_column("Files", justify="right")
        table.add_column("Size", justify="right")
        seen: dict[tuple, dict] = {}
        for a in result.artifacts:
            row = seen.setdefault((a.browser, a.user),
                                  {"cats": set(), "src": 0, "files": 0, "bytes": 0})
            row["cats"].update(a.categories)
            row["src"] += 1
            row["files"] += len(a.files)
            row["bytes"] += a.bytes_total
        for (browser, user), row in seen.items():
            table.add_row(browser, user, ", ".join(sorted(row["cats"])),
                          str(row["src"]), str(row["files"]),
                          human_bytes(row["bytes"]))
        console.print(table)

    console.print(
        f"[bold]Totals:[/bold] {s['sources']} sources · {s['files']} files · "
        f"{human_bytes(s['bytes'])}"
        + (f" · [red]{s['errors']} error(s)[/red]" if s["errors"] else ""))

    if verbose:
        for a in result.artifacts:
            mark = "[red]✗[/red]" if a.error else "[green]✓[/green]"
            console.print(f"  {mark} {a.browser}/{a.user} [{a.presence}] "
                          f"{', '.join(a.categories)} — {len(a.files)} file(s)")
            if a.error:
                console.print(f"      [red]{a.error}[/red]")

    if result.pending_api:
        console.print()
        ptable = Table(title="Pending API reconstruction (cloud/hybrid)",
                       title_style="bold yellow", expand=True)
        ptable.add_column("Browser", style="bold")
        ptable.add_column("Type")
        ptable.add_column("Server-side")
        ptable.add_column("Credential pivot")
        ptable.add_column("Endpoints", justify="right")
        for p in result.pending_api:
            cred = "[green]secured[/green]" if p.credential_sources else "[red]none[/red]"
            ptable.add_row(p.browser, p.service_type,
                           ", ".join(p.server_side_categories) or "—",
                           cred, str(len(p.endpoints)))
        console.print(ptable)
        console.print("[dim]API reconstruction module is not implemented yet — "
                      "these are recorded in the manifest for the next stage.[/dim]")
