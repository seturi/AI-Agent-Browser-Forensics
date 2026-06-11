"""Console + JSON rendering for the parsing module."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .. import __version__
from ..reporting import write_json
from .records import ParseResult

__all__ = ["build_parse_report", "render_parse", "write_json"]

_CATS = ("Account", "Prompt", "Workflow", "Output", "Authentication")


def build_parse_report(results: list[ParseResult], *, target: str | None) -> dict[str, Any]:
    return {
        "tool": "aabf",
        "version": __version__,
        "module": "parsing",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target or "<live system>",
        "results": [r.to_dict() for r in results],
    }


def render_parse(results: list[ParseResult], *, console: Console | None = None,
                 verbose: bool = False) -> None:
    console = console or Console()
    console.print(Panel(Text("AABF · Parsing — structured agent records",
                             style="bold white"), border_style="blue"))

    if not results:
        console.print("[yellow]No records parsed.[/yellow]")
        return

    table = Table(title="Parsed records (by browser)", title_style="bold", expand=True)
    table.add_column("Browser", style="bold")
    table.add_column("User")
    for c in _CATS:
        table.add_column(c, justify="right")
    table.add_column("Total", justify="right")
    table.add_column("Err", justify="right")

    for r in results:
        counts = Counter(rec.category for rec in r.records)
        table.add_row(
            r.browser_key, r.user,
            *[str(counts.get(c, 0) or "·") for c in _CATS],
            str(len(r.records)),
            f"[red]{len(r.errors)}[/red]" if r.errors else "0")
    console.print(table)

    for r in results:
        if r.errors:
            for e in r.errors:
                console.print(f"  [red]error[/red] {r.browser_key}: {e}")

    if verbose:
        for r in results:
            console.print(f"\n[bold]{r.browser_key} / {r.user}[/bold]")
            for rec in r.records:
                content = (rec.content or "").replace("\n", " ")[:80]
                conv = (str(rec.conversation_id)[:10] + "…") if rec.conversation_id else "-"
                console.print(
                    f"  [cyan]{rec.category:14}[/cyan] {conv:12} "
                    f"[dim]{rec.role or '':9}[/dim] {content}")
