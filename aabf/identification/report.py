"""Console + JSON rendering for the identification module.

The JSON structure (``build_report``) is the hand-off contract for the
collection/parsing/analysis modules — keep it stable.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .. import __version__
from ..models import Detection
from ..reporting import TYPE_STYLE, write_json

__all__ = ["build_report", "render_console", "write_json"]


def build_report(detections: list[Detection], *, target: str | None) -> dict[str, Any]:
    """Assemble the machine-readable report dict."""
    return {
        "tool": "aabf",
        "version": __version__,
        "module": "identification",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target or "<live system>",
        "detections_count": len(detections),
        "detections": [d.to_dict() for d in detections],
    }


def render_console(
    detections: list[Detection], *, target: str | None,
    console: Console | None = None, verbose: bool = False,
) -> None:
    console = console or Console()

    if not detections:
        console.print(
            "[yellow]No AI agent browsers identified.[/yellow] "
            "Check the target path or try --min-confidence 0."
        )
        return

    console.print(f"[bold]{len(detections)}[/bold] AI agent browser(s) identified  "
                  f"[dim]· {target or '<live system>'}[/dim]\n")
    _render_summary_table(detections, console)

    if verbose:
        console.print()
        for det in detections:
            _render_detection(det, console, verbose=verbose)
    else:
        console.print("\n[dim]Run with -v for markers, resolved paths and "
                      "per-artifact detail.[/dim]")


def _render_summary_table(detections: list[Detection], console: Console) -> None:
    table = Table(box=box.SIMPLE_HEAD, pad_edge=False)
    table.add_column("Browser", style="bold")
    table.add_column("Type")
    table.add_column("Conf.", justify="right")
    table.add_column("User")
    table.add_column("Profiles")
    table.add_column("Collection route")

    for d in detections:
        st = d.signature.service_type.value
        table.add_row(
            d.signature.name,
            Text(st, style=TYPE_STYLE.get(st, "white")),
            _conf_text(d.confidence),
            d.profile_user,
            ", ".join(d.profiles) or "[dim]none[/dim]",
            d.recommended_route,
        )
    console.print(table)


def _conf_text(conf: float) -> Text:
    style = "green" if conf >= 0.75 else "yellow" if conf >= 0.5 else "red"
    return Text(f"{conf:.0%}", style=style)


def _render_detection(det: Detection, console: Console, *, verbose: bool) -> None:
    sig = det.signature
    title = Text.assemble(
        (f"{sig.name} ", "bold"),
        (f"[{sig.service_type.value}]", TYPE_STYLE.get(sig.service_type.value, "white")),
    )

    lines = Text()
    lines.append(f"Developer   : {sig.developer}  ({sig.base_arch})\n", style="dim")
    lines.append(f"UserData    : {det.user_data_path or 'n/a'}\n")
    if sig.extension_id:
        lines.append(f"Extension   : {sig.extension_id}\n")
    lines.append(f"Route       : {det.recommended_route}\n", style="bold")
    lines.append(f"Auth        : {sig.auth_summary}\n", style="dim")

    console.print(Panel(lines, title=title, border_style="blue", title_align="left"))

    # Markers
    mtable = Table(show_header=True, header_style="dim", box=None, padding=(0, 2, 0, 0))
    mtable.add_column("")
    mtable.add_column("marker")
    mtable.add_column("path", overflow="fold")
    for m in det.marker_hits:
        mark = "[green]✓[/green]" if m.exists else "[red]✗[/red]"
        if m.exists or verbose:
            mtable.add_row(mark, m.marker.description, m.resolved_path)
    console.print("  [bold]Identification markers[/bold]")
    console.print(mtable)

    # Artifacts grouped by category
    present = [a for a in det.artifact_hits if a.exists]
    shown = det.artifact_hits if verbose else present
    if shown:
        atable = Table(show_header=True, header_style="dim", box=None,
                       padding=(0, 2, 0, 0), expand=True)
        atable.add_column("")
        atable.add_column("cat")
        atable.add_column("storage")
        atable.add_column("presence")
        atable.add_column("path/info", overflow="fold")
        for a in shown:
            mark = "[green]✓[/green]" if a.exists else "[red]·[/red]"
            cnt = f" ({a.match_count})" if a.match_count else ""
            enc = " [magenta]DPAPI[/magenta]" if a.spec.encrypted else ""
            atable.add_row(
                mark, a.spec.category.value, a.spec.storage,
                a.spec.presence.value + enc, f"{a.resolved_path}{cnt}",
            )
        console.print(f"  [bold]Agent artifacts[/bold] "
                      f"({len(present)}/{len(det.artifact_hits)} present)")
        console.print(atable)
    else:
        console.print("  [dim]No expected artifacts present on disk "
                      "(may be cloud-only or evicted).[/dim]")
    console.print()
