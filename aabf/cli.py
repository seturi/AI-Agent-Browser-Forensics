"""AABF command-line interface.

    aabf identify [TARGET] [options]     identify & classify AI agent browsers
    aabf signatures                      list the supported browsers
    aabf version

TARGET is a mounted forensic image or an FTK-extracted folder. Omit it to scan
the live Windows system (%LocalAppData% / %AppData%).
"""

from __future__ import annotations

import json as _json
import sys
import tempfile
from pathlib import Path
from typing import Optional

# Korean/CJK Windows consoles default to a legacy codepage (cp949) that cannot
# encode the box-drawing and symbol glyphs Rich emits. Force UTF-8 so output is
# safe on any locale and when piped/redirected.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .collection.local import collect_local
from .collection.report import (
    render_collection,
    write_collection_log,
    write_manifest,
)
from .identification import DEFAULT_MIN_CONFIDENCE, identify as run_identify
from .identification.report import build_report, render_console
from .parsing import parse_collection, parse_manifest
from .parsing.report import build_parse_report, render_parse
from .analysis import analyze as run_analyze
from .analysis.report import (
    build_timeline_report,
    load_case,
    render_case,
    render_timeline,
    write_per_service,
    write_report,
)
from .output import aabf_root, new_case_dir
from .reporting import write_json
from .signatures import SIGNATURES

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="AI Agent Browser Forensics (AABF) — identification & classification.",
)
console = Console()

_BANNER = r"""
  █████╗  █████╗ ██████╗ ███████╗
 ██╔══██╗██╔══██╗██╔══██╗██╔════╝
 ███████║███████║██████╔╝█████╗
 ██╔══██║██╔══██║██╔══██╗██╔══╝
 ██║  ██║██║  ██║██████╔╝██║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝
"""


def _print_banner() -> None:
    """Print the ASCII-art banner (skipped when piped/redirected or disabled)."""
    import os
    if os.environ.get("AABF_NO_BANNER") or not console.is_terminal:
        return
    console.print(f"[bold cyan]{_BANNER}[/bold cyan]", highlight=False)
    console.print(f" [bold white]AI Agent Browser Forensics[/bold white]  "
                  f"[cyan]v{__version__}[/cyan]\n", highlight=False)


@app.callback()
def _root() -> None:
    """Shown before every command; the ASCII banner is the 'ta-da'."""
    _print_banner()


@app.command()
def identify(
    target: Optional[Path] = typer.Argument(
        None,
        metavar="[TARGET]",
        help="Image file (.raw/.001/.E01/.vmdk), mounted drive, or extracted folder. Omit for the live system.",
    ),
    json_out: Optional[Path] = typer.Option(
        None, "--json", "-j", help="Write the JSON report to this path."),
    only: Optional[str] = typer.Option(
        None, "--only", "-o",
        help="Comma-separated signature keys to scan (e.g. comet,sigma)."),
    min_confidence: float = typer.Option(
        DEFAULT_MIN_CONFIDENCE, "--min-confidence", "-c",
        min=0.0, max=1.0, help="Discard detections below this confidence."),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show absent markers/artifacts too."),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress console output (use with --json)."),
) -> None:
    """Identify and classify AI agent browsers in TARGET (or the live system)."""
    only_keys = [k.strip() for k in only.split(",")] if only else None
    if only_keys:
        valid = {s.key for s in SIGNATURES}
        bad = [k for k in only_keys if k not in valid]
        if bad:
            raise typer.BadParameter(
                f"unknown signature key(s): {', '.join(bad)}. "
                f"valid: {', '.join(sorted(valid))}")

    scan = _scan_target(target, quiet=quiet)
    try:
        detections = run_identify(
            scan, min_confidence=min_confidence, only=only_keys)
    except FileNotFoundError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2)

    if not quiet:
        render_console(
            detections, target=str(target) if target else None, verbose=verbose)

    if json_out is not None:
        report = build_report(detections, target=str(target) if target else None)
        write_json(report, json_out)
        if not quiet:
            console.print(f"[green]✓[/green] JSON report written to {json_out}")

    raise typer.Exit(code=0 if detections else 1)


@app.command()
def collect(
    target: Optional[Path] = typer.Argument(
        None, metavar="[TARGET]",
        help="Image file (.raw/.001/.E01/.vmdk), mounted drive, or extracted folder. Omit for the live system."),
    output: Optional[Path] = typer.Option(
        None, "--output", "-O",
        help="Case/output directory. Default: %USERPROFILE%\\Documents\\AABF\\"
             "case_<timestamp>."),
    only: Optional[str] = typer.Option(
        None, "--only", "-o", help="Comma-separated signature keys to collect."),
    min_confidence: float = typer.Option(
        DEFAULT_MIN_CONFIDENCE, "--min-confidence", "-c", min=0.0, max=1.0,
        help="Discard detections below this confidence."),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Per-source detail."),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress console output."),
) -> None:
    """Local artifact-based collection (Section 5.3.1).

    Identifies AI agent browsers, then secures every locally-available artifact
    into OUTPUT with SHA-256 hashes and a chain-of-custody manifest. Cloud-side
    bodies are recorded as pending API reconstruction (separate module).
    """
    only_keys = _parse_only(only)
    case = _open_case(output, quiet=quiet)
    scan = _scan_target(target, dest_base=case, quiet=quiet)
    try:
        detections = run_identify(
            scan, min_confidence=min_confidence, only=only_keys)
    except FileNotFoundError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2)

    if not detections:
        if not quiet:
            console.print("[yellow]No AI agent browsers identified — "
                          "nothing to collect.[/yellow]")
        raise typer.Exit(code=1)

    result = collect_local(
        detections, case, target=str(target) if target else None)

    manifest_path = case / "manifest.json"
    write_manifest(result, manifest_path)
    write_collection_log(result, case / "collection.log")

    if not quiet:
        render_collection(result, console=console, verbose=verbose)
        console.print(f"[green]✓[/green] manifest: {manifest_path}")

    raise typer.Exit(code=0)


@app.command()
def parse(
    target: Optional[Path] = typer.Argument(
        None, metavar="[TARGET]",
        help="Image file (.raw/.001/.E01/.vmdk), mounted drive, or extracted folder. Omit for the live system."),
    manifest: Optional[Path] = typer.Option(
        None, "--manifest", "-m",
        help="Parse an existing collection manifest.json instead of collecting."),
    output: Optional[Path] = typer.Option(
        None, "--output", "-O",
        help="Evidence dir for collection (full pipeline). Defaults to a temp dir."),
    only: Optional[str] = typer.Option(
        None, "--only", "-o", help="Comma-separated signature keys."),
    json_out: Optional[Path] = typer.Option(
        None, "--json", "-j", help="Write the parsed-records JSON report here."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="List every record."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress console output."),
) -> None:
    """Parse collected artifacts into structured agent records.

    Either parse an existing evidence store (``--manifest``), or run the full
    identify → collect → parse pipeline on TARGET (or the live system).
    """
    if manifest is not None:
        results = parse_manifest(manifest)
        target_label = str(manifest)
    else:
        only_keys = _parse_only(only)
        out_dir = _open_case(output, quiet=quiet)
        scan = _scan_target(target, dest_base=out_dir, quiet=quiet)
        try:
            detections = run_identify(scan, only=only_keys)
        except FileNotFoundError as exc:
            console.print(f"[red]error:[/red] {exc}")
            raise typer.Exit(code=2)
        if not detections:
            if not quiet:
                console.print("[yellow]No AI agent browsers identified.[/yellow]")
            raise typer.Exit(code=1)
        result = collect_local(detections, out_dir,
                               target=str(target) if target else None)
        write_manifest(result, out_dir / "manifest.json")
        write_collection_log(result, out_dir / "collection.log")
        results = parse_collection(result)
        target_label = str(target) if target else "<live system>"

    if not quiet:
        render_parse(results, console=console, verbose=verbose)
    if json_out is not None:
        write_json(build_parse_report(results, target=target_label), json_out)
        if not quiet:
            console.print(f"[green]✓[/green] parsed-records JSON: {json_out}")
    raise typer.Exit(code=0)


def _scan_target(target: Optional[Path], *, dest_base: Optional[Path] = None,
                 quiet: bool) -> Optional[Path]:
    """Resolve the path to scan. A forensic image *file* TARGET is extracted to
    ``<dest_base>/_extracted`` (or a temp dir) and that directory is returned;
    a directory/None TARGET is returned unchanged."""
    from . import imaging
    if target is None or not imaging.is_image(target):
        return target
    base = dest_base or Path(tempfile.mkdtemp(prefix="aabf-img-"))
    extract_dir = Path(base) / "_extracted"
    if not quiet:
        console.print(f"[dim]extracting image:[/dim] {target} → {extract_dir}")
    try:
        imaging.extract(Path(target), extract_dir)
    except RuntimeError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2)
    return extract_dir


def _open_case(output: Optional[Path], *, quiet: bool) -> Path:
    """Resolve the per-run case directory
    (default: %USERPROFILE%\\Documents\\AABF\\case_<timestamp>)."""
    case = new_case_dir(output)
    if not quiet:
        console.print(f"[dim]case directory:[/dim] {case}")
    return case


def _parse_only(only: Optional[str]) -> Optional[list[str]]:
    if not only:
        return None
    keys = [k.strip() for k in only.split(",")]
    valid = {s.key for s in SIGNATURES}
    bad = [k for k in keys if k not in valid]
    if bad:
        raise typer.BadParameter(
            f"unknown signature key(s): {', '.join(bad)}. "
            f"valid: {', '.join(sorted(valid))}")
    return keys


@app.command()
def analyze(
    target: Optional[Path] = typer.Argument(
        None, metavar="[TARGET]",
        help="Image file (.raw/.001/.E01/.vmdk), mounted drive, or extracted folder. Omit for the live system."),
    manifest: Optional[Path] = typer.Option(
        None, "--manifest", "-m",
        help="Analyze an existing collection manifest.json instead of collecting."),
    output: Optional[Path] = typer.Option(
        None, "--output", "-O", help="Evidence dir for collection (temp by default)."),
    only: Optional[str] = typer.Option(None, "--only", "-o",
                                       help="Comma-separated signature keys."),
    json_out: Optional[Path] = typer.Option(
        None, "--json", "-j", help="Write the timeline JSON report here."),
    verbose: bool = typer.Option(False, "--verbose", "-v",
                                 help="Print each conversation's events."),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Reconstruct a correlated behavior timeline (Section 5.4).

    Runs identify → collect → parse → analyze on TARGET (or live), or analyzes an
    existing evidence store (``--manifest``). Correlates records by conversation/
    session id and attributes the actor.
    """
    detections = None
    coc = None
    if manifest is not None:
        results = parse_manifest(manifest)
        target_label = str(manifest)
        case_root = manifest.parent
        try:
            coc = _json.loads(manifest.read_text(encoding="utf-8")).get("chain_of_custody")
        except (OSError, ValueError):
            coc = None
    else:
        only_keys = _parse_only(only)
        case = _open_case(output, quiet=quiet)
        scan = _scan_target(target, dest_base=case, quiet=quiet)
        try:
            detections = run_identify(scan, only=only_keys)
        except FileNotFoundError as exc:
            console.print(f"[red]error:[/red] {exc}")
            raise typer.Exit(code=2)
        if not detections:
            if not quiet:
                console.print("[yellow]No AI agent browsers identified.[/yellow]")
            raise typer.Exit(code=1)
        result = collect_local(detections, case,
                               target=str(target) if target else None)
        write_manifest(result, case / "manifest.json")
        write_collection_log(result, case / "collection.log")
        results = parse_collection(result)
        target_label = str(target) if target else "<live system>"
        case_root = case
        coc = result.chain_of_custody()

    timeline = run_analyze(results, detections=detections)

    if not quiet:
        render_timeline(timeline, console=console, verbose=verbose,
                        target=target_label)

    # per-service analysis files (one JSON per service, not a single dump)
    analysis_dir = case_root / "analysis"
    write_per_service(timeline, analysis_dir, target=target_label)
    # single consolidated, human-readable report — the final deliverable
    report_path = write_report(timeline, case_root / "report.md",
                               target=target_label, case_dir=str(case_root),
                               chain_of_custody=coc)
    if json_out is not None:  # optional combined JSON on explicit request
        write_json(build_timeline_report(timeline, target=target_label), json_out)

    if not quiet:
        console.print(f"\n[bold green]► Report[/bold green]  {report_path}")
        console.print(f"[dim]  Case  {case_root}   (artifacts/ · manifest.json · "
                      f"analysis/<service>.json)[/dim]")
    raise typer.Exit(code=0)


@app.command()
def show(
    case: Optional[Path] = typer.Argument(
        None, metavar="[CASE|SERVICE]",
        help="Case dir, OR a service key (e.g. comet) to show that service's full "
             "detail from the latest case. Default: overview of the latest case."),
    service: Optional[str] = typer.Option(
        None, "--service", "-s", help="Show only this browser key (e.g. comet)."),
    session: Optional[str] = typer.Option(
        None, "--session", help="Show only one session by its id or number (1-based)."),
) -> None:
    """View a previously analyzed case (no pipeline re-run).

    Overview: ``aabf show`` lists each browser's sessions/turns. Pass a service
    key (``aabf show comet`` or ``-s comet``) to dump that service's FULL detail —
    complete identity, untruncated prompt/workflow/output, and all residual
    artifacts. ``--session`` drills into one session.
    """
    # Convenience: a bare service key as the positional argument.
    valid_keys = {s.key for s in SIGNATURES}
    if case is not None and service is None and str(case) in valid_keys \
            and not Path(case).exists():
        service = str(case)
        case = None

    case_dir = case or _latest_case()
    if case_dir is None:
        console.print("[yellow]No case found.[/yellow] Run [bold]aabf analyze[/bold] "
                      "first, or pass a case directory.")
        raise typer.Exit(code=1)
    reports = load_case(case_dir)
    if not reports:
        console.print(f"[red]No analysis results in[/red] {case_dir}")
        raise typer.Exit(code=1)
    console.print(f"[dim]case: {case_dir}[/dim]\n")
    render_case(reports, console=console, service=service, session=session)
    raise typer.Exit(code=0)


def _latest_case() -> Optional[Path]:
    root = aabf_root()
    if not root.is_dir():
        return None
    cases = sorted((p for p in root.glob("case_*") if p.is_dir()), key=lambda p: p.name)
    return cases[-1] if cases else None


@app.command()
def reconstruct(
    target: Optional[Path] = typer.Argument(
        None, metavar="[TARGET]",
        help="Image file (.raw/.001/.E01/.vmdk), mounted drive, or extracted folder. Omit for the live system."),
    output: Optional[Path] = typer.Option(
        None, "--output", "-O",
        help="Case/output directory. Default: %USERPROFILE%\\Documents\\AABF\\"
             "case_<timestamp>."),
    only: Optional[str] = typer.Option(
        None, "--only", "-o", help="Comma-separated signature keys."),
    send: bool = typer.Option(
        False, "--send/--plan",
        help="Actually perform the HTTP requests (--send) or just plan them "
             "(--plan, default — no network)."),
    token: list[str] = typer.Option(
        [], "--token", "-t", metavar="KEY=VALUE",
        help="Explicit token per service (e.g. comet=<cookie>); repeatable. "
             "Needed for cookie/DPAPI services."),
    json_out: Optional[Path] = typer.Option(
        None, "--json", "-j", help="Write the reconstruction JSON report here."),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """API-reconstruction-based remote collection (Section 5.3.2).

    Identifies & collects locally, then for each cloud/hybrid service extracts a
    token (auto for Fellou/Sigma; pass --token for cookie/DPAPI services) and
    replays its endpoints. Defaults to --plan (no network); use --send to fetch.
    """
    from .collection.api import reconstruct as run_reconstruct

    tokens = dict(t.split("=", 1) for t in token if "=" in t)
    only_keys = _parse_only(only)
    out_dir = _open_case(output, quiet=quiet)
    scan = _scan_target(target, dest_base=out_dir, quiet=quiet)
    try:
        detections = run_identify(scan, only=only_keys)
    except FileNotFoundError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2)
    if not detections:
        if not quiet:
            console.print("[yellow]No AI agent browsers identified.[/yellow]")
        raise typer.Exit(code=1)

    result = collect_local(detections, out_dir, target=str(target) if target else None)
    write_manifest(result, out_dir / "manifest.json")
    write_collection_log(result, out_dir / "collection.log")

    if not result.pending_api and not quiet:
        console.print("[dim]No cloud/hybrid services pending API reconstruction.[/dim]")

    api_results = []
    for pending in result.pending_api:
        bk, u = pending.browser_key, pending.user
        api_results.append(run_reconstruct(
            pending, token=tokens.get(bk),
            store_dirs=_store_dirs_for(result, bk, u),
            cookies=_files_for(result, bk, u, "Cookies"),
            local_state=_files_for(result, bk, u, "Local State"),
            output_dir=str(out_dir), send=send))

    if not quiet:
        _render_reconstruct(api_results, send=send)
    if json_out is not None:
        write_json({"tool": "aabf", "version": __version__,
                    "module": "collection.api", "send": send,
                    "results": [r.to_dict() for r in api_results]}, json_out)
        if not quiet:
            console.print(f"[green]✓[/green] reconstruction JSON: {json_out}")
    raise typer.Exit(code=0)


def _store_dirs_for(result, browser_key: str, user: str) -> list[Path]:
    dirs: list[Path] = []
    for a in result.artifacts:
        if (a.browser_key == browser_key and a.user == user
                and a.is_leveldb and a.files):
            d = Path(result.output_dir) / Path(a.files[0].dest).parent
            if d not in dirs:
                dirs.append(d)
    return dirs


def _files_for(result, browser_key: str, user: str, name: str) -> list[Path]:
    out: list[Path] = []
    for a in result.artifacts:
        if a.browser_key == browser_key and a.user == user:
            for f in a.files:
                if Path(f.dest).name.lower() == name.lower():
                    out.append(Path(result.output_dir) / f.dest)
    return out


def _render_reconstruct(results, *, send: bool) -> None:
    from rich.table import Table
    title = "API reconstruction" + ("" if send else " — PLAN (no network)")
    table = Table(title=title, title_style="bold", expand=True)
    table.add_column("Browser", style="bold")
    table.add_column("Token")
    table.add_column("Status")
    table.add_column("Requests/Responses", justify="right")
    table.add_column("Note", overflow="fold")
    for r in results:
        tok = "[green]yes[/green]" if r.token_extracted else "[red]no[/red]"
        n = str(len(r.responses)) if r.responses else "-"
        table.add_row(r.browser_key, tok, r.status, n, (r.note or "")[:80])
    console.print(table)
    if not send:
        console.print("[dim]Dry-run: re-run with --send to perform the requests "
                      "(requires the [api] extra and valid tokens).[/dim]")


@app.command()
def signatures() -> None:
    """List the supported AI agent browsers and their classification."""
    table = Table(title="Supported AI agent browsers", title_style="bold")
    table.add_column("Key", style="bold cyan")
    table.add_column("Browser")
    table.add_column("Arch")
    table.add_column("Service type")
    table.add_column("Extension ID")
    table.add_column("Artifacts", justify="right")
    for s in SIGNATURES:
        table.add_row(
            s.key, s.name, s.base_arch, s.service_type.value,
            s.extension_id or "[dim]—[/dim]", str(len(s.artifacts)))
    console.print(table)


@app.command(name="signature")
def signature_detail(
    key: str = typer.Argument(..., help="Signature key, e.g. comet"),
    as_json: bool = typer.Option(False, "--json", help="Emit raw JSON."),
) -> None:
    """Show the full knowledge-base entry for one browser."""
    from .signatures import BY_KEY
    sig = BY_KEY.get(key)
    if sig is None:
        raise typer.BadParameter(
            f"unknown key '{key}'. valid: {', '.join(sorted(BY_KEY))}")
    if as_json:
        console.print_json(_json.dumps(sig.to_dict(), ensure_ascii=False))
        return
    console.print_json(_json.dumps(sig.to_dict(), ensure_ascii=False))


@app.command()
def version() -> None:
    """Print the AABF version."""
    console.print(f"aabf {__version__}")


if __name__ == "__main__":
    app()
