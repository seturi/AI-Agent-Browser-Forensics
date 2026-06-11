"""Console + JSON rendering for the analysis module."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from pathlib import Path

from .. import __version__
from ..reporting import write_json
from . import timestamps
from .models import Timeline

__all__ = ["build_timeline_report", "render_timeline", "write_json",
           "build_service_reports", "write_per_service",
           "build_markdown_report", "write_report",
           "load_case", "render_case"]

_COV_MD = {"recovered": "✓ recovered", "present": "◐ present",
           "server": "☁ server", "absent": "✗ absent", "n/a": "– n/a"}

_ROLE_STYLE = {"user": "bold cyan", "assistant": "green", "agent": "green",
               "tool": "yellow", "system": "dim"}

# coverage status -> (symbol, style)
_COV_MARK = {
    "recovered": ("[green]✓ recovered[/green]", None),
    "present":   ("[yellow]◐ present[/yellow]", None),   # on disk, unparsed
    "server":    ("[cyan]☁ server[/cyan]", None),        # needs API reconstruction
    "absent":    ("[red]✗ absent[/red]", None),
    "n/a":       ("[dim]– n/a[/dim]", None),
}
_COV_CATS = ("Account", "Prompt", "Workflow", "Output")


def build_timeline_report(timeline: Timeline, *, target: str | None) -> dict[str, Any]:
    return {
        "tool": "aabf",
        "version": __version__,
        "module": "analysis",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target or "<live system>",
        "timeline": timeline.to_dict(),
    }


def build_service_reports(timeline: Timeline, *, target: str | None) -> dict[str, dict]:
    """Split the timeline into one report dict per service (no single dump)."""
    keys = ({c.browser_key for c in timeline.coverage}
            | {c.browser_key for c in timeline.conversations}
            | {e.record.browser_key for e in timeline.orphans}
            | {i.browser_key for i in timeline.identities})
    now = datetime.now(timezone.utc).isoformat()
    reports: dict[str, dict] = {}
    for bk in sorted(keys):
        convs = [c for c in timeline.conversations if c.browser_key == bk]
        orph = [e for e in timeline.orphans if e.record.browser_key == bk]
        residual = [e for e in orph if e.record.category == "Residual"]
        other = [e for e in orph if e.record.category != "Residual"]
        reports[bk] = {
            "tool": "aabf", "version": __version__, "module": "analysis",
            "service": bk, "generated_at": now, "target": target or "<live system>",
            "identities": [i.to_dict() for i in timeline.identities
                           if i.browser_key == bk],
            "coverage": [c.to_dict() for c in timeline.coverage
                         if c.browser_key == bk],
            "conversation_count": len(convs),
            "conversations": [c.to_dict() for c in convs],
            "residual_artifacts": [e.to_dict() for e in residual],
            "other_orphan_events": [e.to_dict() for e in other],
        }
    return reports


def write_per_service(timeline: Timeline, out_dir, *, target: str | None) -> list[Path]:
    """Write one ``<service>.json`` per service + an ``index.json`` into ``out_dir``."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    reports = build_service_reports(timeline, target=target)
    written: list[Path] = []
    for bk, rep in reports.items():
        p = out_dir / f"{bk}.json"
        write_json(rep, p)
        written.append(p)
    index = {
        "tool": "aabf", "module": "analysis", "target": target or "<live system>",
        "services": [{"service": bk, "conversations": r["conversation_count"],
                      "residual_artifacts": len(r["residual_artifacts"]),
                      "identities": len(r["identities"])}
                     for bk, r in reports.items()],
    }
    write_json(index, out_dir / "index.json")
    return written


_MD_CATS = ("Account", "Prompt", "Workflow", "Output")


def build_markdown_report(timeline: Timeline, *, target: str | None,
                          case_dir: str | None = None,
                          chain_of_custody: dict | None = None) -> str:
    """Render a single, human-readable forensic report (Markdown) consolidating
    every service's identity, artifact coverage, reconstructed conversations and
    residual artifacts."""
    L: list[str] = []
    coc = chain_of_custody or {}
    L.append("# AI Agent Browser Forensic Report")
    L.append("")
    L.append("| Field | Value |")
    L.append("|---|---|")
    L.append(f"| Tool | aabf v{__version__} |")
    L.append(f"| Generated (UTC) | {datetime.now(timezone.utc).isoformat()} |")
    L.append(f"| Target | {target or '<live system>'} |")
    if case_dir:
        L.append(f"| Case directory | {case_dir} |")
    for k in ("operator", "host", "platform"):
        if coc.get(k):
            L.append(f"| {k.capitalize()} | {coc[k]} |")
    L.append("")

    # ---- 1. Summary ----
    L.append("## 1. Summary")
    L.append("")
    L.append(f"Identified services: **{len(timeline.coverage)}**  ·  "
             f"identities: **{len(timeline.identities)}**  ·  "
             f"conversations: **{len(timeline.conversations)}**")
    L.append("")
    L.append("| Browser | Type | Account | Prompt | Workflow | Output | Conv. | Residual |")
    L.append("|---|---|---|---|---|---|--:|--:|")
    resid_by_svc = _residuals_by_service(timeline)
    conv_by_svc = _count_by_service(c.browser_key for c in timeline.conversations)
    for cov in timeline.coverage:
        cells = [_COV_MD.get(cov.categories[c].status, "?") if c in cov.categories
                 else "– n/a" for c in _MD_CATS]
        L.append(f"| {cov.browser_key} | {cov.service_type} | " + " | ".join(cells)
                 + f" | {conv_by_svc.get(cov.browser_key, 0)} "
                 f"| {len(resid_by_svc.get(cov.browser_key, []))} |")
    L.append("")

    # ---- 2. Identities ----
    if timeline.identities:
        L.append("## 2. Identities")
        L.append("")
        L.append("| Browser | Profile | Email | User ID | Username | Name |")
        L.append("|---|---|---|---|---|---|")
        for i in timeline.identities:
            L.append(f"| {i.browser_key} | {i.profile or '-'} | {i.email or '-'} "
                     f"| {i.user_id or '-'} | {i.username or '-'} | {i.name or '-'} |")
        L.append("")

    # ---- 3. Per-service detail ----
    L.append("## 3. Per-service analysis")
    L.append("")
    for idx, cov in enumerate(timeline.coverage, 1):
        bk = cov.browser_key
        L.append(f"### 3.{idx} {cov.service_name} ({cov.service_type})")
        L.append("")
        ident = next((i for i in timeline.identities if i.browser_key == bk), None)
        if ident:
            L.append(f"**Identity:** {ident.email or ident.username or ident.user_id or '-'}"
                     f" (user_id: {ident.user_id or '-'})")
            L.append("")
        L.append("**Artifact coverage:**")
        L.append("")
        L.append("| Category | Status | Local paths |")
        L.append("|---|---|---|")
        for c in _MD_CATS:
            st = cov.categories.get(c)
            if not st:
                L.append(f"| {c} | – n/a | |")
                continue
            paths = "<br>".join(p for p in st.paths[:3]) if st.paths else ""
            L.append(f"| {c} | {_COV_MD.get(st.status, st.status)}"
                     f"{f' ({st.record_count})' if st.record_count else ''} | {paths} |")
        L.append("")

        convs = [c for c in timeline.conversations if c.browser_key == bk]
        if convs:
            L.append(f"**Conversation sessions ({len(convs)}):**")
            L.append("")
            # session index — list them, then drill into each
            L.append("| # | Profile | Session | Time | Turns | Actor |")
            L.append("|--:|---|---|---|--:|---|")
            for n, conv in enumerate(convs, 1):
                actor = (conv.actor.email or conv.actor.user_id) if conv.actor else "-"
                L.append(f"| {n} | {conv.profile or '-'} | {conv.conversation_id} "
                         f"| {timestamps.iso(conv.started_at) or '?'} "
                         f"| {len(conv.reconstruct())} | {actor or '-'} |")
            L.append("")
            for n, conv in enumerate(convs, 1):
                _md_session(conv, n, L)

        residual = resid_by_svc.get(bk, [])
        if residual:
            L.append(f"**Residual artifacts ({len(residual)}):**")
            L.append("")
            L.append("| Kind | When | Content |")
            L.append("|---|---|---|")
            for e in residual:
                L.append(f"| {e.record.fields.get('kind', '?')} "
                         f"| {timestamps.iso(e.when) or '-'} "
                         f"| {_md_cell(e.record.content)} |")
            L.append("")

    # ---- Legend ----
    L.append("## Legend")
    L.append("")
    L.append("- **✓ recovered** — parsed from local artifacts")
    L.append("- **◐ present** — local store exists but unparsed (residual / not logged in)")
    L.append("- **☁ server** — server-side only; needs API reconstruction (`aabf reconstruct`)")
    L.append("- **✗ absent** — expected local artifact not found")
    L.append("- **– n/a** — category not applicable for this service")
    L.append("")
    return "\n".join(L)


def write_report(timeline: Timeline, path, *, target: str | None,
                 case_dir: str | None = None, chain_of_custody: dict | None = None):
    from pathlib import Path as _P
    md = build_markdown_report(timeline, target=target, case_dir=case_dir,
                               chain_of_custody=chain_of_custody)
    p = _P(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(md, encoding="utf-8")
    return p


def _residuals_by_service(timeline: Timeline) -> dict:
    out: dict = {}
    for e in timeline.orphans:
        if e.record.category == "Residual":
            out.setdefault(e.record.browser_key, []).append(e)
    return out


def _count_by_service(keys) -> dict:
    out: dict = {}
    for k in keys:
        out[k] = out.get(k, 0) + 1
    return out


def _md_cell(text) -> str:
    s = (str(text) if text is not None else "").replace("\n", " ").replace("|", "\\|")
    return s[:200] + ("…" if len(s) > 200 else "")


def _md_text(text, limit: int = 800) -> str:
    s = (str(text) if text is not None else "").replace("\n", " ").replace("|", "\\|")
    return s[:limit] + ("…" if len(s) > limit else "")


def _md_session(conv, n: int, L: list) -> None:
    """Render one conversation session as turns (prompt → workflow → output)."""
    actor = (conv.actor.email or conv.actor.user_id) if conv.actor else "-"
    prof = f" · profile: {conv.profile}" if conv.profile else ""
    L.append(f"#### Session {n} — {conv.conversation_id}")
    L.append("")
    L.append(f"- actor: {actor or '-'}{prof}  ·  "
             f"{timestamps.iso(conv.started_at) or '?'} → "
             f"{timestamps.iso(conv.ended_at) or '?'}  ·  "
             f"{conv.reconstruction_status}")
    L.append("")
    for ti, t in enumerate(conv.reconstruct(), 1):
        when = timestamps.iso(t.prompt.when) if (t.prompt and t.prompt.when) else None
        L.append(f"**Turn {ti}**" + (f" · {when}" if when else ""))
        L.append("")
        if t.prompt_text():
            L.append(f"- 🗩 **Prompt:** {_md_text(t.prompt_text())}")
        steps = t.workflow_steps()
        if steps:
            L.append("- ⚙ **Workflow:**")
            for s in steps:
                L.append(f"    - {_md_cell(s)}")
        for o in t.output_text():
            L.append(f"- ✓ **Output:** {_md_text(o)}")
        L.append("")


def load_case(case_dir) -> list[dict]:
    """Load the per-service analysis JSON reports written under <case>/analysis/."""
    import json
    from pathlib import Path
    adir = Path(case_dir)
    if (adir / "analysis").is_dir():
        adir = adir / "analysis"
    reports = []
    for p in sorted(adir.glob("*.json")):
        if p.name == "index.json":
            continue
        try:
            reports.append(json.loads(p.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return reports


def render_case(reports: list[dict], *, console: Console | None = None,
                service: str | None = None, session: str | None = None) -> None:
    """Render previously-written case results (no pipeline re-run).

    Overview (no ``service``): one line per browser + its sessions/turns.
    When a ``service`` (or ``session``) is selected, show that service in FULL —
    complete identity, untruncated turn content, and the full residual list."""
    console = console or Console()
    if not reports:
        console.print("[yellow]No analysis results found in this case.[/yellow]")
        return
    sel = [r for r in reports if not service or r.get("service") == service]
    if not sel:
        console.print(f"[yellow]No such service '{service}'.[/yellow] "
                      f"Available: {', '.join(r.get('service','?') for r in reports)}")
        return
    full = service is not None or session is not None
    limit = None if full else 200  # None => no truncation

    nconv = sum(r.get("conversation_count", 0) for r in reports)
    console.print(f"[bold]{len(reports)}[/bold] service(s) · "
                  f"[bold]{nconv}[/bold] conversation session(s)\n")

    for r in sel:
        svc = r.get("service", "?")
        idents = r.get("identities", [])
        if full and idents:
            console.rule(f"[bold]{svc}[/bold]", align="left")
            for i in idents:
                console.print(f"  [bold]account[/bold]: "
                              f"[magenta]profile={i.get('profile') or '—'}[/magenta] · "
                              f"email={i.get('email') or '—'} · "
                              f"user_id={i.get('user_id') or '—'} · "
                              f"username={i.get('username') or '—'} · "
                              f"name={i.get('name') or '—'}")
        else:
            profs = sorted({i.get("profile") for i in idents if i.get("profile")})
            who = (idents[0].get("email") or idents[0].get("user_id")) if idents else None
            extra = f"  [magenta]({', '.join(profs)})[/magenta]" if len(profs) > 1 else ""
            console.rule(f"[bold]{svc}[/bold]  [dim]{who or '—'}[/dim]{extra}", align="left")

        convs = r.get("conversations", [])
        if session is not None:
            convs = [c for n, c in enumerate(convs, 1)
                     if session in (str(c.get("conversation_id")), str(n))]
        if not convs:
            console.print("[dim]no conversation sessions[/dim]")
        for n, c in enumerate(convs, 1):
            _print_session_json(c, n, console, limit=limit)

        _render_residuals_json(r.get("residual_artifacts", []), console, full=full)
        console.print()


def _render_residuals_json(residual: list, console: Console, *, full: bool) -> None:
    index = [e for e in residual
             if (e.get("fields") or {}).get("kind") == "conversation-index"]
    other = [e for e in residual if e not in index]
    if index:
        console.print(f"[bold]conversation index[/bold] [dim]({len(index)} — "
                      f"body not cached locally; reconstruct for full)[/dim]")
        for e in index:
            console.print(f"   [cyan]·[/cyan] [dim]{e.get('when') or '?'}[/dim]  "
                          f"{_trim(e.get('content'), None if full else 80)}")
    if not other:
        return
    if full:
        console.print("[bold]residual artifacts[/bold]")
        for e in other:
            kind = (e.get("fields") or {}).get("kind", "?")
            console.print(f"   [yellow]{kind}[/yellow] [dim]{e.get('when') or ''}[/dim] "
                          f"{_trim(e.get('content'), None)}")
    else:
        kinds: dict = {}
        for e in other:
            k = (e.get("fields") or {}).get("kind", "?")
            kinds[k] = kinds.get(k, 0) + 1
        summary = ", ".join(f"{k}×{v}" for k, v in sorted(kinds.items()))
        console.print(f"[dim]residual: {summary}[/dim]")


def _print_session_json(c: dict, n: int, console: Console, *, limit: int | None = 200) -> None:
    prof = c.get("profile")
    prof_s = f" [magenta]\\[{prof}][/magenta]" if prof else ""
    console.print(f"[bold cyan]▶ Session {n}[/bold cyan]{prof_s} "
                  f"[dim]{c.get('conversation_id')} · "
                  f"{c.get('started_at') or '?'} · {len(c.get('turns', []))} turn(s)[/dim]")
    for ti, t in enumerate(c.get("turns", []), 1):
        when = t.get("time") or "—"
        console.print(f"  [bold]Turn {ti}[/bold] [dim]{when}[/dim]")
        if t.get("prompt"):
            console.print(f"    [bold cyan]🗩 Prompt  [/bold cyan] {_trim(t['prompt'], limit)}")
        if t.get("workflow"):
            wf = (" → ".join(t['workflow']) if limit is not None
                  else "\n                ".join(t['workflow']))
            console.print(f"    [yellow]⚙ Workflow[/yellow] {_trim(wf, limit)}")
        for o in t.get("output", []):
            console.print(f"    [green]✓ Output  [/green] {_trim(o, limit)}")
    console.print()


def render_timeline(timeline: Timeline, *, console: Console | None = None,
                    verbose: bool = False, target: str | None = None) -> None:
    """Concise by default (one focused table + key findings); ``--verbose`` adds
    the full coverage matrix, residual table and per-conversation reconstruction."""
    console = console or Console()
    ident_by = {i.browser_key: i for i in timeline.identities}
    resid_by = _residuals_by_service(timeline)
    conv_by = _count_by_service(c.browser_key for c in timeline.conversations)

    ns, ni, nc = len(timeline.coverage), len(timeline.identities), len(timeline.conversations)
    console.print(f"[bold]{ns}[/bold] AI agent browser(s) · [bold]{ni}[/bold] "
                  f"identit(ies) · [bold]{nc}[/bold] conversation(s) recovered locally")
    console.print()

    # ---- one focused per-service table ----
    table = Table(box=box.SIMPLE_HEAD, pad_edge=False)
    table.add_column("Browser", style="bold")
    table.add_column("Type")
    table.add_column("Recovered")
    table.add_column("Identity")
    table.add_column("Conv.", justify="right")
    table.add_column("Next")
    for cov in timeline.coverage:
        ident = ident_by.get(cov.browser_key)
        who = (ident.email or ident.user_id) if ident else None
        table.add_row(
            cov.browser_key,
            _type_short(cov.service_type),
            _recovered_summary(cov),
            (who or "[dim]—[/dim]"),
            str(conv_by.get(cov.browser_key, 0) or "[dim]—[/dim]"),
            _next_action(cov, bool(resid_by.get(cov.browser_key))))
    console.print(table)

    # ---- conversations (the headline result) ----
    if timeline.conversations:
        console.print(f"\n[bold]Conversations[/bold] ({nc})")
        for c in timeline.conversations[:10]:
            cc = c.category_counts()
            who = (c.actor.email or c.actor.user_id) if c.actor else "—"
            console.print(
                f"  • [cyan]{str(c.conversation_id)[:12]}[/cyan] "
                f"[dim]{c.browser_key}[/dim] {who or '—'}  "
                f"{timestamps.iso(c.started_at) or '?'}  "
                f"[dim]P{cc.get('Prompt',0)}/W{cc.get('Workflow',0)}/O{cc.get('Output',0)}[/dim]")
        if nc > 10:
            console.print(f"  [dim]… and {nc - 10} more (see report.md)[/dim]")
    else:
        console.print("\n[dim]No conversation bodies recovered locally. "
                      "Cloud-centric services keep bodies server-side — run "
                      "[/dim][bold]aabf reconstruct[/bold][dim] to fetch them.[/dim]")

    console.print("\n[dim]Run with -v for the full coverage matrix, residual "
                  "artifacts and per-conversation reconstruction.[/dim]")

    # ---- verbose: the full detail ----
    if verbose:
        console.print()
        _render_coverage(timeline, console)
        _render_residuals(timeline, console, verbose=True)
        if timeline.conversations:
            console.print("[bold]Conversation reconstruction[/bold]\n")
            for i, c in enumerate(timeline.conversations, 1):
                _render_conversation(c, console, index=i)


def _type_short(service_type: str) -> str:
    return {"local-centric": "local", "cloud-centric": "[yellow]cloud[/yellow]",
            "hybrid": "[cyan]hybrid[/cyan]"}.get(service_type, service_type)


def _recovered_summary(cov) -> str:
    rec = [c for c in _MD_CATS if cov.categories.get(c)
           and cov.categories[c].status == "recovered"]
    if rec:
        return "[green]" + ", ".join(rec) + "[/green]"
    if any(cov.categories.get(c) and cov.categories[c].status == "present"
           for c in _MD_CATS):
        return "[yellow]residual only[/yellow]"
    return "[dim]—[/dim]"


def _next_action(cov, has_residual: bool) -> str:
    if any(cov.categories.get(c) and cov.categories[c].status == "server"
           for c in _MD_CATS):
        return "[cyan]☁ reconstruct[/cyan]"
    return "[dim]—[/dim]"


def _render_coverage(timeline: Timeline, console: Console) -> None:
    if not timeline.coverage:
        return
    table = Table(title="Agent-artifact coverage (identified services)",
                  title_style="bold", expand=True)
    table.add_column("Browser", style="bold")
    table.add_column("Type")
    table.add_column("User")
    for cat in _COV_CATS:
        table.add_column(cat)
    for cov in timeline.coverage:
        row = [cov.browser_key, cov.service_type, cov.user]
        for cat in _COV_CATS:
            st = cov.categories.get(cat)
            mark = _COV_MARK.get(st.status if st else "n/a", ("?", None))[0]
            if st and st.record_count:
                mark += f" ({st.record_count})"
            row.append(mark)
        table.add_row(*row)
    console.print(table)
    console.print("[dim]✓ recovered · ◐ present on disk but unparsed (residual / "
                  "not-logged-in) · ☁ server-side (needs reconstruct) · ✗ absent · "
                  "– n/a[/dim]\n")


def _render_residuals(timeline: Timeline, console: Console, *, verbose: bool) -> None:
    residual = [e for e in timeline.orphans if e.record.category == "Residual"]
    if not residual:
        return
    # group by (browser, kind)
    groups: dict[tuple, list] = {}
    for e in residual:
        groups.setdefault((e.record.browser_key, e.record.fields.get("kind", "?")),
                          []).append(e)
    table = Table(title="Residual artifacts (persist without login/conversation)",
                  title_style="bold yellow", expand=True)
    table.add_column("Browser", style="bold")
    table.add_column("Kind")
    table.add_column("Count", justify="right")
    table.add_column("Sample", overflow="fold")
    for (bk, kind), evs in sorted(groups.items()):
        sample = next((e.record.content for e in evs if e.record.content), "") or ""
        table.add_row(bk, kind, str(len(evs)), sample[:60])
    console.print(table)

    if verbose:
        for e in residual:
            r = e.record
            when = timestamps.iso(e.when) or "—"
            console.print(f"  [dim]{when}[/dim] [yellow]{r.browser_key}/"
                          f"{r.fields.get('kind')}[/yellow]: {(r.content or '')[:80]}")
    console.print()


def _trim(text, n: int | None = 110) -> str:
    s = (str(text) if text is not None else "").replace("\n", " ")
    if n is None:
        return s
    return s[:n] + ("…" if len(s) > n else "")


def _render_conversation(c, console: Console, *, index: int | None = None) -> None:
    actor = (c.actor.email or c.actor.user_id) if c.actor else "—"
    head = f"Session {index} · " if index else ""
    title = Text.assemble(
        (f"{head}{c.browser_key} ", "bold"),
        (f"{str(c.conversation_id)[:24]}  {actor or '—'}", "dim"))
    console.print(Panel(title, border_style="blue", title_align="left"))
    for ti, t in enumerate(c.reconstruct(), 1):
        when = timestamps.iso(t.prompt.when) if (t.prompt and t.prompt.when) else "—"
        console.print(f"  [bold]Turn {ti}[/bold] [dim]{when}[/dim]")
        if t.prompt_text():
            console.print(f"    [bold cyan]🗩 Prompt  [/bold cyan] {_trim(t.prompt_text())}")
        steps = t.workflow_steps()
        if steps:
            shown = " → ".join(steps)
            console.print(f"    [yellow]⚙ Workflow[/yellow] {_trim(shown)}")
        for o in t.output_text():
            console.print(f"    [green]✓ Output  [/green] {_trim(o)}")
    console.print()
