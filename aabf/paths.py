"""Path resolution for live systems and mounted forensic images.

The signatures express artifact locations relative to Windows anchors
(``%LocalAppData%``, ``%AppData%``, ``%LocalAppData%\\Temp``). This module turns
those into concrete paths in two modes:

* **Live mode** (``target=None``): use the current Windows environment.
* **Target mode**: a path to a mounted image or an FTK-extracted folder. The
  resolver discovers user profile roots within it, however deeply the AppData
  folders are nested.

All component matching is case-insensitive so signatures authored with Windows
casing still resolve on images analysed under Linux/macOS.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .models import Anchor


@dataclass(frozen=True)
class ProfileRoot:
    """One Windows user account's AppData anchors.

    ``user`` is the account name (or ``"<live>"``). Either anchor may be ``None``
    if it was not found under the target (e.g. an extraction that only captured
    Local).
    """

    user: str
    local_appdata: Path | None
    roaming_appdata: Path | None

    def anchor_base(self, anchor: Anchor) -> Path | None:
        if anchor in (Anchor.LOCAL, Anchor.TEMP):
            base = self.local_appdata
            if base is not None and anchor is Anchor.TEMP:
                return _ci_child(base, "Temp") or (base / "Temp")
            return base
        return self.roaming_appdata


def _norm(name: str) -> str:
    """Normalise a path component for matching: case- and space-insensitive.

    Chromium browsers use ``User Data`` / ``Login Data`` (with a space), but the
    paper's tables write them as ``UserData`` / ``LoginData``. Folding spaces
    lets one signature match both spellings without enumerating variants.
    """
    return name.lower().replace(" ", "")


def _ci_child(parent: Path, name: str) -> Path | None:
    """Return the child of ``parent`` matching ``name`` case/space-insensitively.

    Prefers an exact (case-insensitive) match before falling back to the
    space-folded one, so a literal ``User Data`` still wins over ``UserData``
    when both somehow coexist.
    """
    if not parent.is_dir():
        return None
    lower = name.lower()
    norm = _norm(name)
    fallback: Path | None = None
    try:
        for child in parent.iterdir():
            cl = child.name.lower()
            if cl == lower:
                return child
            if fallback is None and _norm(cl) == norm:
                fallback = child
    except (OSError, PermissionError):
        return None
    return fallback


def resolve_relpath(base: Path, relpath: str) -> Path | None:
    """Resolve ``relpath`` (``/``-separated) under ``base`` case-insensitively.

    Returns the existing path, or ``None`` if any component is missing. Use
    :func:`glob_relpath` for paths containing ``*`` or ``{...}`` placeholders.
    """
    current = base
    for part in relpath.split("/"):
        if part in ("", "."):
            continue
        nxt = _ci_child(current, part)
        if nxt is None:
            return None
        current = nxt
    return current


def expand_relpath(base: Path, relpath: str) -> list[Path]:
    """Expand a relpath that may contain ``{profile}``/``{folder16}`` placeholders
    or glob wildcards, returning every existing match.

    Placeholders are treated as ``*`` (a single path component).
    """
    pattern = (
        relpath.replace("{profile}", "*")
        .replace("{folder16}", "*")
        .replace("{folder}", "*")
    )
    parts = [p for p in pattern.split("/") if p not in ("", ".")]
    frontier: list[Path] = [base]
    for part in parts:
        nxt: list[Path] = []
        has_glob = any(c in part for c in "*?[")
        for cur in frontier:
            if not cur.is_dir():
                continue
            if has_glob:
                # case-insensitive glob: match against lowercased names
                low = part.lower()
                try:
                    for child in cur.iterdir():
                        if _fnmatch_ci(child.name, low):
                            nxt.append(child)
                except (OSError, PermissionError):
                    continue
            else:
                child = _ci_child(cur, part)
                if child is not None:
                    nxt.append(child)
        frontier = nxt
        if not frontier:
            break
    return frontier


def _fnmatch_ci(name: str, pattern_lower: str) -> bool:
    import fnmatch
    return fnmatch.fnmatch(name.lower(), pattern_lower)


# ----- profile root discovery ------------------------------------------------


def discover_profile_roots(target: Path | None) -> list[ProfileRoot]:
    """Return the user AppData roots to scan.

    Live mode reads the environment. Target mode handles, in order:
      1. ``target`` already IS an AppData folder (has Local/ and Roaming/);
      2. ``target`` is a user profile folder (contains AppData/);
      3. ``target`` contains a ``Users`` directory → enumerate each user;
      4. fallback: search a few levels down for ``AppData/Local`` folders.
    """
    if target is None:
        la = os.environ.get("LOCALAPPDATA")
        ra = os.environ.get("APPDATA")
        return [ProfileRoot(
            user="<live>",
            local_appdata=Path(la) if la else None,
            roaming_appdata=Path(ra) if ra else None,
        )]

    target = target.expanduser()
    if not target.exists():
        raise FileNotFoundError(f"target path does not exist: {target}")

    roots: list[ProfileRoot] = []

    # Case 1: target is an AppData folder itself.
    local = _ci_child(target, "Local")
    roaming = _ci_child(target, "Roaming")
    if local or roaming:
        roots.append(ProfileRoot(_user_label(target.parent), local, roaming))
        return roots

    # Case 2: target is a user profile folder (contains AppData).
    appdata = _ci_child(target, "AppData")
    if appdata is not None:
        roots.append(_root_from_appdata(target.name, appdata))
        return roots

    # Case 3: target contains a Users directory.
    users = _ci_child(target, "Users")
    if users is not None:
        for udir in _iter_dirs(users):
            ad = _ci_child(udir, "AppData")
            if ad is not None:
                roots.append(_root_from_appdata(udir.name, ad))
        if roots:
            return roots

    # Case 4: fallback — search up to 6 levels for AppData/Local.
    roots = _search_appdata(target, max_depth=6)
    if not roots:
        # Last resort: treat target as both anchors so signatures can still
        # be probed against an arbitrary extraction layout.
        roots = [ProfileRoot(_user_label(target), target, target)]
    return roots


def _root_from_appdata(user: str, appdata: Path) -> ProfileRoot:
    return ProfileRoot(
        user=user,
        local_appdata=_ci_child(appdata, "Local"),
        roaming_appdata=_ci_child(appdata, "Roaming"),
    )


def _iter_dirs(parent: Path):
    try:
        for c in parent.iterdir():
            if c.is_dir():
                yield c
    except (OSError, PermissionError):
        return


def _user_label(path: Path) -> str:
    name = path.name
    return name if name else str(path)


def _search_appdata(root: Path, max_depth: int) -> list[ProfileRoot]:
    """BFS for directories named ``AppData`` with a ``Local`` child."""
    found: list[ProfileRoot] = []
    seen: set[str] = set()
    frontier = [(root, 0)]
    while frontier:
        cur, depth = frontier.pop(0)
        if depth > max_depth:
            continue
        for child in _iter_dirs(cur):
            if child.name.lower() == "appdata":
                local = _ci_child(child, "Local")
                if local is not None:
                    key = str(local).lower()
                    if key not in seen:
                        seen.add(key)
                        found.append(_root_from_appdata(child.parent.name, child))
            else:
                frontier.append((child, depth + 1))
    return found
