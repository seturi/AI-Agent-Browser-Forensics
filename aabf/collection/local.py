"""Local artifact-based collection (paper Section 5.3.1).

Secures the on-disk agent artifacts identified by the identification module into
a hashed evidence store with a chain-of-custody manifest. LevelDB stores are
copied whole (so they stay parseable); SQLite DBs, logs, and JSON are copied by
filename match. Provenance is preserved by mirroring the original path layout.

This route also harvests the residual authentication tokens that cloud-centric
services leave locally — those become the pivot recorded in ``pending_api`` for
the (separate) API-reconstruction module.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

from ..models import Category, Detection, ServiceType
from .base import (
    CollectedArtifact,
    CollectedFile,
    CollectionResult,
    PendingApi,
    copy_with_hash,
    evidence_relpath,
    file_mtime_iso,
    long_path,
    utcnow_iso,
)

# Agent-artifact content categories tracked for the API hand-off.
_CONTENT_CATEGORIES = ("Account", "Prompt", "Workflow", "Output")
_LOCALLY_AVAILABLE = {"local", "both"}


@dataclass
class _SourceGroup:
    """Deduplicated collection task: one physical source, possibly backing
    several artifact categories."""

    browser: str
    browser_key: str
    user: str
    source_path: str
    is_leveldb: bool
    categories: set[str]
    presences: set[str]
    storages: list[str]
    globs: set[str]


def collect_local(
    detections: list[Detection],
    output: Path,
    *,
    target: str | None,
) -> CollectionResult:
    """Collect locally-available artifacts for every detection into ``output``."""
    started = utcnow_iso()
    output = output.expanduser()
    artifacts_root = output / "artifacts"

    groups = _gather_groups(detections)

    collected: list[CollectedArtifact] = []
    for g in groups.values():
        collected.append(_collect_group(g, artifacts_root))

    pending = _build_pending_api(detections, collected)

    result = CollectionResult(
        output_dir=str(output),
        target=target or "<live system>",
        started_at=started,
        finished_at=utcnow_iso(),
        artifacts=collected,
        pending_api=pending,
    )
    return result


# ----- grouping --------------------------------------------------------------


def _gather_groups(detections: list[Detection]) -> dict[tuple, _SourceGroup]:
    groups: dict[tuple, _SourceGroup] = {}
    for det in detections:
        for hit in det.artifact_hits:
            if not hit.exists:
                continue
            src = hit.resolved_path
            key = (det.signature.key, det.profile_user, src)
            g = groups.get(key)
            if g is None:
                g = _SourceGroup(
                    browser=det.signature.name,
                    browser_key=det.signature.key,
                    user=det.profile_user,
                    source_path=src,
                    is_leveldb=_is_leveldb_dir(Path(src)),
                    categories=set(),
                    presences=set(),
                    storages=[],
                    globs=set(),
                )
                groups[key] = g
            g.categories.add(hit.spec.category.value)
            g.presences.add(hit.spec.presence.value)
            if hit.spec.storage not in g.storages:
                g.storages.append(hit.spec.storage)
            for glob in hit.spec.filename_glob.split(";"):
                if glob:
                    g.globs.add(glob)
    return groups


# ----- copying ---------------------------------------------------------------


def _collect_group(g: _SourceGroup, artifacts_root: Path) -> CollectedArtifact:
    art = CollectedArtifact(
        browser=g.browser,
        browser_key=g.browser_key,
        user=g.user,
        categories=sorted(g.categories),
        storage="; ".join(g.storages),
        presence=",".join(sorted(g.presences)),
        source_path=g.source_path,
        is_leveldb=g.is_leveldb,
    )
    src = Path(g.source_path)
    try:
        files = _enumerate_sources(src, g.is_leveldb, sorted(g.globs))
        dest_root = artifacts_root / g.browser_key
        for f in files:
            art.files.append(_copy_one(f, dest_root))
    except (OSError, PermissionError) as exc:
        art.error = f"{type(exc).__name__}: {exc}"
    return art


def _copy_one(src_file: Path, dest_root: Path) -> CollectedFile:
    dest = dest_root / evidence_relpath(src_file)
    size, digest = copy_with_hash(src_file, dest)
    return CollectedFile(
        source=str(src_file),
        dest=str(dest.relative_to(dest_root.parent.parent)),
        size=size,
        sha256=digest,
        mtime=file_mtime_iso(src_file),
    )


def _enumerate_sources(src: Path, is_leveldb: bool, globs: list[str]) -> list[Path]:
    """Return the concrete files to copy for a source.

    * file              -> itself
    * LevelDB directory -> the whole tree
    * other directory   -> entries matching the globs; a matched subdirectory
      (e.g. an IndexedDB *.leveldb store) is itself copied recursively
    """
    if src.is_file():
        return [src]
    if not src.is_dir():
        return []
    if is_leveldb:
        return _walk_files(src)

    out: list[Path] = []
    try:
        entries = list(src.iterdir())
    except (OSError, PermissionError):
        return []
    for entry in entries:
        if not _matches_any(entry.name, globs):
            continue
        if entry.is_dir():
            out.extend(_walk_files(entry))     # nested store (e.g. *.leveldb)
        else:
            out.append(entry)
    return out


def _walk_files(root: Path) -> list[Path]:
    out: list[Path] = []
    stack = [root]
    while stack:
        cur = stack.pop()
        try:
            for child in cur.iterdir():
                if child.is_dir():
                    stack.append(child)
                elif child.is_file():
                    out.append(child)
        except (OSError, PermissionError):
            continue
    return out


def _matches_any(name: str, globs: list[str]) -> bool:
    low = name.lower()
    return any(fnmatch.fnmatch(low, g.lower()) for g in globs)


_LEVELDB_MARKERS = ("current", "log")  # CURRENT file; *.log / *.ldb members


def _is_leveldb_dir(path: Path) -> bool:
    if not path.is_dir():
        return False
    if path.name.lower().endswith("leveldb"):
        return True
    try:
        for child in path.iterdir():
            n = child.name.lower()
            if n == "current" or n.endswith(".ldb") or n.endswith(".log"):
                return True
    except (OSError, PermissionError):
        return False
    return False


# ----- API hand-off ----------------------------------------------------------


def _build_pending_api(
    detections: list[Detection], collected: list[CollectedArtifact]
) -> list[PendingApi]:
    pending: list[PendingApi] = []
    for det in detections:
        sig = det.signature
        if sig.service_type is ServiceType.LOCAL:
            continue  # fully recoverable from disk

        server_cats = _server_side_categories(det)
        if not server_cats:
            continue

        cred_sources = [
            a.source_path
            for a in collected
            if a.browser_key == sig.key
            and a.user == det.profile_user
            and Category.AUTH.value in a.categories
        ]
        pending.append(PendingApi(
            browser=sig.name,
            browser_key=sig.key,
            user=det.profile_user,
            service_type=sig.service_type.value,
            server_side_categories=server_cats,
            credential_sources=cred_sources,
            endpoints=[
                {"path": e.path, "method": e.method, "yields": e.yields,
                 "auth": e.auth, "order": e.order}
                for e in sorted(sig.endpoints, key=lambda x: x.order)
            ],
        ))
    return pending


def _server_side_categories(det: Detection) -> list[str]:
    """Content categories not recoverable from local disk for this detection."""
    locally: set[str] = set()
    for hit in det.artifact_hits:
        if hit.exists and hit.spec.presence.value in _LOCALLY_AVAILABLE:
            locally.add(hit.spec.category.value)
    return [c for c in _CONTENT_CATEGORIES if c not in locally]
