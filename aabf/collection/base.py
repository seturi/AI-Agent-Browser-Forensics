"""Shared types and helpers for the collection module.

Defines the collection result model (consumed by parsing/analysis), the
chain-of-custody manifest, and forensic helpers (hashing, long-path-safe copy).
"""

from __future__ import annotations

import hashlib
import os
import platform
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_CHUNK = 1024 * 1024  # 1 MiB streaming chunk for hash + copy


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ----- result models ---------------------------------------------------------


@dataclass
class CollectedFile:
    """One physical file secured into the evidence store."""

    source: str          # absolute source path
    dest: str            # path relative to the output root
    size: int
    sha256: str
    mtime: str | None    # source mtime, ISO-8601 UTC

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CollectedArtifact:
    """One artifact source (a LevelDB store, a SQLite DB, a log, ...) and the
    file(s) copied from it. A single source may back several agent-artifact
    categories (e.g. one IndexedDB store holds Prompt+Workflow+Output)."""

    browser: str
    browser_key: str
    user: str
    categories: list[str]
    storage: str
    presence: str
    source_path: str
    is_leveldb: bool
    files: list[CollectedFile] = field(default_factory=list)
    error: str | None = None

    @property
    def bytes_total(self) -> int:
        return sum(f.size for f in self.files)

    def to_dict(self) -> dict[str, Any]:
        return {
            "browser": self.browser,
            "browser_key": self.browser_key,
            "user": self.user,
            "categories": self.categories,
            "storage": self.storage,
            "presence": self.presence,
            "source_path": self.source_path,
            "is_leveldb": self.is_leveldb,
            "file_count": len(self.files),
            "bytes_total": self.bytes_total,
            "error": self.error,
            "files": [f.to_dict() for f in self.files],
        }


@dataclass
class PendingApi:
    """A detection that needs API reconstruction to recover server-side bodies.

    This is the hand-off contract to :mod:`aabf.collection.api`: it lists the
    server-only categories, the residual token/credential files secured locally
    (the reconstruction pivot), and the candidate endpoints from the signature.
    """

    browser: str
    browser_key: str
    user: str
    service_type: str
    server_side_categories: list[str]
    credential_sources: list[str]          # local files holding tokens/cookies
    endpoints: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CollectionResult:
    output_dir: str
    target: str
    started_at: str
    finished_at: str
    artifacts: list[CollectedArtifact] = field(default_factory=list)
    pending_api: list[PendingApi] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        files = sum(len(a.files) for a in self.artifacts)
        byts = sum(a.bytes_total for a in self.artifacts)
        errors = [a for a in self.artifacts if a.error]
        per_browser: dict[str, dict[str, Any]] = {}
        for a in self.artifacts:
            b = per_browser.setdefault(
                a.browser, {"sources": 0, "files": 0, "bytes": 0, "categories": set()})
            b["sources"] += 1
            b["files"] += len(a.files)
            b["bytes"] += a.bytes_total
            b["categories"].update(a.categories)
        for b in per_browser.values():
            b["categories"] = sorted(b["categories"])
        return {
            "sources": len(self.artifacts),
            "files": files,
            "bytes": byts,
            "errors": len(errors),
            "pending_api": len(self.pending_api),
            "per_browser": per_browser,
        }

    def chain_of_custody(self) -> dict[str, Any]:
        return {
            "tool": "aabf",
            "module": "collection.local",
            "operator": os.environ.get("USERNAME") or os.environ.get("USER") or "unknown",
            "host": platform.node(),
            "platform": platform.platform(),
            "command": " ".join(sys.argv),
            "target": self.target,
            "output_dir": self.output_dir,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }

    def to_manifest(self) -> dict[str, Any]:
        from .. import __version__
        return {
            "version": __version__,
            "chain_of_custody": self.chain_of_custody(),
            "summary": self.summary(),
            "pending_api": [p.to_dict() for p in self.pending_api],
            "artifacts": [a.to_dict() for a in self.artifacts],
        }


# ----- forensic helpers ------------------------------------------------------


def long_path(p: Path) -> str:
    """Return a Windows extended-length path (\\\\?\\) so copies survive the
    260-char MAX_PATH limit for deeply nested LevelDB stores. No-op elsewhere."""
    if os.name != "nt":
        return str(p)
    s = os.path.abspath(str(p))
    if s.startswith("\\\\?\\"):
        return s
    if s.startswith("\\\\"):  # UNC path
        return "\\\\?\\UNC\\" + s[2:]
    return "\\\\?\\" + s


def copy_with_hash(src: Path, dst: Path) -> tuple[int, str]:
    """Stream-copy ``src`` to ``dst``, returning (size, sha256). Single pass."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    size = 0
    with open(long_path(src), "rb") as fin, open(long_path(dst), "wb") as fout:
        while True:
            chunk = fin.read(_CHUNK)
            if not chunk:
                break
            fout.write(chunk)
            h.update(chunk)
            size += len(chunk)
    return size, h.hexdigest()


def file_mtime_iso(p: Path) -> str | None:
    try:
        ts = os.stat(long_path(p)).st_mtime
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except OSError:
        return None


def evidence_relpath(source: Path) -> Path:
    """Provenance-preserving destination (relative) for a source file.

    Strips the drive/UNC root so ``C:\\Users\\x\\AppData\\...`` becomes
    ``Users/x/AppData/...`` — keeps the user and full path, avoids collisions.
    """
    src = Path(os.path.abspath(str(source)))
    parts = list(src.parts)
    if parts and (parts[0].endswith(":\\") or parts[0].endswith(":")):
        parts = parts[1:]                       # drop "C:\"
    elif src.drive:
        parts = list(src.relative_to(src.anchor).parts)
    cleaned = [p for p in parts if p not in ("\\", "/", "")]
    return Path(*cleaned) if cleaned else Path(src.name)
