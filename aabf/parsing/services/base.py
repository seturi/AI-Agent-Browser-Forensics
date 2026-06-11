"""Base class for per-service parsers, with evidence-locating helpers.

A parser receives the collection-manifest entries for one detection
(browser + user) plus the evidence root, locates the relevant stores/files in
the evidence store, reads them via :mod:`aabf.utils`, and returns normalized
:class:`~aabf.parsing.records.AgentRecord` objects.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any

from ..records import AgentRecord, ParseResult


def profile_of(path: str | None) -> str | None:
    """Extract the browser profile from an artifact path.

    Chromium: ``…/User Data/<profile>/…`` (Default, Profile 1, …).
    Fellou (Electron): ``…/Partitions/<partition>/…``.
    Returns None when the path has no profile segment (e.g. a server log).
    """
    if not path:
        return None
    parts = str(path).replace("\\", "/").split("/")
    norm = [p.lower().replace(" ", "") for p in parts]
    for i, seg in enumerate(norm):
        if seg == "userdata" and i + 1 < len(parts):
            return parts[i + 1]
    for i, seg in enumerate(norm):
        if seg == "partitions" and i + 1 < len(parts):
            return parts[i + 1]
    return None


class BaseServiceParser:
    key: str = ""
    service_name: str = ""

    def parse(self, *, user: str, artifacts: list[dict], evidence_root: Path) -> ParseResult:
        """Parse one detection's collected artifacts into records. Override."""
        return self._empty(user)

    # --- evidence location helpers ------------------------------------------

    def store_dirs(self, artifacts: list[dict], evidence_root: Path, *,
                   storage_contains: str | None = None,
                   category: str | None = None) -> list[Path]:
        """Resolve LevelDB store directories (in the evidence store) from the
        manifest entries, optionally filtered by storage label / category."""
        out: list[Path] = []
        for a in artifacts:
            if not self._match(a, storage_contains, category):
                continue
            if a.get("is_leveldb") and a.get("files"):
                d = Path(evidence_root) / Path(a["files"][0]["dest"]).parent
                if d not in out:
                    out.append(d)
        return out

    def files(self, artifacts: list[dict], evidence_root: Path, *,
              name: str | None = None, storage_contains: str | None = None,
              category: str | None = None) -> list[Path]:
        """Resolve individual files (in the evidence store), optionally filtered
        by filename glob / storage label / category."""
        out: list[Path] = []
        for a in artifacts:
            if not self._match(a, storage_contains, category):
                continue
            for f in a.get("files", []):
                p = Path(evidence_root) / f["dest"]
                if name and not fnmatch.fnmatch(p.name.lower(), name.lower()):
                    continue
                if p not in out:
                    out.append(p)
        return out

    @staticmethod
    def _match(artifact: dict, storage_contains: str | None,
               category: str | None) -> bool:
        if storage_contains and storage_contains.lower() not in artifact.get("storage", "").lower():
            return False
        if category and category not in artifact.get("categories", []):
            return False
        return True

    # --- record construction -------------------------------------------------

    def _empty(self, user: str) -> ParseResult:
        return ParseResult(browser_key=self.key, user=user)

    def _record(self, user: str, category: str, source: str, **kw: Any) -> AgentRecord:
        return AgentRecord(browser_key=self.key, user=user,
                           category=category, source=source, **kw)

    # category for residual local traces (browsing/navigation/config/scheduled
    # tasks) that persist even when not logged in — kept OUT of the four agent
    # artifact categories so coverage stays honest; tagged with a ``kind``.
    RESIDUAL = "Residual"

    def _residual(self, user: str, source: str, kind: str, content: Any = None, *,
                  timestamp: Any = None, conversation_id: str | None = None,
                  **extra: Any) -> AgentRecord:
        fields = {"kind": kind, "residual": True}
        fields.update({k: v for k, v in extra.items() if v is not None})
        return AgentRecord(
            browser_key=self.key, user=user, category=self.RESIDUAL, source=source,
            content=(str(content) if content is not None else None),
            timestamp=timestamp, conversation_id=conversation_id, fields=fields)
