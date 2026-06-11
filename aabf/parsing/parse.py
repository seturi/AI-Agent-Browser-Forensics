"""Parsing dispatcher.

Consumes a collection manifest (the evidence store) and routes each detection's
collected artifacts to its service parser, returning normalized records.
"""

from __future__ import annotations

import json
from pathlib import Path

from .records import ParseResult
from .services.base import BaseServiceParser, profile_of
from .services.browseros import BrowserosParser
from .services.comet import CometParser
from .services.edge import EdgeParser
from .services.fellou import FellouParser
from .services.genspark import GensparkParser
from .services.sigma import SigmaParser

# Registry: signature key -> parser instance.
_PARSERS: dict[str, BaseServiceParser] = {
    p.key: p for p in (
        CometParser(),
        FellouParser(),
        EdgeParser(),
        BrowserosParser(),
        SigmaParser(),
        GensparkParser(),
    )
}


def get_parser(key: str) -> BaseServiceParser | None:
    return _PARSERS.get(key)


def _parse_grouped(artifacts: list[dict], evidence_root: Path) -> list[ParseResult]:
    grouped: dict[tuple[str, str], list[dict]] = {}
    for art in artifacts:
        grouped.setdefault((art["browser_key"], art["user"]), []).append(art)

    results: list[ParseResult] = []
    for (key, user), arts in grouped.items():
        parser = _PARSERS.get(key)
        if parser is None:
            continue
        result = parser.parse(user=user, artifacts=arts, evidence_root=evidence_root)
        for r in result.records:          # tag each record with its profile
            if r.profile is None:
                r.profile = profile_of(r.source)
        results.append(result)
    return results


def parse_manifest(manifest_path: Path) -> list[ParseResult]:
    """Parse every collected detection described by a collection manifest.json.

    Groups manifest artifacts by (browser_key, user) and runs the matching
    service parser. Unknown keys are skipped.
    """
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    evidence_root = Path(manifest_path).parent
    return _parse_grouped(manifest.get("artifacts", []), evidence_root)


def parse_collection(result) -> list[ParseResult]:
    """Parse a :class:`~aabf.collection.base.CollectionResult` in memory (no
    manifest file needed) — convenient for the collect→parse pipeline/tests."""
    artifacts = [a.to_dict() for a in result.artifacts]
    return _parse_grouped(artifacts, Path(result.output_dir))
