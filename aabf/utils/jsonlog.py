"""JSON and plain-text log readers (stdlib) — functional.

For Fellou *.json (user.json, currentUser.json, ...), BrowserOS
gemini-client-error-*.json, and line-oriented logs (browseros-server.log).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator


def read_json(path: Path) -> Any:
    """Parse a JSON file (utf-8, BOM-tolerant). Raises on malformed JSON."""
    text = path.read_text(encoding="utf-8-sig")
    return json.loads(text)


def read_json_safe(path: Path) -> Any | None:
    """Like :func:`read_json` but returns None on any read/parse error."""
    try:
        return read_json(path)
    except (OSError, ValueError):
        return None


def iter_lines(path: Path) -> Iterator[str]:
    """Yield log lines (utf-8, errors replaced), stripped of trailing newline."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line.rstrip("\n")


def iter_jsonl(path: Path) -> Iterator[Any]:
    """Yield one parsed object per line for JSON-lines logs; skips bad lines."""
    for line in iter_lines(path):
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except ValueError:
            continue
