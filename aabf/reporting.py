"""Shared reporting helpers used by every module's report renderer.

Per-module rendering lives in ``<module>/report.py``; the small bits they all
need (JSON writing, byte formatting, service-type colours) live here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Service-type colours, shared across module renderers.
TYPE_STYLE = {
    "local-centric": "green",
    "cloud-centric": "yellow",
    "hybrid": "cyan",
}


def write_json(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def human_bytes(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if f < 1024 or unit == "TB":
            return f"{f:.0f} {unit}" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024
    return f"{f:.1f} TB"
