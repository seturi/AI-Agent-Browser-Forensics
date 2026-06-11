"""Output location management.

All run outputs (collected artifacts, manifest, reports) are written under a
per-run case directory:

    %USERPROFILE%\\Documents\\AABF\\case_{YYYYmmdd_HHMMSS}\\
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path


def aabf_root() -> Path:
    """The AABF output root: %USERPROFILE%\\Documents\\AABF."""
    home = os.environ.get("USERPROFILE") or str(Path.home())
    return Path(home) / "Documents" / "AABF"


def new_case_dir(base: Path | None = None, *,
                 when: datetime | None = None) -> Path:
    """Create and return a ``case_{timestamp}`` directory.

    ``base`` overrides the location (e.g. an explicit ``-O`` path); when given it
    is used as the case directory directly (no AABF/case_ wrapping).
    """
    if base is not None:
        case = Path(base)
    else:
        ts = (when or datetime.now()).strftime("%Y%m%d_%H%M%S")
        case = aabf_root() / f"case_{ts}"
    case.mkdir(parents=True, exist_ok=True)
    return case
