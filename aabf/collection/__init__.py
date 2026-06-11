"""Collection module (paper Section 5.3).

Two collection routes, kept deliberately separate:

* :mod:`aabf.collection.local` — local artifact-based collection. Secures the
  on-disk agent artifacts (LevelDB stores, SQLite DBs, logs, JSON) in a
  recoverable, hashed form with a chain-of-custody manifest. Applies to
  local-centric and hybrid services, and also harvests the residual
  authentication tokens that cloud-centric services leave locally.

* :mod:`aabf.collection.api` — API-reconstruction-based remote collection.
  Extracts a residual token, (DPAPI-)decrypts it, and replays the service API to
  pull server-side conversation bodies. **Stub for now** — interface defined,
  implementation deferred.

The integrated analysis module consumes the outputs of both.
"""

from .base import (
    CollectedArtifact,
    CollectedFile,
    CollectionResult,
    PendingApi,
)
from .local import collect_local

__all__ = [
    "CollectedArtifact",
    "CollectedFile",
    "CollectionResult",
    "PendingApi",
    "collect_local",
]
