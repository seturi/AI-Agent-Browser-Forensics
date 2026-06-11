"""API-reconstruction-based remote collection (paper Section 5.3.2).

One reconstructor per service lives in ``<service>_api.py`` and subclasses
:class:`~aabf.collection.api.base.BaseApiReconstructor`. This package wires them
into a registry and exposes a dispatcher that the collection module / CLI calls
with the ``PendingApi`` hand-off produced by the local route.

Currently every reconstructor is a STUB (no network/crypto). Implement them
service by service; the dispatch and result plumbing are already in place.
"""

from __future__ import annotations

from ..base import PendingApi
from .base import (
    ApiCollectionResult,
    ApiResponse,
    BaseApiReconstructor,
    NotImplementedYet,
)
from .browseros_api import BrowserosApiReconstructor
from .comet_api import CometApiReconstructor
from .edge_api import EdgeApiReconstructor
from .fellou_api import FellouApiReconstructor
from .genspark_api import GensparkApiReconstructor
from .sigma_api import SigmaApiReconstructor

# Registry: signature key -> reconstructor instance.
_RECONSTRUCTORS: dict[str, BaseApiReconstructor] = {
    r.key: r for r in (
        CometApiReconstructor(),
        FellouApiReconstructor(),
        EdgeApiReconstructor(),
        BrowserosApiReconstructor(),
        SigmaApiReconstructor(),
        GensparkApiReconstructor(),
    )
}


def get_reconstructor(key: str) -> BaseApiReconstructor | None:
    """Return the reconstructor for a signature key, or None if unknown."""
    return _RECONSTRUCTORS.get(key)


def reconstruct(pending: PendingApi, **kwargs) -> ApiCollectionResult:
    """Dispatch one ``PendingApi`` to its service reconstructor."""
    rec = _RECONSTRUCTORS.get(pending.browser_key)
    if rec is None:
        res = BaseApiReconstructor()._new_result(pending, status="unsupported")
        res.note = f"No API reconstructor registered for '{pending.browser_key}'."
        return res
    return rec.reconstruct(pending, **kwargs)


def reconstruct_all(pendings: list[PendingApi], **kwargs) -> list[ApiCollectionResult]:
    """Dispatch every pending detection; returns one result each."""
    return [reconstruct(p, **kwargs) for p in pendings]


__all__ = [
    "ApiCollectionResult",
    "ApiResponse",
    "BaseApiReconstructor",
    "NotImplementedYet",
    "get_reconstructor",
    "reconstruct",
    "reconstruct_all",
    "_RECONSTRUCTORS",
]
