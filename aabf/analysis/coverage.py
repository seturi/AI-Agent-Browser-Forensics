"""Artifact coverage: for every identified service, the status of all four
agent-artifact categories (Account / Prompt / Workflow / Output).

Even when a service has no recovered conversation (e.g. not logged in), its
residual local stores are reported, and categories that could not be confirmed
are marked explicitly (present-but-unparsed / server-only / absent / n/a).
Combines the identification module's per-category artifact presence with the
parsing module's recovered record counts.
"""

from __future__ import annotations

from collections import Counter

from ..models import Detection, ServiceType
from ..parsing.records import ParseResult
from ..signatures import BY_KEY
from .models import CategoryStatus, ServiceCoverage

CATEGORIES = ("Account", "Prompt", "Workflow", "Output")
_LOCALLY_AVAILABLE = {"local", "both"}


def build_coverage(parse_results: list[ParseResult],
                   detections: list[Detection] | None = None) -> list[ServiceCoverage]:
    counts = _record_counts(parse_results)

    if detections:
        return [_from_detection(d, counts) for d in detections]
    # Fallback (e.g. --manifest, no detections): signature + records only.
    out = []
    for pr in parse_results:
        sig = BY_KEY.get(pr.browser_key)
        if sig:
            out.append(_from_signature(sig, pr.user, counts))
    return out


def _record_counts(parse_results: list[ParseResult]) -> Counter:
    c: Counter = Counter()
    for pr in parse_results:
        for r in pr.records:
            c[(pr.browser_key, r.user, r.category)] += 1
    return c


def _from_detection(det: Detection, counts: Counter) -> ServiceCoverage:
    sig = det.signature
    user = det.profile_user
    cats: dict[str, CategoryStatus] = {}
    for cat in CATEGORIES:
        specs = [a for a in sig.artifacts if a.category.value == cat]
        hits = [h for h in det.artifact_hits if h.spec.category.value == cat]
        local_present = any(
            h.exists and h.spec.presence.value in _LOCALLY_AVAILABLE for h in hits)
        server_side = _server_side(cat, specs, sig.service_type, local_present)
        rec = counts.get((sig.key, user, cat), 0)
        paths = [h.resolved_path for h in hits if h.exists]
        cats[cat] = CategoryStatus(
            category=cat,
            status=_status(rec, local_present, server_side, bool(specs)),
            local_present=local_present, server_side=server_side,
            record_count=rec, paths=paths)
    return ServiceCoverage(sig.key, sig.name, sig.service_type.value, user, cats)


def _from_signature(sig, user: str, counts: Counter) -> ServiceCoverage:
    cats: dict[str, CategoryStatus] = {}
    for cat in CATEGORIES:
        specs = [a for a in sig.artifacts if a.category.value == cat]
        rec = counts.get((sig.key, user, cat), 0)
        server_side = _server_side(cat, specs, sig.service_type, False)
        # no detection => can't tell present vs absent; recovered or server, else unknown
        if rec > 0:
            status = "recovered"
        elif server_side:
            status = "server"
        elif specs:
            status = "present"   # store was collected (manifest), parse empty
        else:
            status = "n/a"
        cats[cat] = CategoryStatus(cat, status, False, server_side, rec, [])
    return ServiceCoverage(sig.key, sig.name, sig.service_type.value, user, cats)


def _server_side(cat: str, specs, service_type: ServiceType, local_present: bool) -> bool:
    # explicit server/both presence on a local spec, or — for cloud/hybrid — a
    # content category with no local spec at all (body lives only on the server)
    if any(s.presence.value in ("server", "both") for s in specs):
        return True
    if not specs and cat in ("Prompt", "Workflow", "Output") \
            and service_type in (ServiceType.CLOUD, ServiceType.HYBRID):
        return True
    return False


def _status(rec: int, local_present: bool, server_side: bool, has_spec: bool) -> str:
    if rec > 0:
        return "recovered"
    if local_present:
        return "present"      # residual store exists but nothing parsed
    if server_side:
        return "server"
    if has_spec:
        return "absent"       # expected locally, not found
    return "n/a"
