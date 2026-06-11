"""Identification & classification module (paper Section 5.2).

Given a live system or a forensic image/folder, this module:

1. **Identifies** which AI agent browsers are present, from local traces —
   installation/UserData directories, profile and extension-storage structure,
   and fixed extension IDs.
2. **Classifies** each detected browser into a service type (local-centric /
   cloud-centric / hybrid), which dictates the collection route the next module
   should take.
3. Resolves and existence-checks the expected agent artifacts so the collection
   module receives concrete paths.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

from ..models import (
    ArtifactHit,
    BrowserSignature,
    Detection,
    IdentMarker,
    MarkerHit,
)
from ..paths import ProfileRoot, discover_profile_roots, expand_relpath
from ..signatures import SIGNATURES

# A detection below this score is discarded (e.g. a stray directory name).
DEFAULT_MIN_CONFIDENCE = 0.35


def identify(
    target: Path | None,
    *,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    only: list[str] | None = None,
    probe_artifacts: bool = True,
) -> list[Detection]:
    """Scan ``target`` (or the live system) and return detections.

    ``only`` restricts the scan to the given signature keys.
    """
    roots = discover_profile_roots(target)
    signatures = [s for s in SIGNATURES if not only or s.key in only]

    detections: list[Detection] = []
    for root in roots:
        for sig in signatures:
            det = _detect_one(sig, root, probe_artifacts=probe_artifacts)
            if det is not None and det.confidence >= min_confidence:
                detections.append(det)

    detections.sort(key=lambda d: (-d.confidence, d.signature.name))
    return detections


def _detect_one(
    sig: BrowserSignature, root: ProfileRoot, *, probe_artifacts: bool
) -> Detection | None:
    marker_hits = [_eval_marker(m, root) for m in sig.markers]
    matched_weight = sum(h.marker.weight for h in marker_hits if h.exists)
    total_weight = sum(m.weight for m in sig.markers) or 1.0
    confidence = matched_weight / total_weight

    if matched_weight == 0:
        return None

    user_data_paths = expand_relpath(
        _base_or_root(root, sig.user_data_anchor), sig.user_data_relpath
    )
    user_data_path = str(user_data_paths[0]) if user_data_paths else ""
    profiles = _detect_profiles(user_data_paths)

    artifact_hits: list[ArtifactHit] = []
    if probe_artifacts:
        for spec in sig.artifacts:
            artifact_hits.extend(_eval_artifact(spec, root))

    return Detection(
        signature=sig,
        profile_user=root.user,
        user_data_path=user_data_path,
        profiles=profiles,
        confidence=confidence,
        marker_hits=marker_hits,
        artifact_hits=artifact_hits,
    )


def _base_or_root(root: ProfileRoot, anchor) -> Path:
    base = root.anchor_base(anchor)
    return base if base is not None else Path("/nonexistent-anchor")


def _eval_marker(marker: IdentMarker, root: ProfileRoot) -> MarkerHit:
    base = root.anchor_base(marker.anchor)
    if base is None:
        return MarkerHit(marker, f"<{marker.anchor.value} anchor not found>", False)
    matches = expand_relpath(base, marker.relpath)
    if matches:
        return MarkerHit(marker, str(matches[0]), True)
    # Show the would-be path for the report even when absent.
    shown = str(base / marker.relpath.replace("{profile}", "*"))
    return MarkerHit(marker, shown, False)


def _eval_artifact(spec, root: ProfileRoot) -> list[ArtifactHit]:
    base = root.anchor_base(spec.anchor)
    if base is None:
        return [ArtifactHit(spec, f"<{spec.anchor.value} anchor not found>", False, 0)]

    dirs = expand_relpath(base, spec.relpath)
    if not dirs:
        shown = str(base / spec.relpath.replace("{profile}", "*"))
        return [ArtifactHit(spec, shown, False, 0)]

    globs = [g for g in spec.filename_glob.split(";") if g]
    hits: list[ArtifactHit] = []
    for d in dirs:
        count = _count_matches(d, globs)
        hits.append(ArtifactHit(spec, str(d), count > 0 or d.is_file(), count))
    return hits


def _count_matches(directory: Path, globs: list[str]) -> int:
    if directory.is_file():
        return 1
    if not directory.is_dir():
        return 0
    count = 0
    try:
        names = [c.name for c in directory.iterdir()]
    except (OSError, PermissionError):
        return 0
    for name in names:
        for g in globs:
            if fnmatch.fnmatch(name.lower(), g.lower()):
                count += 1
                break
    return count


# Chromium profile directories typically contain one of these markers.
_PROFILE_MARKERS = ("Local Storage", "Network", "Preferences", "IndexedDB")


def _detect_profiles(user_data_paths: list[Path]) -> list[str]:
    profiles: list[str] = []
    for ud in user_data_paths:
        if not ud.is_dir():
            continue
        try:
            children = list(ud.iterdir())
        except (OSError, PermissionError):
            continue
        for child in children:
            if not child.is_dir():
                continue
            if child.name in profiles:
                continue
            if _looks_like_profile(child):
                profiles.append(child.name)
    return profiles


def _looks_like_profile(path: Path) -> bool:
    name = path.name
    if name in ("Default", "Guest Profile", "System Profile"):
        return True
    if name.lower().startswith("profile "):
        return True
    try:
        existing = {c.name for c in path.iterdir()}
    except (OSError, PermissionError):
        return False
    return any(m in existing for m in _PROFILE_MARKERS)
