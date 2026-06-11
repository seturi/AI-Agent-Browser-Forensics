"""Core data models for AABF.

These dataclasses define the static knowledge base (browser signatures and the
artifacts each browser produces) and the runtime results emitted by the
identification module. They are intentionally serialization-friendly so the
collection/parsing/analysis modules can consume the JSON report directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Anchor(str, Enum):
    """Filesystem anchor a relative artifact path is resolved against.

    Windows environment variables, generalised so paths can also be resolved
    inside a mounted forensic image where these folders live under a user
    profile (``Users/<name>/AppData/{Local,Roaming}``).
    """

    LOCAL = "local"      # %LocalAppData%  -> ...\AppData\Local
    ROAMING = "roaming"  # %AppData%       -> ...\AppData\Roaming
    TEMP = "temp"        # %LocalAppData%\Temp


class ServiceType(str, Enum):
    LOCAL = "local-centric"
    CLOUD = "cloud-centric"
    HYBRID = "hybrid"


class Category(str, Enum):
    ACCOUNT = "Account"
    PROMPT = "Prompt"
    WORKFLOW = "Workflow"
    OUTPUT = "Output"
    AUTH = "Authentication"  # tokens/session — the pivot for API reconstruction


class Presence(str, Enum):
    """Where an artifact category lives for a given service (paper Table 4)."""

    LOCAL = "local"        # present in local storage
    SERVER = "server"      # only retrievable via API reconstruction
    BOTH = "both"          # present locally and on the server
    NA = "n/a"             # not applicable (e.g. BrowserOS has no account)


@dataclass(frozen=True)
class ArtifactSpec:
    """A forensically meaningful artifact produced by a browser.

    ``relpath`` is relative to ``anchor`` and may contain a ``{profile}``
    placeholder for the Chromium profile directory (Default, Profile 1, ...).
    """

    category: Category
    anchor: Anchor
    relpath: str
    filename_glob: str           # e.g. "*.ldb", "Cookies", "user.json"
    storage: str                 # human label, e.g. "Local Storage (LevelDB)"
    info: str                    # what can be recovered here
    presence: Presence = Presence.LOCAL
    encrypted: bool = False      # e.g. DPAPI-protected
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["anchor"] = self.anchor.value
        d["presence"] = self.presence.value
        return d


@dataclass(frozen=True)
class IdentMarker:
    """A trace used to identify a browser and score detection confidence.

    ``kind`` is one of:
      - "install_dir"   : a distinctive UserData/profile directory
      - "extension"     : a fixed extension ID under LocalExtensionSettings
      - "support_dir"   : a corroborating directory (weaker signal)
    """

    kind: str
    anchor: Anchor
    relpath: str
    weight: float
    description: str = ""


@dataclass(frozen=True)
class ApiEndpoint:
    """Server endpoint used by the API-reconstruction collection module."""

    path: str
    method: str
    yields: str                  # what categories/data this returns
    auth: str                    # how the request authenticates
    order: int = 0               # reconstruction call order


@dataclass(frozen=True)
class BrowserSignature:
    """Static knowledge about one AI agent browser."""

    key: str                     # stable id, e.g. "comet"
    name: str                    # display name, e.g. "Comet"
    developer: str
    base_arch: str               # "Chromium" | "Electron"
    service_type: ServiceType
    user_data_anchor: Anchor
    user_data_relpath: str       # the UserData root, {profile} excluded
    extension_id: str | None
    markers: tuple[IdentMarker, ...]
    artifacts: tuple[ArtifactSpec, ...]
    auth_summary: str            # how authentication/session works
    endpoints: tuple[ApiEndpoint, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "developer": self.developer,
            "base_arch": self.base_arch,
            "service_type": self.service_type.value,
            "extension_id": self.extension_id,
            "auth_summary": self.auth_summary,
            "artifacts": [a.to_dict() for a in self.artifacts],
            "endpoints": [
                {**asdict(e)} for e in sorted(self.endpoints, key=lambda x: x.order)
            ],
        }


# ----- runtime results -------------------------------------------------------


@dataclass
class MarkerHit:
    marker: IdentMarker
    resolved_path: str
    exists: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.marker.kind,
            "description": self.marker.description,
            "path": self.resolved_path,
            "exists": self.exists,
            "weight": self.marker.weight,
        }


@dataclass
class ArtifactHit:
    spec: ArtifactSpec
    resolved_path: str
    exists: bool
    match_count: int = 0         # files matching filename_glob, when present

    def to_dict(self) -> dict[str, Any]:
        d = self.spec.to_dict()
        d["path"] = self.resolved_path
        d["exists"] = self.exists
        d["match_count"] = self.match_count
        return d


@dataclass
class Detection:
    """One identified browser instance within one profile root."""

    signature: BrowserSignature
    profile_user: str            # which user/profile root it was found under
    user_data_path: str
    profiles: list[str]          # detected Chromium profile dirs (Default, ...)
    confidence: float            # 0..1
    marker_hits: list[MarkerHit] = field(default_factory=list)
    artifact_hits: list[ArtifactHit] = field(default_factory=list)

    @property
    def recommended_route(self) -> str:
        st = self.signature.service_type
        if st is ServiceType.LOCAL:
            return "local-artifact-collection"
        if st is ServiceType.CLOUD:
            return "api-reconstruction"
        return "local + api-reconstruction (parallel)"

    def to_dict(self) -> dict[str, Any]:
        return {
            "browser": self.signature.name,
            "key": self.signature.key,
            "developer": self.signature.developer,
            "base_arch": self.signature.base_arch,
            "service_type": self.signature.service_type.value,
            "confidence": round(self.confidence, 3),
            "profile_user": self.profile_user,
            "user_data_path": self.user_data_path,
            "profiles": self.profiles,
            "extension_id": self.signature.extension_id,
            "recommended_route": self.recommended_route,
            "auth_summary": self.signature.auth_summary,
            "markers": [m.to_dict() for m in self.marker_hits],
            "artifacts": [a.to_dict() for a in self.artifact_hits],
        }
