"""Shared interface for per-service API reconstruction (paper Section 5.3.2).

Cloud-/hybrid-type services keep conversation bodies server-side and leave only
a credential locally. Recovery proceeds:

    1. extract the residual token from local storage (DPAPI-decrypt if needed)
    2. determine endpoints + request format (pre-encoded per signature)
    3. replay the endpoints with the token to pull server-side data

Every service authenticates and paginates differently, so the actual logic lives
in one module per service (``<service>_api.py``), each subclassing
:class:`BaseApiReconstructor`. This module holds the base class, the result
models, and helpers they share.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...signatures import BY_KEY
from ..base import PendingApi, utcnow_iso

# A browser-like UA so requests are not trivially rejected.
DEFAULT_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/146.0.0.0 Safari/537.36"),
}


class NotImplementedYet(NotImplementedError):
    """Raised by a reconstruction step that is not implemented yet."""


class TokenUnavailable(Exception):
    """No usable token could be extracted from local artifacts (e.g. it is
    cookie/DPAPI-encrypted and decryption is deferred). Provide one explicitly."""


@dataclass
class RequestSpec:
    """A planned HTTP request (built offline, executed by :meth:`_execute`)."""

    method: str
    url: str
    categories: list[str]
    label: str = ""
    params: dict | None = None
    headers: dict | None = None
    cookies: dict | None = None
    json_body: dict | None = None

    def to_dict(self) -> dict[str, Any]:
        # never serialise secret values verbatim in the plan view
        return {"method": self.method, "url": self.url, "label": self.label,
                "params": self.params, "categories": self.categories,
                "auth": ("cookie" if self.cookies else
                         "bearer" if (self.headers or {}).get("Authorization") else "none")}


@dataclass
class ApiResponse:
    """One captured server response (raw body persisted alongside metadata)."""

    endpoint: str
    method: str
    status: int | None
    categories: list[str]
    dest: str | None = None          # path to the saved raw response
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "status": self.status,
            "categories": self.categories,
            "dest": self.dest,
            "error": self.error,
        }


@dataclass
class ApiCollectionResult:
    """Outcome of reconstructing one detection's server-side data."""

    browser: str
    browser_key: str
    user: str
    started_at: str
    finished_at: str
    token_source: str | None = None
    token_extracted: bool = False
    responses: list[ApiResponse] = field(default_factory=list)
    status: str = "not-implemented"   # not-implemented | ok | partial | error
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "browser": self.browser,
            "browser_key": self.browser_key,
            "user": self.user,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "token_source": self.token_source,
            "token_extracted": self.token_extracted,
            "status": self.status,
            "note": self.note,
            "responses": [r.to_dict() for r in self.responses],
        }


class BaseApiReconstructor:
    """Base class for a single service's API reconstruction.

    Subclasses set ``key``/``service_name``/``token_strategy`` and implement
    :meth:`extract_token` and :meth:`reconstruct`. Endpoints are read from the
    browser signature, so they stay in one place (``signatures.py``).
    """

    key: str = ""
    service_name: str = ""
    # One-line hint for the implementer: where/how the token is obtained.
    token_strategy: str = ""

    # --- to implement per service -------------------------------------------

    def extract_token(self, pending: PendingApi, *, store_dirs=None, **kwargs) -> str | None:
        """Step 1 — extract the residual token from collected local artifacts.

        Implemented where the token sits in plaintext (Local Storage / extension
        store). Where it is cookie/DPAPI-encrypted, raises :class:`TokenUnavailable`
        so the caller can supply a token explicitly.
        """
        raise TokenUnavailable(
            f"{self.key}: token is cookie/DPAPI-encrypted — pass token=… explicitly")

    def plan(self, token: str, **kwargs) -> list[RequestSpec]:
        """Step 2 — build the request specs (pure; testable offline). Override."""
        raise NotImplementedYet(f"{self.key}: request plan not implemented")

    # --- generic reconstruction flow (steps 1-3) ----------------------------

    def reconstruct(
        self, pending: PendingApi, *, output_dir=None, token: str | None = None,
        store_dirs=None, send: bool = True, **kwargs,
    ) -> ApiCollectionResult:
        """Run reconstruction: get token -> plan requests -> execute & persist.

        ``token`` may be supplied directly (e.g. a decrypted cookie); otherwise
        :meth:`extract_token` is tried. ``send=False`` returns the planned
        requests without performing any network I/O (used for offline checks).
        """
        res = self._new_result(pending)
        if token is None:
            try:
                token = self.extract_token(pending, store_dirs=store_dirs, **kwargs)
            except (TokenUnavailable, NotImplementedYet) as exc:
                res.status = "no-token"
                res.note = str(exc)
                return res
        if not token:
            res.status = "no-token"
            res.note = f"{self.key}: no token available"
            return res

        res.token_extracted = True
        try:
            specs = self.plan(token, **kwargs)
        except NotImplementedYet as exc:
            res.status = "not-implemented"
            res.note = str(exc)
            return res

        if not send:
            res.status = "planned"
            res.note = f"{len(specs)} request(s) planned: " + \
                       ", ".join(f"{s.method} {s.url}" for s in specs)
            return res

        res.responses = self._execute(specs, output_dir)
        ok = [r for r in res.responses if r.status == 200]
        res.status = "ok" if ok and len(ok) == len(res.responses) else (
            "partial" if ok else "error")
        res.finished_at = utcnow_iso()
        return res

    def _execute(self, specs: list[RequestSpec], output_dir) -> list[ApiResponse]:
        """Send each request and persist raw responses. ``requests`` is imported
        lazily so the package works without the optional [api] extra installed."""
        import requests  # noqa: PLC0415 - optional dependency

        out: list[ApiResponse] = []
        base = None
        if output_dir is not None:
            base = Path(output_dir) / "api" / self.key
            base.mkdir(parents=True, exist_ok=True)
        for sp in specs:
            try:
                resp = requests.request(
                    sp.method, sp.url, params=sp.params,
                    headers={**DEFAULT_HEADERS, **(sp.headers or {})},
                    cookies=sp.cookies, json=sp.json_body, timeout=20)
                dest = None
                if base is not None:
                    dest = str(base / f"{sp.label or _slug(sp.url)}.json")
                    Path(dest).write_text(resp.text, encoding="utf-8")
                out.append(ApiResponse(
                    sp.url, sp.method, resp.status_code, sp.categories, dest,
                    None if resp.status_code == 200 else resp.text[:200]))
            except Exception as exc:  # noqa: BLE001 - one failure shouldn't abort
                out.append(ApiResponse(sp.url, sp.method, None, sp.categories,
                                       None, f"{type(exc).__name__}: {exc}"))
        return out

    # --- helpers shared by all services -------------------------------------

    def endpoints(self):
        sig = BY_KEY.get(self.key)
        return list(sig.endpoints) if sig else []

    def _new_result(self, pending: PendingApi, **overrides) -> ApiCollectionResult:
        now = utcnow_iso()
        base = dict(
            browser=pending.browser,
            browser_key=pending.browser_key,
            user=pending.user,
            started_at=now,
            finished_at=now,
            token_source=(pending.credential_sources[0]
                          if pending.credential_sources else None),
        )
        base.update(overrides)
        return ApiCollectionResult(**base)

    @staticmethod
    def _slug(text: str) -> str:
        return _slug(text)

    def _decrypt_named_cookie(self, names, *, cookies=None, local_state=None) -> str | None:
        """Decrypt a named v10 cookie from collected Cookies + Local State.

        Loads the os_crypt master key from a collected ``Local State`` and uses
        it to AES-GCM-decrypt the first matching cookie's ``encrypted_value``.
        Returns None if the key/cookie is unavailable or decryption fails
        (e.g. non-Windows, no [decrypt] extra, or a different user account).
        """
        from ...utils import dpapi, sqlite  # lazy: optional deps / Windows-only

        key = dpapi.load_key_from_candidates(local_state)
        if key is None:
            return None
        wanted = set(names)
        for cdb in cookies or []:
            try:
                rows = sqlite.read_table(cdb, "cookies")
            except Exception:  # noqa: BLE001
                continue
            for r in rows:
                if r.get("name") in wanted and r.get("encrypted_value"):
                    try:
                        return dpapi.decrypt_cookie(bytes(r["encrypted_value"]), key)
                    except Exception:  # noqa: BLE001
                        continue
        return None

    def _not_implemented(self, pending: PendingApi) -> ApiCollectionResult:
        res = self._new_result(pending, status="not-implemented")
        eps = self.endpoints()
        strat = f" [{self.token_strategy}]" if self.token_strategy else ""
        res.note = (
            f"{self.service_name or self.key} API reconstruction not implemented "
            f"yet. Would pull {pending.server_side_categories} via {len(eps)} "
            f"endpoint(s){strat}; credential at "
            f"{pending.credential_sources or 'n/a'}."
        )
        return res


def _slug(text: str) -> str:
    """Filesystem-safe short label derived from a URL/endpoint."""
    s = re.sub(r"^https?://", "", str(text))
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")
    return (s[:80] or "response")
