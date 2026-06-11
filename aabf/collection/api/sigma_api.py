"""Sigma Browser API reconstruction.

Token : JWT access_token — plaintext in Local Storage 'search-storage'.state or
        the extension's chrome.storage.local 'socketAuth'. Sent as Bearer.
Host  : https://bagoodex.io
Flow  : /api/v1/account/profile (account) ->
        /api/v1/account/thread/history/{user_id} (task list + search_hash) ->
        /api/v1/search (POST body search_hash) for the workflow log.
Ref   : FYI/network/sigma_api.py.
"""

from __future__ import annotations

import json

from ...utils import extstore, localstorage
from ..base import PendingApi
from .base import BaseApiReconstructor, RequestSpec

HOST = "https://bagoodex.io"
SIGMA_ORIGIN = "https://app.sigmabrowser.com"
AGENT_EXT = "amabiocpfnlgbceffljgkcjeacejflga"


class SigmaApiReconstructor(BaseApiReconstructor):
    key = "sigma"
    service_name = "Sigma Browser"
    token_strategy = "JWT access_token from Local Storage 'search-storage' (Bearer)"

    def extract_token(self, pending: PendingApi, *, store_dirs=None, **kwargs):
        for d in store_dirs or []:
            ss = localstorage.get(d, "search-storage", SIGMA_ORIGIN) or \
                localstorage.get(d, "search-storage")
            if ss:
                tok = self.token_from_search_storage(
                    json.loads(ss) if isinstance(ss, str) else ss)
                if tok:
                    return tok
            try:
                store = extstore.read_store(d)
                tok = self.token_from_extstore(store.live)
                if tok:
                    return tok
            except Exception:  # noqa: BLE001 - not an ext store; ignore
                pass
        return None

    def token_from_search_storage(self, ss: dict) -> str | None:
        state = ss.get("state", ss) if isinstance(ss, dict) else {}
        return state.get("access_token") if isinstance(state, dict) else None

    def token_from_extstore(self, live: dict) -> str | None:
        sa = live.get("socketAuth")
        return sa.get("token") if isinstance(sa, dict) else None

    def plan(self, token: str, *, user_id: str | None = None,
             search_hash: str | None = None, **kwargs) -> list[RequestSpec]:
        h = {"Authorization": f"Bearer {token}", "Content-Type": "application/json",
             "Accept": "*/*"}
        specs = [RequestSpec("GET", f"{HOST}/api/v1/account/profile",
                             ["Account"], "profile", headers=h)]
        if user_id:
            specs.append(RequestSpec(
                "GET", f"{HOST}/api/v1/account/thread/history/{user_id}",
                ["Prompt"], f"thread_history_{user_id}", headers=h))
        if search_hash:
            specs.append(RequestSpec(
                "POST", f"{HOST}/api/v1/search", ["Workflow", "Output"],
                "search", headers=h, json_body={"search_hash": search_hash}))
        return specs
