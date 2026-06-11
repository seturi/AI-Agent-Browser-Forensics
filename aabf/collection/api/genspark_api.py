"""Genspark (MainFunc) API reconstruction.

Token : the 'session_id' cookie IS the auth token (value '<user_uuid>:<token>');
        sent as a cookie, not Bearer. It is in the Cookies SQLite
        (DPAPI/AES-GCM encrypted on disk) so it must be decrypted or supplied.
        (Cloudflare cf_clearance/__cf_bm may also be required to pass the WAF.)
Host  : https://www.genspark.ai
Flow  : /api/user (account/subscription) ->
        /api/project/my?from=agents (ALL projects: session_clean_text = full
        per-round flow: prompt + workflow + output) in one call.
Ref   : FYI/network/genspark_api.py.
"""

from __future__ import annotations

from .base import BaseApiReconstructor, RequestSpec

HOST = "https://www.genspark.ai"
COOKIE = "session_id"


class GensparkApiReconstructor(BaseApiReconstructor):
    key = "genspark"
    service_name = "Genspark Browser"
    token_strategy = "'session_id' cookie (=auth token); replay as cookie"

    def extract_token(self, pending, *, cookies=None, local_state=None, **kwargs):
        return self._decrypt_named_cookie(
            [COOKIE], cookies=cookies, local_state=local_state)

    def plan(self, token: str, *, cf_clearance: str | None = None,
             cf_bm: str | None = None, **kwargs) -> list[RequestSpec]:
        cookies = {COOKIE: token}
        if cf_clearance:
            cookies["cf_clearance"] = cf_clearance
        if cf_bm:
            cookies["__cf_bm"] = cf_bm
        return [
            RequestSpec("GET", f"{HOST}/api/user", ["Account"], "user", cookies=cookies),
            RequestSpec("GET", f"{HOST}/api/project/my", ["Prompt", "Workflow", "Output"],
                        "project_my", params={"from": "agents"}, cookies=cookies),
        ]
