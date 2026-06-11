"""Comet (Perplexity) API reconstruction.

Token : NextAuth JWE session cookie '__Secure-next-auth.session-token'. It lives
        in the Cookies SQLite (DPAPI/AES-GCM encrypted on disk), so it must be
        decrypted or supplied explicitly (decryption is a later step).
Host  : https://www.perplexity.ai
Flow  : /rest/thread/list_recent (conversation list: title/url_slug/uuid) ->
        /rest/thread/{slug} (full body: prompt/workflow/output/model + account).
Ref   : FYI/network/comet_api.py.
"""

from __future__ import annotations

from .base import BaseApiReconstructor, RequestSpec

HOST = "https://www.perplexity.ai"
COOKIE = "__Secure-next-auth.session-token"


class CometApiReconstructor(BaseApiReconstructor):
    key = "comet"
    service_name = "Comet"
    token_strategy = "JWE session cookie '__Secure-next-auth.session-token' (DPAPI)"

    def extract_token(self, pending, *, cookies=None, local_state=None, **kwargs):
        return self._decrypt_named_cookie(
            [COOKIE], cookies=cookies, local_state=local_state)

    def plan(self, token: str, *, slug: str | None = None,
             slugs: list[str] | None = None, cf_clearance: str | None = None,
             **kwargs) -> list[RequestSpec]:
        cookies = {COOKIE: token}
        if cf_clearance:
            cookies["cf_clearance"] = cf_clearance
        specs = [RequestSpec("GET", f"{HOST}/rest/thread/list_recent",
                             ["Prompt"], "list_recent", cookies=cookies)]
        for s in ([slug] if slug else []) + (slugs or []):
            specs.append(RequestSpec(
                "GET", f"{HOST}/rest/thread/{s}",
                ["Account", "Prompt", "Workflow", "Output"],
                f"thread_{s}", cookies=cookies))
        return specs
