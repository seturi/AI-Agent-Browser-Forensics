"""Microsoft Edge (Copilot) API reconstruction.

Token : MSAL Bearer (JWE). Stored in Local Storage as DPAPI-encrypted msal.2.*
        entries, so it must be decrypted or supplied explicitly.
Host  : https://copilot.microsoft.com
Flow  : /c/api/conversations (list: conversationId/title/last time) ->
        /c/api/conversations/{conversationId}/history (body: prompts, responses,
        author human/ai, time, citations).
Ref   : FYI/network/edge_api.py.
"""

from __future__ import annotations

from .base import BaseApiReconstructor, RequestSpec

HOST = "https://copilot.microsoft.com"
HISTORY_PARAMS = {"api-version": "2", "ncedge": "1", "channel": "edge"}


class EdgeApiReconstructor(BaseApiReconstructor):
    key = "edge"
    service_name = "Microsoft Edge (Copilot)"
    token_strategy = "MSAL Bearer JWE (DPAPI-encrypted in Local Storage)"

    def plan(self, token: str, *, conversation_id: str | None = None,
             conversation_ids: list[str] | None = None, **kwargs) -> list[RequestSpec]:
        h = {"Authorization": f"Bearer {token}"}
        specs = [RequestSpec("GET", f"{HOST}/c/api/conversations",
                             ["Prompt"], "conversations", headers=h)]
        for cid in ([conversation_id] if conversation_id else []) + (conversation_ids or []):
            specs.append(RequestSpec(
                "GET", f"{HOST}/c/api/conversations/{cid}/history",
                ["Prompt", "Workflow", "Output"], f"history_{cid}",
                headers=h, params=dict(HISTORY_PARAMS)))
        return specs
