"""BrowserOS API reconstruction.

Token : '__Secure-better-auth.session_token' cookie (Network/Cookies,
        DPAPI-encrypted on disk; URL-encoded). Sent as a Cookie, not Bearer.
Host  : https://api.browseros.com/graphql
Query : GetConversationWithMessages($conversationId) ->
          conversation.conversationMessages.nodes.message
        conversationIds come from the local extension store (conversations[].id).
Note  : a loopback 127.0.0.1 control server exists but is Origin-restricted (403).
Ref   : FYI/network/browseros_api.py.
"""

from __future__ import annotations

from .base import BaseApiReconstructor, RequestSpec

URL = "https://api.browseros.com/graphql"
COOKIE = "__Secure-better-auth.session_token"

_QUERY = (
    "query GetConversationWithMessages($conversationId: String!) {"
    " conversation(rowId: $conversationId) { rowId"
    " conversationMessages(first: 100, orderBy: ORDER_INDEX_ASC) {"
    " nodes { message } } } }"
)


class BrowserosApiReconstructor(BaseApiReconstructor):
    key = "browseros"
    service_name = "BrowserOS"
    token_strategy = "'__Secure-better-auth.session_token' cookie (DPAPI); graphql"

    def extract_token(self, pending, *, cookies=None, local_state=None, **kwargs):
        return self._decrypt_named_cookie(
            [COOKIE], cookies=cookies, local_state=local_state)

    def plan(self, token: str, *, conversation_id: str | None = None,
             conversation_ids: list[str] | None = None, **kwargs) -> list[RequestSpec]:
        cookies = {COOKIE: token}
        headers = {"accept": "application/graphql-response+json",
                   "content-type": "application/json"}
        ids = ([conversation_id] if conversation_id else []) + (conversation_ids or [])
        specs = []
        for cid in ids:
            specs.append(RequestSpec(
                "POST", URL, ["Prompt", "Workflow", "Output"],
                f"conversation_{cid}", headers=headers, cookies=cookies,
                json_body={"query": _QUERY, "variables": {"conversationId": cid}}))
        return specs
