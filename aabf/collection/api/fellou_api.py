"""Fellou (ASI X) API reconstruction.

Token : fellou.id_token (JWT) — plaintext in Partitions Local Storage, so it is
        extractable offline. Sent as Authorization: Bearer.
Host  : https://api.fellou.ai
Flow  : /api/userPoint (account) -> /api/chat/history (list+prompts) ->
        /api/chat/message/{chatId} (prompts+workflow); /api/task-config/scheduled-task.
Ref   : FYI/network/fellou_api.py.
"""

from __future__ import annotations

from ...utils import localstorage
from ..base import PendingApi
from .base import BaseApiReconstructor, RequestSpec

HOST = "https://api.fellou.ai"
FELLOU_ORIGIN = "https://agent.fellou.ai"


class FellouApiReconstructor(BaseApiReconstructor):
    key = "fellou"
    service_name = "Fellou"
    token_strategy = "JWT fellou.id_token from Partitions Local Storage (Bearer)"

    def extract_token(self, pending: PendingApi, *, store_dirs=None, **kwargs):
        for d in store_dirs or []:
            for name in ("fellou.id_token", "_authing_token"):
                tok = localstorage.get(d, name, FELLOU_ORIGIN) or localstorage.get(d, name)
                if tok:
                    return tok
        return None

    def token_from_localstorage(self, live: dict) -> str | None:
        """Offline helper: pull the token from a decoded Local Storage dict."""
        return live.get("fellou.id_token") or live.get("_authing_token")

    def plan(self, token: str, *, chat_id: str | None = None, **kwargs) -> list[RequestSpec]:
        h = {"Authorization": f"Bearer {token}"}
        specs = [
            RequestSpec("GET", f"{HOST}/api/userPoint", ["Account"], "userPoint", headers=h),
            RequestSpec("GET", f"{HOST}/api/chat/history", ["Prompt"], "chat_history", headers=h),
            RequestSpec("GET", f"{HOST}/api/task-config/scheduled-task",
                        ["Workflow"], "scheduled_task", headers=h),
        ]
        if chat_id:
            specs.append(RequestSpec(
                "GET", f"{HOST}/api/chat/message/{chat_id}",
                ["Prompt", "Workflow"], f"chat_message_{chat_id}", headers=h))
        return specs
