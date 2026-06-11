"""Sigma Browser parser.

Local Storage 'search-storage' (origin https://app.sigmabrowser.com):
  Account : .user (user_id/email/username/created_at/last_login_at/subscription)
  Auth    : access_token / refresh_token / session_id / is_log_in
  Prompt  : .userHistory[] (query, hash, created_at, session_id, thread_name, ...)
  Output  : .userHistory[].summary
chrome.storage.local (agent extension, via utils.extstore):
  Auth    : userId, socketAuth (sessionId/token)
  Prompt  : 'inputSearchPage:<id>' / 'inputMainPage' (raw typed text)
  Workflow: activeTarget_<uuid> / lastVisitedPath (navigation hints)
Workflow (agent reasoning) proper is SERVER-only (/api/v1/search via hash).
"""

from __future__ import annotations

from ...utils import extstore, localstorage
from ..records import AgentRecord, ParseResult
from .base import BaseServiceParser

SIGMA_ORIGIN = "https://app.sigmabrowser.com"
AGENT_EXT = "amabiocpfnlgbceffljgkcjeacejflga"


class SigmaParser(BaseServiceParser):
    key = "sigma"
    service_name = "Sigma Browser"

    def parse(self, *, user, artifacts, evidence_root) -> ParseResult:
        res = self._empty(user)
        for d in self.store_dirs(artifacts, evidence_root, storage_contains="Local Storage"):
            try:
                ss = localstorage.get(d, "search-storage", SIGMA_ORIGIN)
                if ss is None:
                    ss = localstorage.get(d, "search-storage")
                if ss is not None:
                    import json
                    val = json.loads(ss) if isinstance(ss, str) else ss
                    res.records += self.records_from_search_storage(val, user, str(d))
            except Exception as exc:  # noqa: BLE001
                res.errors.append(f"localstorage {d}: {exc}")
        for d in self.store_dirs(artifacts, evidence_root,
                                 storage_contains="Local Extension Settings"):
            try:
                store = extstore.read_store(d)
                res.records += self.records_from_extstore(store.live, user, str(d))
            except Exception as exc:  # noqa: BLE001
                res.errors.append(f"extstore {d}: {exc}")
        return res

    def records_from_search_storage(self, ss: dict, user: str, source: str) -> list[AgentRecord]:
        out: list[AgentRecord] = []
        state = ss.get("state", ss) if isinstance(ss, dict) else {}
        if not isinstance(state, dict):
            return out

        u = state.get("user")
        if isinstance(u, dict):
            out.append(self._record(
                user, "Account", source, content=u.get("email"),
                timestamp=u.get("created_at"),
                fields={k: u.get(k) for k in
                        ("user_id", "email", "username", "created_at",
                         "last_login_at", "subscription")}))

        if state.get("access_token") or state.get("session_id"):
            out.append(self._record(
                user, "Authentication", source, session_id=state.get("session_id"),
                content="access_token", fields={
                    "access_token": state.get("access_token"),
                    "refresh_token": state.get("refresh_token"),
                    "is_log_in": state.get("is_log_in")}))

        for h in state.get("userHistory", []) or []:
            if not isinstance(h, dict):
                continue
            out.append(self._record(
                user, "Prompt", source, role="user", content=h.get("query"),
                conversation_id=h.get("id") or h.get("api_thread_id"),
                session_id=h.get("session_id"), timestamp=h.get("created_at"),
                fields={"hash": h.get("hash"), "thread_name": h.get("thread_name"),
                        "thread_type": h.get("thread_type")}))
            if h.get("summary"):
                out.append(self._record(
                    user, "Output", source, role="assistant", content=h.get("summary"),
                    conversation_id=h.get("id") or h.get("api_thread_id"),
                    timestamp=h.get("updated_at") or h.get("created_at")))
        return out

    def records_from_extstore(self, live: dict, user: str, source: str) -> list[AgentRecord]:
        out: list[AgentRecord] = []
        sa = live.get("socketAuth")
        if isinstance(sa, dict):
            out.append(self._record(
                user, "Authentication", source, session_id=sa.get("sessionId"),
                content="socketAuth", fields={"userId": live.get("userId"),
                                              "token": sa.get("token")}))
        for k, v in live.items():
            if isinstance(k, str) and k.startswith(("inputSearchPage:", "inputMainPage")):
                cid = k.split(":", 1)[1] if ":" in k else None
                if v:
                    out.append(self._record(
                        user, "Prompt", source, role="user", content=v,
                        conversation_id=cid,
                        fields={"_origin": "extension-input-box", "key": k}))
        # residual navigation traces (persist without a recovered conversation)
        lvp = live.get("lastVisitedPath")
        if lvp:
            out.append(self._residual(user, source, "navigation", lvp))
        for k, v in live.items():
            if isinstance(k, str) and k.startswith("activeTarget_"):
                out.append(self._residual(
                    user, source, "active-target", v,
                    target_id=k[len("activeTarget_"):]))
        return out
