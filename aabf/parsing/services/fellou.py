"""Fellou (ASI X) parser.

Local Storage (Partitions; origins agent.fellou.ai / file:// / authing):
  Account : 'fellou.userInfo' (id/email/phone/createdAt/authing_user_id),
            '_authing_user' (id/username/email/phone)
  Auth    : 'fellou.id_token' / 'fellou.access_token' / '_authing_token' (JWT)
            — the API-reconstruction pivot; JWT payload is base64 (not encrypted)
            so userID/email are recoverable.
  Quota   : 'userPoint'
Prompt/Workflow/Output bodies are server-side (API reconstruction).
"""

from __future__ import annotations

import base64
import json
from typing import Any

from ...utils import localstorage
from ..records import AgentRecord, ParseResult
from .base import BaseServiceParser


class FellouParser(BaseServiceParser):
    key = "fellou"
    service_name = "Fellou"

    def parse(self, *, user, artifacts, evidence_root) -> ParseResult:
        res = self._empty(user)
        for d in self.store_dirs(artifacts, evidence_root, storage_contains="Local Storage"):
            try:
                by_key = {sk: v for _o, sk, v in localstorage.iter_items(d)}
                res.records += self.records_from_localstorage(by_key, user, str(d))
            except Exception as exc:  # noqa: BLE001
                res.errors.append(f"localstorage {d}: {exc}")
        return res

    def records_from_localstorage(self, live: dict, user: str, source: str) -> list[AgentRecord]:
        out: list[AgentRecord] = []

        info = live.get("fellou.userInfo")
        if isinstance(info, dict):
            out.append(self._record(
                user, "Account", source, content=info.get("email"),
                timestamp=info.get("createdAt"),
                fields={k: info.get(k) for k in
                        ("id", "email", "phone_number", "createdAt",
                         "authing_user_id", "isAdmin")}))

        au = live.get("_authing_user")
        if isinstance(au, dict):
            out.append(self._record(
                user, "Account", source, content=au.get("email"),
                fields={k: au.get(k) for k in
                        ("id", "username", "email", "phone")}))

        for tkey in ("fellou.id_token", "fellou.access_token", "_authing_token"):
            tok = live.get(tkey)
            if isinstance(tok, str) and tok:
                out.append(self._record(
                    user, "Authentication", source, content=tkey,
                    fields={"token": tok, "jwt_payload": _jwt_payload(tok)}))

        pt = live.get("userPoint")
        if isinstance(pt, dict):
            out.append(self._record(
                user, "Account", source, content="userPoint",
                fields={k: pt.get(k) for k in
                        ("availablePoint", "usedPoint", "monthlyPoint")}))
        return out


def _jwt_payload(token: str) -> Any:
    """Base64url-decode the JWT payload (claims). Not decryption — JWTs are
    signed, not encrypted; the body is public base64."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        seg = parts[1]
        seg += "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg).decode("utf-8", "replace"))
    except (ValueError, json.JSONDecodeError):
        return None
