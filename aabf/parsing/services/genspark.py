"""Genspark (MainFunc) parser.

Local data is auth/account only; conversation bodies are server-side
(/api/project/my?from=agents returns session_clean_text with the full flow).

  Cookies (SQLite):
    session_id  -> THE authentication token (API-reconstruction pivot). Value is
                   '<uuid>:<hex-token>'; sent as the 'session_id' cookie. Required.
    ai_user     -> user identifier + first-issue time ('<id>|<ISO time>') -> Account
    ai_session  -> session timestamp(s) ('<id>|<ts>|<ts>') -> session metadata
  Login Data (SQLite) : account email
  IndexedDB           : reissue auth token

Cookie values on disk are usually DPAPI/AES-GCM encrypted (in encrypted_value);
per current scope we surface the cookie name + any plaintext + the encrypted
flag, leaving decryption to a later step. The decrypted session_id is what the
API reconstructor replays.

No dataset dump for Genspark, so this is implemented to spec (paper Section
4.1.6 + the analyst's genspark_api.py) and validated against real Genspark data.
"""

from __future__ import annotations

from typing import Any

from ...utils import dpapi, sqlite
from ..records import AgentRecord, ParseResult
from .base import BaseServiceParser

# cookie name -> (category, is_api_token)
_COOKIE_ROLES = {
    "session_id": ("Authentication", True),   # the auth token / API pivot
    "ai_user": ("Account", False),            # user id + first-issue time
    "ai_session": ("Authentication", False),  # session timestamp(s)
}


class GensparkParser(BaseServiceParser):
    key = "genspark"
    service_name = "Genspark Browser"

    def parse(self, *, user, artifacts, evidence_root) -> ParseResult:
        res = self._empty(user)
        key = dpapi.load_key_from_candidates(
            self.files(artifacts, evidence_root, name="Local State"))
        for cookies in self.files(artifacts, evidence_root, name="Cookies"):
            try:
                rows = sqlite.read_table(cookies, "cookies")
                res.records += self.records_from_cookies(rows, user, str(cookies), key=key)
            except Exception as exc:  # noqa: BLE001
                res.errors.append(f"cookies {cookies}: {exc}")
        for login in self.files(artifacts, evidence_root, name="Login Data"):
            try:
                rows = sqlite.read_table(login, "logins")
                res.records += self.records_from_logins(rows, user, str(login))
            except Exception as exc:  # noqa: BLE001
                res.errors.append(f"login {login}: {exc}")
        return res

    def records_from_cookies(self, rows: list[dict], user: str, source: str,
                             *, key: bytes | None = None) -> list[AgentRecord]:
        out: list[AgentRecord] = []
        for r in rows:
            name = r.get("name")
            if name not in _COOKIE_ROLES:
                continue
            category, is_token = _COOKIE_ROLES[name]
            value = r.get("value") or ""
            decrypted = False
            ev = r.get("encrypted_value")
            if not value and ev and key is not None:
                try:
                    value = dpapi.decrypt_cookie(bytes(ev), key)
                    decrypted = True
                except Exception:  # noqa: BLE001 - leave encrypted
                    pass
            fields: dict[str, Any] = {
                "name": name, "value": value,
                "host_key": r.get("host_key"),
                "has_encrypted": bool(ev),
                "decrypted": decrypted,
                "is_api_token": is_token,
            }
            if is_token:
                fields["note"] = "session_id cookie = auth token for /api/project/my"
            fields.update(_decompose(name, value))
            out.append(self._record(
                user, category, source, content=name,
                timestamp=r.get("creation_utc"), fields=fields))
        return out

    def records_from_logins(self, rows: list[dict], user: str, source: str) -> list[AgentRecord]:
        out: list[AgentRecord] = []
        for r in rows:
            email = r.get("username_value")
            if email:
                out.append(self._record(
                    user, "Account", source, content=email,
                    fields={"origin_url": r.get("origin_url")}))
        return out


def _decompose(name: str, value: str) -> dict[str, Any]:
    """Split a plaintext Genspark cookie value into its parts (best-effort).

    Encrypted (empty) values yield {}; structure is recovered post-decryption.
    """
    if not value:
        return {}
    if name == "session_id" and ":" in value:                # <user_uuid>:<token>
        uid, tok = value.split(":", 1)
        return {"user_uuid": uid, "token": tok}
    if name == "ai_user" and "|" in value:                   # <id>|<ISO first-issue>
        uid, _, issued = value.partition("|")
        return {"user_id": uid, "first_issued_at": issued}
    if name == "ai_session" and "|" in value:                # <id>|<ts>|<ts>
        parts = value.split("|")
        return {"session_token": parts[0], "timestamps": parts[1:]}
    return {}
