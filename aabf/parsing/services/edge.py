"""Microsoft Edge (Copilot) parser.

Local Storage (origin https://copilot.microsoft.com): MSAL cache.
  'msal.2.account.keys'                      -> list of account entry ids
  'msal.2|...'  account entry  {id, nonce, data, lastUpdatedAt}
  'msal.2|...|idtoken|...' / '...|accesstoken|...' token entries (DPAPI 'data')
The token 'data' body is DPAPI-encrypted -> kept as a metadata marker only
(decryption is a separate, later step). Identifiers (tenant/client/scope) come
from the key structure; session timing from lastUpdatedAt. Conversation bodies
are server-side (API reconstruction).
"""

from __future__ import annotations

from ...utils import localstorage
from ..records import AgentRecord, ParseResult
from .base import BaseServiceParser

COPILOT_ORIGIN = "https://copilot.microsoft.com"


class EdgeParser(BaseServiceParser):
    key = "edge"
    service_name = "Microsoft Edge (Copilot)"

    def parse(self, *, user, artifacts, evidence_root) -> ParseResult:
        res = self._empty(user)
        for d in self.store_dirs(artifacts, evidence_root, storage_contains="Local Storage"):
            try:
                live = {sk: v for o, sk, v in localstorage.iter_items(d)
                        if o.startswith(COPILOT_ORIGIN)}
                res.records += self.records_from_localstorage(live, user, str(d))
            except Exception as exc:  # noqa: BLE001
                res.errors.append(f"localstorage {d}: {exc}")
        return res

    def records_from_localstorage(self, live: dict, user: str, source: str) -> list[AgentRecord]:
        out: list[AgentRecord] = []
        for k, v in live.items():
            if not (isinstance(k, str) and k.startswith("msal.2|") and isinstance(v, dict)):
                continue
            parts = k.split("|")
            is_token = "idtoken" in parts or "accesstoken" in parts
            category = "Authentication" if is_token else "Account"
            ttype = ("idtoken" if "idtoken" in parts else
                     "accesstoken" if "accesstoken" in parts else "account")
            scope = parts[-3] if is_token and len(parts) >= 3 else None
            out.append(self._record(
                user, category, source, content=ttype,
                session_id=v.get("id"), timestamp=v.get("lastUpdatedAt"),
                fields={"client_or_tenant": parts[3] if len(parts) > 3 else None,
                        "scope": scope, "nonce": v.get("nonce"),
                        "dpapi_encrypted": bool(v.get("data")),
                        "data_present": bool(v.get("data"))}))
        return out
