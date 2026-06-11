"""Comet (Perplexity) parser.

Local Storage (origin https://www.perplexity.ai):
  Account : 'pplx-next-auth-session'.user (email/id/name/username/image)
  Prompt  : 'comet-sidecar-threads-by-id' (conversation index: slug + updatedAt)

IndexedDB keyval-store (deserialized values):
  key = ["pplx-query-cache-<v>", <cache-type>, <slug/uuid>, ...]
  'all_results' bodies are lists of step entries holding:
    Prompt   : query_str (+ thread_title)
    Account  : author_id / author_username / author_image
    Workflow : blocks[].plan_block.goals / blocks[].workflow_block
    Output   : blocks[].markdown_block.answer
  conversation_id = backend_uuid; timestamp = entry_created_datetime.

The store readers (utils.localstorage / utils.indexeddb) and the JSON dumps
produced by the analyst scripts yield the same decoded values, so the pure
``records_from_*`` methods work for both live parsing and dump-based validation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from ...utils import dpapi, indexeddb, localstorage, sqlite
from ..records import AgentRecord, ParseResult
from .base import BaseServiceParser

PPLX_ORIGIN = "https://www.perplexity.ai"
SESSION_COOKIE = "__Secure-next-auth.session-token"


class CometParser(BaseServiceParser):
    key = "comet"
    service_name = "Comet"

    # --- production wiring ---------------------------------------------------

    def parse(self, *, user, artifacts, evidence_root) -> ParseResult:
        res = self._empty(user)

        for d in self.store_dirs(artifacts, evidence_root, storage_contains="Local Storage"):
            try:
                live = {sk: v for o, sk, v in localstorage.iter_items(d, PPLX_ORIGIN)}
                res.records += self.records_from_localstorage(live, user, str(d))
            except Exception as exc:  # noqa: BLE001 - record, don't abort
                res.errors.append(f"localstorage {d}: {exc}")

        for d in self.store_dirs(artifacts, evidence_root, storage_contains="IndexedDB"):
            try:
                items = ((r.key, r.value) for r in indexeddb.iter_records(d, store="keyval"))
                res.records += self.records_from_keyval(items, user, str(d))
            except Exception as exc:  # noqa: BLE001
                res.errors.append(f"indexeddb {d}: {exc}")

        key = dpapi.load_key_from_candidates(
            self.files(artifacts, evidence_root, name="Local State"))
        for cdb in self.files(artifacts, evidence_root, name="Cookies"):
            try:
                rows = sqlite.read_table(cdb, "cookies")
                res.records += self.records_from_cookies(rows, user, str(cdb), key=key)
            except Exception as exc:  # noqa: BLE001
                res.errors.append(f"cookies {cdb}: {exc}")
        return res

    def records_from_cookies(self, rows: list[dict], user: str, source: str,
                             *, key: bytes | None = None) -> list[AgentRecord]:
        out: list[AgentRecord] = []
        for r in rows:
            if r.get("name") != SESSION_COOKIE:
                continue
            value = r.get("value") or ""
            ev = r.get("encrypted_value")
            decrypted = False
            if not value and ev and key is not None:
                try:
                    value = dpapi.decrypt_cookie(bytes(ev), key)
                    decrypted = True
                except Exception:  # noqa: BLE001 - leave encrypted
                    pass
            out.append(self._record(
                user, "Authentication", source, content=SESSION_COOKIE,
                fields={"token": value, "host_key": r.get("host_key"),
                        "decrypted": decrypted, "has_encrypted": bool(ev),
                        "note": "JWE session cookie — API reconstruction pivot"}))
        return out

    # --- pure mapping (works on live readers and on JSON dumps) --------------

    def records_from_localstorage(self, live: dict, user: str, source: str) -> list[AgentRecord]:
        out: list[AgentRecord] = []
        sess = live.get("pplx-next-auth-session")
        if isinstance(sess, dict) and isinstance(sess.get("user"), dict):
            u = sess["user"]
            out.append(self._record(
                user, "Account", source,
                content=u.get("email"), timestamp=sess.get("expires"),
                fields={k: u.get(k) for k in
                        ("id", "email", "name", "username", "image", "org_role")}))

        # comet-sidecar-threads-by-id is only a conversation INDEX (slug + time),
        # not a prompt body — record it as a conversation-index residual so it
        # does not masquerade as a full session. The real prompt/workflow/output
        # come from IndexedDB all_results (records_from_keyval).
        threads = live.get("comet-sidecar-threads-by-id")
        if isinstance(threads, dict):
            for tid, meta in threads.items():
                if not isinstance(meta, dict):
                    continue
                out.append(self._residual(
                    user, source, "conversation-index",
                    _slug_text(meta.get("url")) or meta.get("url"),
                    timestamp=meta.get("updatedAt"),
                    url=meta.get("url"), thread_id=str(tid)))

        out += self._residuals_from_localstorage(live, user, source)
        return out

    def _residuals_from_localstorage(self, live: dict, user: str,
                                     source: str) -> list[AgentRecord]:
        """Residual local traces that persist even when not logged in:
        visited sites, last navigation URLs, onboarding step, location."""
        out: list[AgentRecord] = []
        top = live.get("pplx-top-sites-cache")
        if isinstance(top, list):
            for s in top:
                if isinstance(s, dict) and s.get("url"):
                    out.append(self._residual(
                        user, source, "visited-site", s.get("url"),
                        timestamp=s.get("lastAccess"), title=s.get("title"),
                        visit_count=s.get("visitCount")))
        for k, v in live.items():
            if not isinstance(k, str) or not isinstance(v, str):
                continue
            if k.endswith("web_url") or k.endswith("first_page_visit_url"):
                out.append(self._residual(user, source, "navigation", v, key=k))
        ob = live.get("cometOnboardingStep")
        if ob:
            out.append(self._residual(user, source, "onboarding", ob))
        loc = live.get("locationMetadata")
        if isinstance(loc, dict):
            out.append(self._residual(
                user, source, "location", loc.get("permissionState"),
                updated_at=loc.get("updatedAt")))
        return out

    def records_from_keyval(self, items: Iterable[tuple[Any, Any]], user: str,
                            source: str) -> list[AgentRecord]:
        """Parse the IndexedDB keyval cache. ``all_results`` holds full bodies;
        ``/rest/thread/list_recent`` and ``/rest/thread/list_ask_threads`` hold
        the conversation list (real title / query_str / uuid / time) which
        survives even when bodies are evicted; ``thread_metadata`` adds title +
        timestamps. Conversations already recovered from a full body are not
        duplicated by the lighter list/metadata sources."""
        items = list(items)
        out: list[AgentRecord] = []
        seen_authors: set[str] = set()
        covered: set[str] = set()   # conversation ids with a full body
        listed: set[str] = set()    # conversation ids surfaced from the list

        # pass 1 — full bodies
        for raw_key, value in items:
            key = _normalize_key(raw_key)
            if len(key) >= 2 and key[1] == "all_results" and isinstance(value, list):
                for entry in value:
                    if isinstance(entry, dict):
                        out += self._from_entry(entry, user, source, seen_authors)
                        for k in ("backend_uuid", "thread_url_slug", "uuid",
                                  "query_str", "thread_title"):
                            if entry.get(k):
                                covered.add(str(entry[k]))

        # pass 2 — conversation lists (titles/prompts/uuids for the rest)
        for raw_key, value in items:
            key = _normalize_key(raw_key)
            if len(key) < 2:
                continue
            ct = key[1]
            if ct == "/rest/thread/list_recent" and isinstance(value, list):
                for t in value:
                    if isinstance(t, dict):
                        self._from_thread_list(t, user, source, covered, listed, out)
            elif ct == "/rest/thread/list_ask_threads" and isinstance(value, dict):
                for page in value.get("pages", []) or []:
                    if isinstance(page, list):
                        for t in page:
                            if isinstance(t, dict):
                                self._from_thread_list(t, user, source, covered, listed, out)

        # pass 3 — thread_metadata (fallback title + timestamps)
        for raw_key, value in items:
            key = _normalize_key(raw_key)
            if len(key) >= 3 and key[1] == "thread_metadata" and isinstance(value, dict):
                slug = str(key[2])
                title = value.get("title")
                if (slug in covered or slug in listed or not title
                        or title in covered):
                    continue
                listed.add(slug)
                out.append(self._record(
                    user, "Prompt", source, role="user", content=value.get("title"),
                    conversation_id=slug, timestamp=value.get("created_at"),
                    fields={"status": value.get("thread_status"),
                            "updated_at": value.get("updated_at"),
                            "_origin": "thread_metadata"}))

        # de-duplicate: the same conversation body is cached under multiple
        # query-cache versions and block variants, producing identical records.
        seen: set = set()
        deduped: list[AgentRecord] = []
        for r in out:
            sig = (r.category, str(r.conversation_id), r.role, r.content)
            if sig in seen:
                continue
            seen.add(sig)
            deduped.append(r)
        return deduped

    def _from_thread_list(self, t: dict, user: str, source: str,
                          covered: set, listed: set, out: list) -> None:
        uuid = t.get("uuid") or t.get("backend_uuid")
        slug = t.get("slug")
        cid = str(uuid or slug or "")
        prompt = t.get("query_str") or t.get("title")
        if (not cid or cid in covered or cid in listed
                or (slug and str(slug) in covered)
                or (prompt and prompt in covered)):
            return
        listed.add(cid)
        ts = t.get("last_query_datetime") or t.get("created_at") or t.get("updated_at")
        out.append(self._record(
            user, "Prompt", source, role="user", content=prompt,
            conversation_id=cid, timestamp=ts,
            fields={"title": t.get("title"), "slug": slug,
                    "status": t.get("status") or t.get("thread_status"),
                    "mode": t.get("mode") or t.get("mode_type"),
                    "_origin": "thread-list"}))
        if t.get("answer_preview"):
            out.append(self._record(
                user, "Output", source, role="assistant",
                content=t.get("answer_preview"), conversation_id=cid, timestamp=ts,
                fields={"_origin": "answer_preview"}))

    # --- helpers -------------------------------------------------------------

    def _from_entry(self, e: dict, user: str, source: str,
                    seen_authors: set) -> list[AgentRecord]:
        out: list[AgentRecord] = []
        conv = e.get("backend_uuid") or e.get("thread_url_slug")
        ts = e.get("entry_created_datetime") or e.get("updated_datetime")
        common = dict(conversation_id=conv, session_id=e.get("context_uuid"))

        if e.get("query_str"):
            out.append(self._record(
                user, "Prompt", source, role="user", content=e["query_str"],
                timestamp=ts, fields={"thread_title": e.get("thread_title"),
                                      "model": e.get("display_model"),
                                      "mode": e.get("mode")}, **common))

        author = e.get("author_id")
        if author and author not in seen_authors:
            seen_authors.add(author)
            out.append(self._record(
                user, "Account", source, content=e.get("author_username"),
                fields={"author_id": author,
                        "author_username": e.get("author_username"),
                        "author_image": e.get("author_image")}, **common))

        for b in e.get("blocks", []) or []:
            if not isinstance(b, dict):
                continue
            md = b.get("markdown_block")
            if isinstance(md, dict) and md.get("answer"):
                out.append(self._record(
                    user, "Output", source, role="assistant",
                    content=md["answer"], timestamp=ts,
                    fields={"intended_usage": b.get("intended_usage"),
                            "progress": md.get("progress")}, **common))
            # Workflow = the agent's plan + reasoning steps + tool/search actions.
            plan = b.get("plan_block")
            if isinstance(plan, dict) and plan.get("goals"):
                goals = [g.get("description") for g in plan["goals"]
                         if isinstance(g, dict)]
                out.append(self._record(
                    user, "Workflow", source, role="agent", timestamp=ts,
                    content="Plan: " + " | ".join(filter(None, goals)),
                    fields={"kind": "plan", "goals": plan["goals"]}, **common))
            wf = b.get("workflow_block")
            if isinstance(wf, dict):
                out += self._workflow_steps(wf, user, source, ts, common)
        return out

    def _workflow_steps(self, wf: dict, user: str, source: str, ts,
                        common: dict) -> list[AgentRecord]:
        """Each workflow step = a reasoning title + its tool/search actions
        (queries issued, sources retrieved). This is the agent's execution."""
        out: list[AgentRecord] = []
        for step in wf.get("steps", []) or []:
            if not isinstance(step, dict):
                continue
            queries: list = []
            sources: list = []
            actions: list = []
            for it in step.get("items", []) or []:
                if not isinstance(it, dict):
                    continue
                it_type = it.get("type", "")
                pay = it.get("payload") or {}
                if it_type == "WORKFLOW_ITEM_QUERIES":
                    queries += (pay.get("queries_payload") or {}).get("queries", []) or []
                elif it_type == "WORKFLOW_ITEM_SOURCES":
                    sources += [s.get("url") for s in
                                (pay.get("sources_payload") or {}).get("sources", []) or []
                                if isinstance(s, dict) and s.get("url")]
                elif it_type:
                    actions.append(it_type.replace("WORKFLOW_ITEM_", "").lower())
            title = step.get("title") or "step"
            detail = title
            if queries:
                detail += "  [search: " + "; ".join(queries[:3]) + "]"
            out.append(self._record(
                user, "Workflow", source, role="agent", timestamp=ts,
                content=detail,
                fields={"kind": "step", "title": title, "status": step.get("status"),
                        "queries": queries, "sources": sources, "actions": actions},
                **common))
        return out


def _normalize_key(k: Any) -> list:
    """Accept an IndexedDB key as a list (live reader) or as the analyst dump's
    ``<IdbKey [...]>`` repr string; return a list."""
    if isinstance(k, list):
        return k
    if isinstance(k, str):
        s = k.strip()
        if s.startswith("<IdbKey ") and s.endswith(">"):
            s = s[len("<IdbKey "):-1]
        try:
            parsed = json.loads(s)
            return parsed if isinstance(parsed, list) else [parsed]
        except (json.JSONDecodeError, ValueError):
            return [k]
    return [k]


def _ms(v: Any) -> Any:
    """Pass-through for epoch-ms timestamps (kept raw; analysis normalises)."""
    return v


def _slug_text(url: Any) -> Any:
    """Derive readable prompt text from a Comet sidecar URL slug."""
    if not isinstance(url, str):
        return None
    tail = url.rstrip("/").split("/")[-1]
    # strip the trailing random id segment, turn dashes into spaces
    parts = tail.split("-")
    if len(parts) > 2:
        parts = parts[:-1]
    return " ".join(parts) or tail
