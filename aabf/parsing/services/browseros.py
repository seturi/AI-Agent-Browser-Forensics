"""BrowserOS parser.

chrome.storage.local (agent extension, via utils.extstore):
  'conversations' = [{id, lastMessagedAt, messages:[{id, role, parts:[...]}]}]
    role 'user'      -> Prompt   (text parts)
    role 'assistant' -> Output   (text parts)
    parts 'tool-*'   -> Workflow (one per tool call: input/output/state)
No account (BrowserOS has no separate login).
"""

from __future__ import annotations

from ...utils import extstore
from ..records import AgentRecord, ParseResult
from .base import BaseServiceParser

AGENT_EXT = "bflpfmnmnokmjhmgnolecpppdbdophmk"


class BrowserosParser(BaseServiceParser):
    key = "browseros"
    service_name = "BrowserOS"

    def parse(self, *, user, artifacts, evidence_root) -> ParseResult:
        res = self._empty(user)
        for d in self.store_dirs(artifacts, evidence_root,
                                 storage_contains="Local Extension Settings"):
            try:
                store = extstore.read_store(d)
                res.records += self.records_from_extstore(store.live, user, str(d))
            except Exception as exc:  # noqa: BLE001
                res.errors.append(f"extstore {d}: {exc}")
        return res

    def records_from_extstore(self, live: dict, user: str, source: str) -> list[AgentRecord]:
        out: list[AgentRecord] = []
        for conv in live.get("conversations", []) or []:
            if not isinstance(conv, dict):
                continue
            cid = conv.get("id")
            ts = conv.get("lastMessagedAt")
            for msg in conv.get("messages", []) or []:
                if not isinstance(msg, dict):
                    continue
                out += self._from_message(msg, cid, ts, user, source)
        out += self._residuals_from_extstore(live, user, source)
        return out

    def _residuals_from_extstore(self, live: dict, user: str,
                                 source: str) -> list[AgentRecord]:
        """Residual config/intent traces that persist without any conversation:
        scheduled tasks, configured LLM providers, MCP servers, session info."""
        out: list[AgentRecord] = []
        for job in live.get("scheduledJobRuns") or []:
            if isinstance(job, dict):
                out.append(self._residual(
                    user, source, "scheduled-task", job.get("id") or job.get("name"),
                    timestamp=job.get("nextRunAt") or job.get("lastRunAt"),
                    status=job.get("status"), prompt=job.get("prompt") or job.get("goal")))
        for p in live.get("llm-providers") or []:
            if isinstance(p, dict):
                out.append(self._residual(
                    user, source, "model-config", p.get("modelId") or p.get("name"),
                    timestamp=p.get("createdAt"), provider=p.get("type"),
                    base_url=p.get("baseUrl"), context_window=p.get("contextWindow")))
        for m in live.get("mcpServers") or []:
            name = m.get("name") if isinstance(m, dict) else m
            url = m.get("url") if isinstance(m, dict) else None
            out.append(self._residual(user, source, "mcp-server", name, url=url))
        si = live.get("sessionInfo")
        if isinstance(si, dict) and si:
            out.append(self._residual(user, source, "session", None, **si))
        return out

    def _from_message(self, msg, cid, ts, user, source) -> list[AgentRecord]:
        out: list[AgentRecord] = []
        role = msg.get("role")
        parts = msg.get("parts") or []
        texts = [p.get("text") for p in parts
                 if isinstance(p, dict) and p.get("type") == "text" and p.get("text")]
        tools = [p for p in parts
                 if isinstance(p, dict) and str(p.get("type", "")).startswith("tool-")]

        if texts:
            text = "\n".join(texts)
            if role == "user":
                out.append(self._record(user, "Prompt", source, role="user",
                                         content=text, conversation_id=cid, timestamp=ts))
            else:
                out.append(self._record(user, "Output", source, role=role or "assistant",
                                         content=text, conversation_id=cid, timestamp=ts))

        for t in tools:
            tool_name = str(t.get("type", ""))[len("tool-"):]
            out.append(self._record(
                user, "Workflow", source, role="tool", conversation_id=cid,
                timestamp=ts, content=tool_name,
                fields={"input": t.get("input"), "output": t.get("output"),
                        "state": t.get("state"), "toolCallId": t.get("toolCallId")}))
        return out
