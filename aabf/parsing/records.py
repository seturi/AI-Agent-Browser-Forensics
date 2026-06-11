"""Normalized record models emitted by the parsing module.

Service parsers turn raw artifacts into these uniform records so the analysis
module can correlate across services by a common identifier (conversation /
session id). One record = one atomic fact (a prompt, an answer, a workflow step,
an account field, a token, ...).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class AgentRecord:
    browser_key: str
    user: str
    category: str                     # Account | Prompt | Workflow | Output | Authentication
    source: str                       # artifact path the record came from
    profile: str | None = None        # Chromium profile (Default, Profile 1, ...)
    conversation_id: str | None = None
    session_id: str | None = None
    timestamp: str | None = None      # ISO-8601 if known
    role: str | None = None           # user | agent | tool | system
    content: str | None = None        # prompt text, answer, step text, token, ...
    fields: dict[str, Any] = field(default_factory=dict)  # extra structured data

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ParseResult:
    browser_key: str
    user: str
    records: list[AgentRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def by_category(self, category: str) -> list[AgentRecord]:
        return [r for r in self.records if r.category == category]

    def to_dict(self) -> dict[str, Any]:
        return {
            "browser_key": self.browser_key,
            "user": self.user,
            "record_count": len(self.records),
            "errors": self.errors,
            "records": [r.to_dict() for r in self.records],
        }
