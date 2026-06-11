"""Data models for the integrated analysis module (paper Section 5.4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..parsing.records import AgentRecord
from . import timestamps

# Ordering of categories within one conversation turn (prompt -> work -> output).
_CATEGORY_ORDER = {"Account": 0, "Authentication": 0, "Prompt": 1,
                   "Workflow": 2, "Output": 3}


@dataclass
class TimelineEvent:
    """One record placed on the timeline with a normalized timestamp."""

    record: AgentRecord
    when: datetime | None
    epoch: float | None
    source_side: str = "local"      # local | server

    @classmethod
    def from_record(cls, rec: AgentRecord, *, source_side: str = "local") -> "TimelineEvent":
        when, epoch = timestamps.normalize(rec.timestamp)
        return cls(record=rec, when=when, epoch=epoch, source_side=source_side)

    @property
    def sort_key(self) -> tuple:
        # events without a timestamp sort last within their category
        return (self.epoch if self.epoch is not None else float("inf"),
                _CATEGORY_ORDER.get(self.record.category, 9))

    def to_dict(self) -> dict[str, Any]:
        r = self.record
        return {
            "when": timestamps.iso(self.when),
            "epoch": self.epoch,
            "source_side": self.source_side,
            "browser_key": r.browser_key,
            "user": r.user,
            "profile": r.profile,
            "category": r.category,
            "role": r.role,
            "conversation_id": r.conversation_id,
            "session_id": r.session_id,
            "content": r.content,
            "source": r.source,
            "fields": r.fields,
        }


@dataclass
class IdentityProfile:
    """Actor identity assembled from Account/Authentication records."""

    browser_key: str
    user: str
    profile: str | None = None        # Chromium profile (Default, Profile 1, ...)
    email: str | None = None
    user_id: str | None = None
    username: str | None = None
    name: str | None = None

    def merge(self, **kw) -> None:
        for k, v in kw.items():
            if v and getattr(self, k, None) in (None, ""):
                setattr(self, k, v)

    def to_dict(self) -> dict[str, Any]:
        return {"browser_key": self.browser_key, "user": self.user,
                "profile": self.profile,
                "email": self.email, "user_id": self.user_id,
                "username": self.username, "name": self.name}


@dataclass
class Conversation:
    """A correlated cluster of events sharing a conversation id."""

    browser_key: str
    user: str
    conversation_id: str | None
    profile: str | None = None        # Chromium profile (Default, Profile 1, ...)
    actor: IdentityProfile | None = None
    events: list[TimelineEvent] = field(default_factory=list)
    source_sides: set[str] = field(default_factory=set)

    def order(self) -> None:
        self.events.sort(key=lambda e: e.sort_key)

    @property
    def started_at(self) -> datetime | None:
        ts = [e.when for e in self.events if e.when]
        return min(ts) if ts else None

    @property
    def ended_at(self) -> datetime | None:
        ts = [e.when for e in self.events if e.when]
        return max(ts) if ts else None

    def category_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for e in self.events:
            counts[e.record.category] = counts.get(e.record.category, 0) + 1
        return counts

    @property
    def reconstruction_status(self) -> str:
        """local-only / server-only / merged — the cloud-sync clue (Section 5.4)."""
        if self.source_sides == {"local"}:
            return "local-only"
        if self.source_sides == {"server"}:
            return "server-only"
        return "merged"

    def reconstruct(self) -> list["Turn"]:
        """Group the (time-ordered) events into turns so a session reads as one
        unit: each user **prompt** plus the **workflow** steps and **output** that
        follow it. Account/Authentication/Residual events are not part of a turn.
        Multi-turn conversations yield multiple turns."""
        turns: list[Turn] = []
        cur: Turn | None = None
        for e in self.events:
            cat = e.record.category
            if cat == "Prompt":
                cur = Turn(prompt=e)
                turns.append(cur)
            elif cur is not None and cat == "Workflow":
                cur.workflow.append(e)
            elif cur is not None and cat == "Output":
                cur.output.append(e)
        # workflow/output that arrived before any prompt -> one promptless turn
        if cur is None:
            wf = [e for e in self.events if e.record.category == "Workflow"]
            out = [e for e in self.events if e.record.category == "Output"]
            if wf or out:
                turns.append(Turn(prompt=None, workflow=wf, output=out))
        return turns

    def to_dict(self) -> dict[str, Any]:
        return {
            "conversation_id": self.conversation_id,
            "browser_key": self.browser_key,
            "user": self.user,
            "profile": self.profile,
            "actor": self.actor.to_dict() if self.actor else None,
            "started_at": timestamps.iso(self.started_at),
            "ended_at": timestamps.iso(self.ended_at),
            "reconstruction_status": self.reconstruction_status,
            "category_counts": self.category_counts(),
            "turn_count": len(self.reconstruct()),
            # grouped, readable session view (prompt -> workflow -> output)
            "turns": [t.to_dict() for t in self.reconstruct()],
            # raw chronological events (full per-step detail) kept for reference
            "events": [e.to_dict() for e in self.events],
        }


@dataclass
class Turn:
    """One round of a conversation: a prompt and the agent's response to it."""

    prompt: "TimelineEvent | None" = None
    workflow: list["TimelineEvent"] = field(default_factory=list)
    output: list["TimelineEvent"] = field(default_factory=list)

    def prompt_text(self) -> str | None:
        return self.prompt.record.content if self.prompt else None

    def workflow_steps(self) -> list[str]:
        return [e.record.content for e in self.workflow if e.record.content]

    def output_text(self) -> list[str]:
        return [e.record.content for e in self.output if e.record.content]

    def to_dict(self) -> dict[str, Any]:
        when = self.prompt.when if self.prompt else (
            self.output[0].when if self.output else None)
        return {
            "time": timestamps.iso(when),
            "prompt": self.prompt_text(),
            "workflow": self.workflow_steps(),
            "output": self.output_text(),
        }


@dataclass
class CategoryStatus:
    """Status of one agent-artifact category for one service.

    status: recovered | present | server | absent | n/a
      recovered — parsed ≥1 record locally
      present   — local store/file exists on disk but nothing parsed (residual /
                  not-logged-in / evicted) — an *unconfirmed* artifact
      server    — only retrievable via API reconstruction
      absent    — expected local artifact not found
      n/a       — category not applicable for this service
    """

    category: str
    status: str
    local_present: bool = False
    server_side: bool = False
    record_count: int = 0
    paths: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"category": self.category, "status": self.status,
                "local_present": self.local_present, "server_side": self.server_side,
                "record_count": self.record_count, "paths": self.paths}


@dataclass
class ServiceCoverage:
    """Per-service 4-category artifact coverage for an identified service."""

    browser_key: str
    service_name: str
    service_type: str
    user: str
    categories: dict[str, CategoryStatus] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"browser_key": self.browser_key, "service_name": self.service_name,
                "service_type": self.service_type, "user": self.user,
                "categories": {k: v.to_dict() for k, v in self.categories.items()}}


@dataclass
class Timeline:
    """The assembled behavior timeline."""

    conversations: list[Conversation] = field(default_factory=list)
    identities: list[IdentityProfile] = field(default_factory=list)
    orphans: list[TimelineEvent] = field(default_factory=list)  # no conversation id
    coverage: list[ServiceCoverage] = field(default_factory=list)

    def global_events(self) -> list[TimelineEvent]:
        evs = [e for c in self.conversations for e in c.events] + self.orphans
        return sorted(evs, key=lambda e: e.sort_key)

    def to_dict(self) -> dict[str, Any]:
        return {
            "identities": [i.to_dict() for i in self.identities],
            "coverage": [c.to_dict() for c in self.coverage],
            "conversation_count": len(self.conversations),
            "conversations": [c.to_dict() for c in self.conversations],
            "orphan_events": [e.to_dict() for e in self.orphans],
        }
