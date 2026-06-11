"""Correlation: group records into conversations and attribute the actor.

Local and server records are correlated by ``conversation_id`` (session_id as a
secondary clue). The same conversation seen on both sides is merged; one seen on
only one side is itself an investigative clue (paper Section 5.4) — surfaced via
``Conversation.reconstruction_status``.
"""

from __future__ import annotations

from ..parsing.records import AgentRecord
from .models import Conversation, IdentityProfile, TimelineEvent


def build_identities(records: list[AgentRecord]) -> dict[tuple, IdentityProfile]:
    """Assemble one IdentityProfile per (browser_key, user, profile) from
    Account/Auth records — so different Chromium profiles stay distinct."""
    profiles: dict[tuple, IdentityProfile] = {}
    for r in records:
        if r.category not in ("Account", "Authentication"):
            continue
        k = (r.browser_key, r.user, r.profile)
        prof = profiles.get(k)
        if prof is None:
            prof = profiles[k] = IdentityProfile(r.browser_key, r.user, profile=r.profile)
        f = r.fields or {}
        prof.merge(
            email=f.get("email") or (r.content if "@" in str(r.content or "") else None),
            user_id=f.get("id") or f.get("user_id") or f.get("user_uuid")
            or f.get("author_id"),
            username=f.get("username") or f.get("author_username"),
            name=f.get("name"))
    return profiles


def correlate(
    local: list[AgentRecord], server: list[AgentRecord] | None = None,
) -> tuple[list[Conversation], list[IdentityProfile], list[TimelineEvent]]:
    """Return (conversations, identities, orphan_events)."""
    server = server or []
    identities = build_identities(local + server)

    convs: dict[tuple[str, str, str], Conversation] = {}
    orphans: list[TimelineEvent] = []

    def ingest(records: list[AgentRecord], side: str) -> None:
        for r in records:
            ev = TimelineEvent.from_record(r, source_side=side)
            if not r.conversation_id:
                orphans.append(ev)
                continue
            key = (r.browser_key, r.user, r.profile, str(r.conversation_id))
            conv = convs.get(key)
            if conv is None:
                conv = convs[key] = Conversation(
                    browser_key=r.browser_key, user=r.user, profile=r.profile,
                    conversation_id=str(r.conversation_id),
                    actor=identities.get((r.browser_key, r.user, r.profile)))
            conv.events.append(ev)
            conv.source_sides.add(side)

    ingest(local, "local")
    ingest(server, "server")

    for conv in convs.values():
        conv.order()

    return list(convs.values()), list(identities.values()), orphans
