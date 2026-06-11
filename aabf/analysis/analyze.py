"""Analysis orchestrator: parsing records -> correlated behavior Timeline.

Local-first: consumes the parsing module's ``ParseResult`` records. A
``server_records`` hook is in place for API-reconstruction-derived records once
those responses are parsed into :class:`~aabf.parsing.records.AgentRecord`s
(local↔server reconciliation then happens in :func:`correlate`).
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..models import Detection
from ..parsing.records import AgentRecord, ParseResult
from .correlate import correlate
from .coverage import build_coverage
from .models import Conversation, Timeline

_FUTURE = datetime.max.replace(tzinfo=timezone.utc)


def analyze(parse_results: list[ParseResult],
            detections: list[Detection] | None = None,
            server_records: list[AgentRecord] | None = None) -> Timeline:
    local = [r for pr in parse_results for r in pr.records]
    conversations, identities, orphans = correlate(local, server_records)
    conversations.sort(key=_conv_sort)
    coverage = build_coverage(parse_results, detections)
    return Timeline(conversations=conversations, identities=identities,
                    orphans=orphans, coverage=coverage)


def _conv_sort(c: Conversation):
    return (c.started_at or _FUTURE, c.browser_key, str(c.conversation_id))
