"""Integrated analysis module (paper Section 5.4).

Takes the parsing module's local records (and, in future, API-reconstruction
server records) and links them into a single, attributed, chronological behavior
timeline — correlating by conversation/session id, attributing the actor, and
flagging local-only vs server-only conversations as cloud-sync clues.

  models.py      TimelineEvent / Conversation / IdentityProfile / Timeline
  timestamps.py  ISO / epoch-ms / epoch-s / WebKit -> UTC
  correlate.py   group by conversation/session + actor attribution (+server hook)
  analyze.py     orchestrator: ParseResult records -> Timeline
  report.py      console + JSON

Local-first: server-side reconciliation is wired (``server_records`` hook) but
anti-forensic flagging (Scenario 2) is deferred.
"""

from .analyze import analyze
from .models import Conversation, IdentityProfile, Timeline, TimelineEvent

__all__ = ["analyze", "Timeline", "Conversation", "TimelineEvent", "IdentityProfile"]
