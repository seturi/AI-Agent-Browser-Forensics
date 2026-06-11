"""Parsing module (planned — scaffolded).

Turns the raw artifacts secured by the collection module into structured agent
records (Account / Prompt / Workflow / Output / Authentication).

Layout:
  records.py        normalized record models (AgentRecord, ParseResult)
  parse.py          dispatcher: collection manifest -> per-service parsers
  services/         one parser per browser (knows key/field -> category mapping)

Shared storage reading is delegated to :mod:`aabf.utils` (leveldb / localstorage
/ indexeddb via ccl_chromium_reader; sqlite / jsonlog via stdlib).

Service parsers are STUBS returning empty results until implemented one storage
backend at a time. Input: a collection ``manifest.json`` + the evidence store.
Output: ``ParseResult`` records keyed by conversation/session id for analysis.
"""

from .parse import get_parser, parse_collection, parse_manifest
from .records import AgentRecord, ParseResult

__all__ = ["AgentRecord", "ParseResult", "parse_manifest", "parse_collection",
           "get_parser"]
