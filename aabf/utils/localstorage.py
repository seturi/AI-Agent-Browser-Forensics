"""Chromium Local Storage reader (backed by ccl_chromium_reader).

Local Storage uses a LevelDB with a '__meta'/'_<origin>\\x00<key>' layout, not
plain key/value — the paper used ccl_chromium_reader for exactly this. Holds
account info and auth tokens for Comet, Fellou, Sigma; MSAL cache for Edge.

Records are (storage_key, script_key, value): ``storage_key`` is the origin
(e.g. ``https://www.perplexity.ai``), ``script_key`` is the JS key, ``value`` is
the stored string.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterator

from ccl_chromium_reader.ccl_chromium_localstorage import LocalStoreDb

from .extstore import try_parse_json


def iter_items(leveldb_dir: Path, origin: str | None = None, *,
               live_only: bool = True, parse_json: bool = True
               ) -> Iterator[tuple[str, str, Any]]:
    """Yield (storage_key, script_key, value) items; optionally one ``origin``.

    By default values are run through :func:`extstore.try_parse_json` so that
    JSON-encoded strings (e.g. Comet ``pplx-next-auth-session``, Edge ``msal.2|``
    entries, Sigma ``search-storage``) are returned as Python objects — matching
    the analyst dump format the parsers expect. Set ``parse_json=False`` for the
    raw stored string.
    """
    db = LocalStoreDb(Path(leveldb_dir))
    try:
        for rec in db.iter_all_records():
            if live_only and not rec.is_live:
                continue
            if origin is not None and rec.storage_key != origin:
                continue
            yield rec.storage_key, rec.script_key, (
                try_parse_json(rec.value) if parse_json else rec.value)
    finally:
        db.close()


def get(leveldb_dir: Path, key: str, origin: str | None = None) -> str | None:
    """Return the value for script key ``key`` (first match), or None."""
    for _origin, script_key, value in iter_items(leveldb_dir, origin):
        if script_key == key:
            return value
    return None


def origins(leveldb_dir: Path) -> list[str]:
    """List the storage origins present in the Local Storage db."""
    db = LocalStoreDb(Path(leveldb_dir))
    try:
        return list(db.iter_storage_keys())
    finally:
        db.close()
