"""chrome.storage.local reader for 'Local Extension Settings' (and Sync/Managed).

Extension storage is a plain LevelDB (read via :mod:`leveldb`), but its values
follow Chromium's ``LeveldbValueStore`` convention, which differs from Local
Storage: the value is a **raw JSON string with no 1-byte type prefix**. This
module adds that decoding plus recursive resolution of nested JSON strings.

Used by the BrowserOS and Sigma parsers (prompts / workflow / socketAuth) and by
Sigma's API token extraction.

Mechanism mirrors the analyst reference script (FYI/analysis_extension.py):
  * key  = ``rec.user_key`` decoded as UTF-8 (the chrome.storage.local key)
  * value: try ``json.loads(raw)``; fallback strip 1 leading byte; else hex
  * recursively parse JSON-encoded strings found inside values
  * keep highest-seq live record per key; collect deleted separately
  * accept a single ``<ext-id>`` dir OR a parent 'Local Extension Settings' dir
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import leveldb


def try_parse_json(value: Any) -> Any:
    """Recursively resolve JSON-encoded strings within ``value``."""
    if isinstance(value, str):
        try:
            return try_parse_json(json.loads(value))
        except (json.JSONDecodeError, ValueError, TypeError):
            return value
    if isinstance(value, dict):
        return {k: try_parse_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [try_parse_json(v) for v in value]
    return value


def decode_value(raw: bytes) -> Any:
    """Decode a chrome.storage.local value.

    Values are raw JSON strings. A 1-byte-prefix strip is attempted as a
    defensive fallback for variant forks; unparseable bytes are preserved as hex.
    """
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    if len(raw) > 1:
        try:
            return json.loads(raw[1:].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return {"_raw_hex": raw.hex(), "_size": len(raw)}


def _decode_key(raw: bytes) -> Any:
    try:
        return try_parse_json(raw.decode("utf-8"))
    except UnicodeDecodeError:
        return raw.hex()


@dataclass
class ExtStore:
    """Parsed contents of one extension's chrome.storage.local store."""

    extension_id: str
    live: dict[Any, Any] = field(default_factory=dict)        # key -> value (latest)
    deleted: list[dict[str, Any]] = field(default_factory=list)  # {key, value, seq}

    def get(self, key: str, default: Any = None) -> Any:
        return self.live.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        return {"extension_id": self.extension_id,
                "live": self.live, "deleted": self.deleted}


def read_store(leveldb_dir: Path, *, extension_id: str | None = None) -> ExtStore:
    """Read one ``<ext-id>`` LevelDB dir into an :class:`ExtStore`.

    Keeps the highest-seq live value per key; deleted records are kept separately
    (for recovering removed conversations/prompts).
    """
    leveldb_dir = Path(leveldb_dir)
    store = ExtStore(extension_id=extension_id or leveldb_dir.name)

    best_seq: dict[Any, int] = {}
    for rec in leveldb.iter_raw(leveldb_dir, include_deleted=True):
        key = _decode_key(rec.key)
        value = try_parse_json(decode_value(rec.value))
        hkey = _hashable(key)
        if rec.is_live:
            if hkey not in best_seq or rec.seq > best_seq[hkey]:
                best_seq[hkey] = rec.seq
                store.live[key] = value
        else:
            store.deleted.append({"key": key, "value": value, "seq": rec.seq})
    return store


def read_settings(path: Path) -> dict[str, ExtStore]:
    """Read a single ``<ext-id>`` dir or a parent 'Local Extension Settings' dir.

    Returns ``{extension_id: ExtStore}``.
    """
    path = Path(path)
    if leveldb.is_leveldb_dir(path):
        return {path.name: read_store(path)}

    out: dict[str, ExtStore] = {}
    if not path.is_dir():
        return out
    for sub in sorted(path.iterdir()):
        if leveldb.is_leveldb_dir(sub):
            try:
                out[sub.name] = read_store(sub)
            except Exception:  # one corrupt store shouldn't sink the rest
                continue
    return out


def _hashable(key: Any) -> Any:
    """A stable, hashable form of a (possibly dict/list) key for dedup."""
    if isinstance(key, (dict, list)):
        return json.dumps(key, sort_keys=True, ensure_ascii=False)
    return key
