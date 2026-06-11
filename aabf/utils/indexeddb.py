"""Chromium IndexedDB reader (backed by ccl_chromium_reader).

IndexedDB is a LevelDB with Blink + V8 serialization layered on top —
reimplementing it is impractical, so we wrap ccl_chromium_reader (the same
library the paper used). Holds the cached conversation bodies for Comet
(keyval-store), BrowserOS (extension store), and Genspark (reissue token).

``iter_records`` yields :class:`IdbRecord` with the value already deserialized
into Python objects by ccl.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from ccl_chromium_reader.ccl_chromium_indexeddb import WrappedIndexDB


@dataclass
class IdbRecord:
    database: str
    object_store: str
    key: Any
    value: Any
    is_live: bool


def _blob_dir_for(leveldb_dir: Path) -> Path | None:
    """IndexedDB external blobs live in a sibling '<name>.blob' dir."""
    p = Path(leveldb_dir)
    if p.name.endswith(".leveldb"):
        cand = p.with_name(p.name[: -len(".leveldb")] + ".blob")
        if cand.is_dir():
            return cand
    return None


def _bad_value(key, data):
    """Placeholder for a record whose V8 value can't be deserialized (e.g. a
    forensic copy taken mid-write). Lets iteration continue past the bad record
    instead of aborting the whole store."""
    return {"_deserialize_error": True, "_size": len(data) if data else 0}


def iter_records(
    leveldb_dir: Path, blob_dir: Path | None = None, *,
    database: str | None = None, store: str | None = None,
    live_only: bool = True,
) -> Iterator[IdbRecord]:
    """Yield records across databases/object stores, optionally filtered.

    Tolerant of unreadable databases/stores and of individual records that fail
    to deserialize (common when imaging a live profile) — those are skipped so a
    single bad record never drops the entire store."""
    leveldb_dir = Path(leveldb_dir)
    blob_dir = blob_dir or _blob_dir_for(leveldb_dir)
    widb = WrappedIndexDB(leveldb_dir, blob_dir)
    try:
        for dbid in widb.database_ids:
            try:
                wdb = widb[dbid.dbid_no]
            except Exception:  # noqa: BLE001 - unreadable database
                continue
            if database is not None and wdb.name != database:
                continue
            for store_name in wdb.object_store_names:
                if store is not None and store_name != store:
                    continue
                try:
                    obj_store = wdb.get_object_store_by_name(store_name)
                    records = obj_store.iterate_records(
                        live_only=live_only, bad_deserializer_data_handler=_bad_value)
                    for rec in records:
                        yield IdbRecord(
                            database=wdb.name,
                            object_store=store_name,
                            key=rec.key.value if rec.key is not None else None,
                            value=rec.value,
                            is_live=rec.is_live,
                        )
                except Exception:  # noqa: BLE001 - corrupt store: skip, keep others
                    continue
    finally:
        widb.close()


def list_stores(leveldb_dir: Path) -> dict[str, list[str]]:
    """Map database name -> object store names (for inspection)."""
    leveldb_dir = Path(leveldb_dir)
    widb = WrappedIndexDB(leveldb_dir, _blob_dir_for(leveldb_dir))
    out: dict[str, list[str]] = {}
    try:
        for dbid in widb.database_ids:
            wdb = widb[dbid.dbid_no]
            out[wdb.name] = list(wdb.object_store_names)
    finally:
        widb.close()
    return out
