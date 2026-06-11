"""Raw LevelDB key/value reader (backed by ccl_chromium_reader).

Low-level access to any LevelDB directory. For the structured Chromium web
stores use :mod:`localstorage` / :mod:`indexeddb`; for extension
``chrome.storage.local`` (Local Extension Settings) use :mod:`extstore`, which
adds the value-decoding semantics on top of this reader.

Reads a forensic copy directly (no repair/lock). LevelDB keeps multiple versions
of a key across .ldb/.log files; helpers here either surface every raw record
(:func:`iter_raw`) or keep the highest-sequence record per key
(:func:`iter_records` / :func:`get`).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ccl_chromium_reader.storage_formats.ccl_leveldb import KeyState, RawLevelDb


@dataclass
class LevelDbRecord:
    key: bytes
    value: bytes
    seq: int
    is_live: bool          # True only for KeyState.Live (Deleted/Unknown -> False)
    source_file: str | None


def iter_raw(leveldb_dir: Path, *, include_deleted: bool = True) -> Iterator[LevelDbRecord]:
    """Yield every raw record (all versions, unsorted) in a LevelDB directory."""
    db = RawLevelDb(Path(leveldb_dir))
    try:
        for rec in db.iterate_records_raw():
            is_live = rec.state == KeyState.Live
            if not include_deleted and not is_live:
                continue
            yield LevelDbRecord(
                key=rec.user_key,
                value=rec.value,
                seq=rec.seq,
                is_live=is_live,
                source_file=rec.origin_file.name if rec.origin_file else None,
            )
    finally:
        db.close()


def _latest_by_key(leveldb_dir: Path) -> dict[bytes, LevelDbRecord]:
    latest: dict[bytes, LevelDbRecord] = {}
    for r in iter_raw(leveldb_dir, include_deleted=True):
        prev = latest.get(r.key)
        if prev is None or r.seq > prev.seq:
            latest[r.key] = r
    return latest


def iter_records(leveldb_dir: Path, *, live_only: bool = True,
                 include_deleted: bool = False) -> Iterator[tuple[bytes, bytes]]:
    """Yield (key, value) for each key's latest record.

    ``include_deleted`` overrides ``live_only`` to also surface tombstoned keys
    (useful for recovering deleted conversations).
    """
    for key, r in _latest_by_key(Path(leveldb_dir)).items():
        if not include_deleted and live_only and not r.is_live:
            continue
        yield key, r.value


def get(leveldb_dir: Path, key: bytes) -> bytes | None:
    """Return the latest live value for ``key``, or None."""
    r = _latest_by_key(Path(leveldb_dir)).get(key)
    if r is None or not r.is_live:
        return None
    return r.value


def is_leveldb_dir(p: Path) -> bool:
    """A LevelDB directory has a CURRENT file."""
    p = Path(p)
    return p.is_dir() and (p / "CURRENT").is_file()
