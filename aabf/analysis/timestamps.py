"""Timestamp normalization to UTC.

AI agent browsers stamp records in several formats; the analysis module must put
them on one axis:

  * ISO-8601 strings  (Comet ``entry_created_datetime``, Sigma ``created_at``)
  * epoch milliseconds (BrowserOS ``lastMessagedAt``, Comet LS ``updatedAt``)
  * epoch seconds      (Comet ``perplexity_last_event_timestamp``)
  * Chromium/WebKit microseconds since 1601-01-01 (SQLite ``creation_utc``)

``normalize`` returns ``(datetime|None, epoch_seconds|None)`` — the datetime for
display, the float for sorting.
"""

from __future__ import annotations

from datetime import datetime, timezone

# Offset between the Windows/WebKit epoch (1601-01-01) and Unix epoch, in seconds.
_WEBKIT_EPOCH_OFFSET = 11644473600


def normalize(value) -> tuple[datetime | None, float | None]:
    if value is None or value == "":
        return None, None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt, dt.timestamp()
    if isinstance(value, bool):
        return None, None
    if isinstance(value, (int, float)):
        return _from_number(float(value))
    if isinstance(value, str):
        return _from_string(value.strip())
    return None, None


def _from_number(v: float) -> tuple[datetime | None, float | None]:
    """Disambiguate numeric epochs by magnitude (works for ~1973-2200)."""
    av = abs(v)
    if av >= 1e15:            # WebKit microseconds since 1601
        epoch = v / 1e6 - _WEBKIT_EPOCH_OFFSET
    elif av >= 1e11:          # milliseconds since 1970
        epoch = v / 1000.0
    else:                     # seconds since 1970
        epoch = v
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc), epoch
    except (OverflowError, OSError, ValueError):
        return None, None


def _from_string(s: str) -> tuple[datetime | None, float | None]:
    if not s:
        return None, None
    # purely numeric string -> treat as epoch
    if s.lstrip("-").isdigit():
        return _from_number(float(s))
    iso = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        # last resort: a few common explicit formats
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
        else:
            return None, None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt, dt.timestamp()


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None
