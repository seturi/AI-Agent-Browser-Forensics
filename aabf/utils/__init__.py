"""Shared storage-format readers.

Generic, service-agnostic readers for the on-disk formats AI agent browsers use.
They operate on *already-collected* local artifacts (the evidence store) and are
reused by BOTH consumers:

* ``parsing/`` — to extract structured agent records.
* ``collection/api/*_api.py`` — to extract the auth token before API replay.

Backends:
  leveldb      raw LevelDB key/value           -> ccl_chromium_reader (ccl_leveldb)
  extstore     chrome.storage.local            -> leveldb + JSON value decode
               (Local/Sync/Managed Extension Settings)
  localstorage Chromium Local Storage          -> ccl_chromium_reader
  indexeddb    Chromium IndexedDB              -> ccl_chromium_reader
  sqlite       Cookies / Login Data / *.db     -> stdlib sqlite3
  jsonlog      JSON files / plain-text logs    -> stdlib
  dpapi        Chromium v10 cookie/login crypto -> ctypes DPAPI + cryptography
               (decrypts encrypted_value via the Local State master key)

All readers are functional. The per-service parsers in ``parsing/services/``
build on them.
"""

__all__: list[str] = []
