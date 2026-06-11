"""Chromium v10 secret decryption (Windows DPAPI + AES-256-GCM).

Chromium stores cookie values and saved passwords encrypted. On Windows the
scheme ("v10") is:

  1. The master key lives in ``Local State`` -> os_crypt.encrypted_key (base64).
     base64-decode it, strip the 5-byte ``DPAPI`` prefix, then DPAPI-decrypt
     (CryptUnprotectData, same Windows user) to get a 32-byte AES key.
  2. Each encrypted blob is:  b"v10" | nonce(12) | ciphertext | tag(16)
     decrypted with AES-256-GCM using that key and nonce.
  3. Cookie plaintext (modern Chrome) is prefixed with a 32-byte SHA-256 domain
     hash, which is stripped to recover the value. Saved passwords have no prefix.

Legacy blobs (no ``v10``/``v11`` prefix) are raw DPAPI and decrypt directly.

Scope: this is the classic v10 scheme. App-Bound Encryption (v20, Chrome 127+),
which wraps the key for the SYSTEM account, is NOT handled here.

Dependencies: DPAPI via ctypes (no dependency, Windows only); AES-GCM via the
``cryptography`` package — install the extra: ``pip install -e ".[decrypt]"``.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

_KEY_PREFIX = b"DPAPI"
_GCM_PREFIXES = (b"v10", b"v11")
_NONCE_LEN = 12
_TAG_LEN = 16
_COOKIE_HASH_PREFIX = 32  # SHA-256(domain) prepended to modern cookie plaintext


class DecryptionUnavailable(RuntimeError):
    """Raised when decryption cannot run (non-Windows, missing dependency,
    or DPAPI failure under a different user)."""


# ----- DPAPI (ctypes, Windows-only) -----------------------------------------


def dpapi_decrypt(blob: bytes) -> bytes:
    """CryptUnprotectData under the current Windows user. No external deps."""
    if os.name != "nt":
        raise DecryptionUnavailable("DPAPI is only available on Windows")
    import ctypes
    from ctypes import wintypes

    class _BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(blob, len(blob))
    blob_in = _BLOB(len(blob), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = _BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out))
    if not ok:
        raise DecryptionUnavailable(
            "CryptUnprotectData failed (wrong user account or corrupt blob)")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


# ----- AES-256-GCM (cryptography) -------------------------------------------


def _aes_gcm_decrypt(key: bytes, nonce: bytes, ct_and_tag: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover
        raise DecryptionUnavailable(
            "AES-GCM needs the 'cryptography' package — pip install -e '.[decrypt]'"
        ) from exc
    return AESGCM(key).decrypt(nonce, ct_and_tag, None)


# ----- key + value API -------------------------------------------------------


def load_state_key(local_state_path: Path) -> bytes:
    """Return the 32-byte AES master key from a profile's ``Local State``."""
    data: dict[str, Any] = json.loads(Path(local_state_path).read_text(encoding="utf-8"))
    enc_b64 = data.get("os_crypt", {}).get("encrypted_key")
    if not enc_b64:
        raise DecryptionUnavailable("Local State has no os_crypt.encrypted_key")
    enc = base64.b64decode(enc_b64)
    if enc[:len(_KEY_PREFIX)] == _KEY_PREFIX:
        enc = enc[len(_KEY_PREFIX):]
    return dpapi_decrypt(enc)


def load_key_from_candidates(local_state_paths) -> bytes | None:
    """Best-effort: return the master key from the first usable ``Local State``,
    or None if none work (non-Windows, missing dep, wrong user)."""
    for ls in local_state_paths or []:
        try:
            return load_state_key(Path(ls))
        except Exception:  # noqa: BLE001
            continue
    return None


def decrypt_value(blob: bytes, key: bytes | None = None) -> bytes:
    """Decrypt a Chromium encrypted_value. v10/v11 -> AES-GCM (needs ``key``);
    otherwise treated as a raw DPAPI blob."""
    if not blob:
        return b""
    if blob[:3] in _GCM_PREFIXES:
        if key is None:
            raise DecryptionUnavailable("v10/v11 blob requires the Local State key")
        nonce = blob[3:3 + _NONCE_LEN]
        return _aes_gcm_decrypt(key, nonce, blob[3 + _NONCE_LEN:])
    return dpapi_decrypt(blob)


def decrypt_cookie(blob: bytes, key: bytes | None = None) -> str:
    """Decrypt a cookie value and strip the modern 32-byte domain-hash prefix
    when present. Returns a best-effort UTF-8 string."""
    pt = decrypt_value(blob, key)
    try:
        return pt.decode("utf-8")                       # legacy: no prefix
    except UnicodeDecodeError:
        pass
    if len(pt) > _COOKIE_HASH_PREFIX:                   # modern: 32-byte hash prefix
        try:
            return pt[_COOKIE_HASH_PREFIX:].decode("utf-8")
        except UnicodeDecodeError:
            pass
    return pt.decode("utf-8", "replace")


class ChromiumCrypto:
    """Convenience wrapper bound to one profile's Local State key.

        cc = ChromiumCrypto.from_local_state(path_to_local_state)
        token = cc.cookie(encrypted_value_bytes)
    """

    def __init__(self, key: bytes):
        self.key = key

    @classmethod
    def from_local_state(cls, local_state_path: Path) -> "ChromiumCrypto":
        return cls(load_state_key(local_state_path))

    def value(self, blob: bytes) -> bytes:
        return decrypt_value(blob, self.key)

    def cookie(self, blob: bytes) -> str:
        return decrypt_cookie(blob, self.key)
