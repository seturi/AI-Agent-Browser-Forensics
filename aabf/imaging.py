"""Direct forensic image input.

Lets ``TARGET`` be a raw/split/E01/VMDK image *file* instead of a mounted drive
or extracted folder. The whole pipeline works on real filesystem paths (ccl /
sqlite open by path), so an image is handled by **extracting the AI-agent-browser
subtrees** out of it into a working directory that mirrors
``Users/<user>/AppData/{Local,Roaming}/...``; the normal pipeline then runs on
that directory.

Reading is done with ``dissect.target`` (pure-Python: raw, split .001, E01,
VMDK, VHD/X — no native libtsk/libewf). Install the extra::

    pip install -e ".[image]"

Only the directories the signatures need are pulled (each browser's UserData
tree + Fellou's Roaming dir), and bulky cache directories are skipped, so the
extraction stays small.
"""

from __future__ import annotations

from pathlib import Path

from .models import Anchor
from .signatures import SIGNATURES

# Image file extensions we accept as a TARGET file.
IMAGE_EXTS = {".raw", ".dd", ".img", ".001", ".e01", ".ex01", ".s01",
              ".vmdk", ".vhd", ".vhdx", ".aff", ".aff4", ".bin"}

# Chromium cache-like directories to skip when extracting (large, not needed).
_SKIP_DIRS = {
    "cache", "code cache", "gpucache", "graphitedawncache", "grshadercache",
    "shadercache", "dawngraphitecache", "dawnwebgpucache", "service worker",
    "component_crx_cache", "extensions_crx_cache", "crashpad", "crashpadmetrics",
    "blob_storage", "gcm store", "dawncache",
}


def is_image(path: Path) -> bool:
    """True if ``path`` is a forensic image file we should extract from."""
    p = Path(path)
    if not p.is_file():
        return False
    return p.suffix.lower() in IMAGE_EXTS


def extract(image_path: Path, dest: Path) -> Path:
    """Extract the browser-relevant subtrees from ``image_path`` into ``dest``.

    Returns ``dest`` (which mirrors ``Users/<user>/AppData/...``) for the normal
    pipeline to consume.
    """
    try:
        from dissect.target import Target  # lazy: optional [image] extra
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "image input needs the 'image' extra — pip install -e \".[image]\""
        ) from exc

    target = Target.open(str(image_path))
    return extract_from_filesystems(list(target.filesystems), dest)


def extract_from_filesystems(filesystems, dest: Path) -> Path:
    """Core extraction (separated for testing with a VirtualFilesystem)."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)

    # de-dup the UserData trees the signatures need, per anchor
    wanted: list[tuple[Anchor, str]] = []
    for sig in SIGNATURES:
        item = (sig.user_data_anchor, sig.user_data_relpath)
        if item not in wanted:
            wanted.append(item)

    for fs in filesystems:
        try:
            root = fs.path("/")
        except Exception:  # noqa: BLE001 - skip unreadable fs
            continue
        users = _ci_child(root, "Users")
        if users is None or not _is_dir(users):
            continue
        for udir in _iter_dirs(users):
            user = udir.name
            local = _resolve(udir, "AppData/Local")
            roaming = _resolve(udir, "AppData/Roaming")
            for anchor, relpath in wanted:
                base = local if anchor in (Anchor.LOCAL, Anchor.TEMP) else roaming
                if base is None:
                    continue
                src = _resolve(base, relpath)
                if src is None or not _is_dir(src):
                    continue
                anchor_name = "Local" if anchor in (Anchor.LOCAL, Anchor.TEMP) else "Roaming"
                out = dest / "Users" / user / "AppData" / anchor_name / Path(relpath)
                _copy_tree(src, out)
    return dest


# ----- dissect TargetPath helpers (also work on VirtualFilesystem paths) -----


def _norm(name: str) -> str:
    return name.lower().replace(" ", "")


def _is_dir(p) -> bool:
    try:
        return p.is_dir()
    except Exception:  # noqa: BLE001
        return False


def _iter_dirs(parent):
    try:
        for c in parent.iterdir():
            if _is_dir(c):
                yield c
    except Exception:  # noqa: BLE001
        return


def _ci_child(parent, name: str):
    """Case/space-insensitive child lookup (UserData vs User Data)."""
    lower, norm = name.lower(), _norm(name)
    fallback = None
    try:
        for child in parent.iterdir():
            cl = child.name.lower()
            if cl == lower:
                return child
            if fallback is None and _norm(cl) == norm:
                fallback = child
    except Exception:  # noqa: BLE001
        return None
    return fallback


def _resolve(base, relpath: str):
    cur = base
    for part in relpath.split("/"):
        if part in ("", "."):
            continue
        cur = _ci_child(cur, part)
        if cur is None:
            return None
    return cur


def _copy_tree(src, dst: Path) -> None:
    """Recursively copy a dissect dir into ``dst`` (skipping cache dirs)."""
    dst.mkdir(parents=True, exist_ok=True)
    try:
        children = list(src.iterdir())
    except Exception:  # noqa: BLE001
        return
    for child in children:
        name = child.name
        if _is_dir(child):
            if _norm(name) in {_norm(s) for s in _SKIP_DIRS}:
                continue
            _copy_tree(child, dst / name)
        else:
            try:
                with child.open("rb") as fh:
                    data = fh.read()
                (dst / name).write_bytes(data)
            except Exception:  # noqa: BLE001 - skip locked/unreadable files
                continue
