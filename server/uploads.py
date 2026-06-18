"""C3 — safe repo ZIP extraction for the web UI.

A user can upload a ``.zip`` of a private/local repo instead of typing a path. We extract it to a
staging dir under ``runs_dir`` and hand the path to the normal run flow (ingest's ``acquire_repo``
copies it read-only, as for any local folder). Extraction is hardened against the usual ZIP abuses:

  * **path traversal** — every member must resolve *inside* the destination (no ``..`` / absolute);
  * **zip bombs** — caps on entry count and total uncompressed size;
  * symlinks are skipped (never recreated).

Localhost, single-user tool — these are defense-in-depth, not a substitute for not exposing the
server. The target repo stays read-only downstream; nothing here executes the uploaded code.
"""

from __future__ import annotations

import shutil
import stat
import zipfile
from pathlib import Path

MAX_ENTRIES = 20_000
MAX_TOTAL_BYTES = 300 * 1024 * 1024      # 300 MB uncompressed
_COPY_CHUNK = 1024 * 1024


class UnsafeZip(ValueError):
    """The upload is not a usable, safe repo zip."""


def extract_zip(file_obj, dest: Path) -> dict:
    """Extract a zip (a path or a file-like) into ``dest`` safely. Returns
    ``{"path": <repo root>, "files": <file count>}``. Raises :class:`UnsafeZip` on any abuse."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    dest_root = dest.resolve()
    try:
        zf = zipfile.ZipFile(file_obj)
    except zipfile.BadZipFile as exc:
        raise UnsafeZip(f"not a valid zip file: {exc}") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise UnsafeZip(f"too many entries ({len(infos)} > {MAX_ENTRIES})")
        total = sum(i.file_size for i in infos)
        if total > MAX_TOTAL_BYTES:
            raise UnsafeZip(f"uncompressed size too large ({total} > {MAX_TOTAL_BYTES} bytes)")
        for info in infos:
            target = (dest / info.filename).resolve()
            if not target.is_relative_to(dest_root):           # path traversal / absolute
                raise UnsafeZip(f"unsafe member path: {info.filename!r}")
            # skip symlinks (the high bits of external_attr encode the unix mode)
            if stat.S_ISLNK(info.external_attr >> 16):
                continue
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out, _COPY_CHUNK)
    # a github-style zip wraps everything in one top dir; use it as the repo root
    entries = list(dest.iterdir())
    root = entries[0] if len(entries) == 1 and entries[0].is_dir() else dest
    files = sum(1 for p in root.rglob("*") if p.is_file())
    if files == 0:
        raise UnsafeZip("the zip contained no files")
    return {"path": str(root), "files": files}
