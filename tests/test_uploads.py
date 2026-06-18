"""C3 — safe repo .zip upload: the extractor's safety rails + the /uploads endpoint feeding a run."""

import io
import zipfile

import pytest

from server.uploads import MAX_ENTRIES, UnsafeZip, extract_zip


def _zip(members: dict) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in members.items():
            zf.writestr(name, content)
    buf.seek(0)
    return buf


def test_extract_picks_single_top_dir(tmp_path):
    z = _zip({"myrepo/a.py": "x = 1\n", "myrepo/pkg/b.py": "y = 2\n"})
    info = extract_zip(z, tmp_path / "stg")
    assert info["files"] == 2
    assert info["path"].endswith("myrepo")                  # github-style single top dir -> repo root
    assert (tmp_path / "stg" / "myrepo" / "pkg" / "b.py").is_file()


def test_extract_flat_uses_dest_root(tmp_path):
    z = _zip({"a.py": "x = 1\n", "b.py": "y = 2\n"})
    info = extract_zip(z, tmp_path / "stg")
    assert info["files"] == 2 and info["path"].endswith("stg")


def test_extract_rejects_path_traversal(tmp_path):
    z = _zip({"../evil.py": "pwn\n"})
    with pytest.raises(UnsafeZip):
        extract_zip(z, tmp_path / "stg")
    assert not (tmp_path / "evil.py").exists()              # nothing escaped the dest


def test_extract_rejects_too_many_entries(tmp_path, monkeypatch):
    monkeypatch.setattr("server.uploads.MAX_ENTRIES", 3)
    z = _zip({f"r/f{i}.py": "x\n" for i in range(5)})
    with pytest.raises(UnsafeZip):
        extract_zip(z, tmp_path / "stg")


def test_extract_rejects_empty_and_bad_zip(tmp_path):
    with pytest.raises(UnsafeZip):
        extract_zip(_zip({}), tmp_path / "a")               # no files
    with pytest.raises(UnsafeZip):
        extract_zip(io.BytesIO(b"not a zip"), tmp_path / "b")
