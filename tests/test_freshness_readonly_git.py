"""Freshness fetch must work on the read-only repo copy ingest leaves behind (POSIX: the .git
directories lose their write bit, so git cannot create FETCH_HEAD)."""

import os
import stat

import pytest

from argo.stages.freshness import _make_git_metadata_writable
from argo.stages.ingest import _make_readonly


@pytest.mark.skipif(os.name == "nt", reason="directory write bits only matter on POSIX")
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores mode bits")
def test_git_dirs_writable_again_before_fetch(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git" / "refs" / "heads").mkdir(parents=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (repo / "a.txt").write_text("x")
    _make_readonly(repo)
    with pytest.raises(PermissionError):
        (repo / ".git" / "FETCH_HEAD").write_text("")
    _make_git_metadata_writable(repo)
    (repo / ".git" / "FETCH_HEAD").write_text("")              # git fetch writes this
    (repo / ".git" / "refs" / "heads" / "x").write_text("")
    assert not (repo / "a.txt").stat().st_mode & stat.S_IWUSR   # the source tree stays read-only
    _make_readonly(repo / ".git")
    for p in (repo / ".git").rglob("*"):
        p.chmod(p.stat().st_mode | stat.S_IWUSR)               # let tmp_path cleanup proceed
