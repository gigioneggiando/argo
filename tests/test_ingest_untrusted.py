"""Ingest of an untrusted LOCAL source: its .git/config must not execute anything, and making the
copy read-only must not touch files outside it through symlinks."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from argo.stages.ingest import _make_readonly, acquire_repo


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True).stdout.strip()


def _hostile_repo(tmp_path: Path) -> tuple[Path, str, Path]:
    repo = tmp_path / "untrusted"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-qm", "c1")
    marker = tmp_path / "EXECUTED.txt"
    hook = tmp_path / "hook.py"
    hook.write_text(f"open(r'{marker}', 'w').write('ran')\n", encoding="utf-8")
    cmd = f'"{sys.executable}" "{hook}"'
    _git(repo, "config", "core.fsmonitor", cmd)
    _git(repo, "config", "core.sshCommand", cmd)
    _git(repo, "config", "include.path", str(tmp_path / "evil.inc"))
    _git(repo, "remote", "add", "origin", "https://example.invalid/x.git")
    return repo, _git(repo, "rev-parse", "HEAD"), marker


def test_copied_git_config_runs_nothing(tmp_path):
    repo, sha, marker = _hostile_repo(tmp_path)
    dest = tmp_path / "copy"
    acquire_repo(str(repo), dest, is_url=False, commit=sha)
    assert not marker.exists()
    cfg = (dest / ".git" / "config").read_text(encoding="utf-8")
    for bad in ("fsmonitor", "sshCommand", "include"):
        assert bad not in cfg
    assert "https://example.invalid/x.git" in cfg                 # origin kept (freshness/incremental)
    assert _git(dest, "rev-parse", "HEAD") == sha                 # still a usable repository
    assert not (dest / ".git" / "hooks").exists()


def test_gitdir_pointer_file_is_dropped(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    (src / ".git").write_text(f"gitdir: {tmp_path / 'elsewhere'}\n", encoding="utf-8")
    dest = tmp_path / "copy"
    acquire_repo(str(src), dest, is_url=False)
    assert not (dest / ".git").exists() and (dest / "a.py").is_file()


def test_make_readonly_does_not_follow_symlinks(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "secret.txt"
    victim.write_text("keep me writable\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    try:
        (repo / "link_file").symlink_to(victim)
        (repo / "link_dir").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this platform does not allow creating symlinks")
    try:
        _make_readonly(repo)
        assert os.access(victim, os.W_OK)
        assert os.access(outside, os.W_OK)
        assert not os.access(repo / "a.py", os.W_OK)              # the repo itself is protected
    finally:
        os.chmod(repo / "a.py", 0o644)
