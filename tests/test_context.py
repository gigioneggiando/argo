"""``context.atomic_write_json`` — the temp-file + os.replace helper stage outputs use so a hard
kill mid-write can never leave a torn/corrupt file behind for the next stage or a resumed run.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argo.context import atomic_write_json


def test_writes_correct_content_and_leaves_no_tmp_file(tmp_path):
    path = tmp_path / "validated_findings.json"
    atomic_write_json(path, {"findings": [{"id": "F-1"}]})
    assert json.loads(path.read_text(encoding="utf-8")) == {"findings": [{"id": "F-1"}]}
    assert not path.with_suffix(".json.tmp").exists()


def test_creates_missing_parent_directories(tmp_path):
    path = tmp_path / "nested" / "dir" / "out.json"
    atomic_write_json(path, {"ok": True})
    assert json.loads(path.read_text(encoding="utf-8")) == {"ok": True}


def test_a_write_that_fails_before_replace_never_touches_the_original(tmp_path, monkeypatch):
    """The core guarantee: if the process dies (or errors) after writing the temp file but before
    the atomic replace, the file a resumed run would read is still the LAST GOOD version — never a
    half-written one. Simulated by making ``Path.replace`` raise partway through."""
    path = tmp_path / "validated_findings.json"
    atomic_write_json(path, {"version": 1})  # a real "last good" file already on disk

    def _boom(self, target):
        raise OSError("simulated kill mid-replace")

    monkeypatch.setattr(Path, "replace", _boom, raising=True)
    with pytest.raises(OSError):
        atomic_write_json(path, {"version": 2})

    # the original, valid file is untouched -- a resumed run reads version 1, not a torn file
    assert json.loads(path.read_text(encoding="utf-8")) == {"version": 1}


def test_retries_transient_windows_permission_error_then_succeeds(tmp_path, monkeypatch):
    path = tmp_path / "out.json"
    attempts = {"n": 0}
    real_replace = Path.replace

    def _flaky_replace(self, target):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise PermissionError("WinError 5: simulated concurrent reader")
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", _flaky_replace, raising=True)
    monkeypatch.setattr("argo.context.time.sleep", lambda _: None)  # don't actually sleep in tests
    atomic_write_json(path, {"ok": True})
    assert attempts["n"] == 3
    assert json.loads(path.read_text(encoding="utf-8")) == {"ok": True}


def test_raises_after_persistent_permission_error_instead_of_silently_dropping(tmp_path, monkeypatch):
    """Unlike progress.py's telemetry writer (which may drop an update rather than crash the run),
    a stage's real output must never be silently lost -- persistent failure must raise."""
    path = tmp_path / "out.json"

    def _always_locked(self, target):
        raise PermissionError("WinError 5: still locked")

    monkeypatch.setattr(Path, "replace", _always_locked, raising=True)
    monkeypatch.setattr("argo.context.time.sleep", lambda _: None)
    with pytest.raises(PermissionError):
        atomic_write_json(path, {"ok": True})
