"""cli_versions resolves each CLI through PATH/PATHEXT first: on Windows npm installs ``claude.cmd``
and a bare ``claude`` argv[0] fails in CreateProcess, so the run's provenance recorded None."""

import subprocess

from argo import provenance


def test_cli_versions_uses_resolved_path(monkeypatch):
    seen = []
    monkeypatch.setattr(provenance.shutil, "which",
                        lambda name: rf"C:\npm\{name}.cmd" if name != "vibe" else None)

    def fake_run(command, **kw):
        seen.append(command[0])
        if command[0] == "vibe":
            raise FileNotFoundError
        return subprocess.CompletedProcess(command, 0, stdout=f"{command[0]} 1.0\nextra\n", stderr="")

    monkeypatch.setattr(provenance.subprocess, "run", fake_run)
    out = provenance.cli_versions()
    assert seen == [r"C:\npm\claude.cmd", r"C:\npm\codex.cmd", r"C:\npm\gemini.cmd", "vibe"]
    assert out["claude"] == r"C:\npm\claude.cmd 1.0"
    assert out["vibe"] is None
