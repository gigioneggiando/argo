"""``cli._run_with_resume_hint`` — the wrapper around ``run_pipeline``/``resume_pipeline`` that
prints a clear pointer to ``argo resume <run_id>`` on any interruption, so a stopped run doesn't
read as total data loss to someone who doesn't already know the resume command exists.
"""

from __future__ import annotations

from types import SimpleNamespace
import json

import pytest
import typer

from argo.cli import _run_with_resume_hint
from typer.testing import CliRunner
from argo import cli


def _ctx(run_id="RUN-1"):
    return SimpleNamespace(run_id=run_id)


def test_returns_the_callable_result_on_success(capsys):
    result = _run_with_resume_hint(lambda: {"ok": True}, _ctx())
    assert result == {"ok": True}
    assert "argo resume" not in capsys.readouterr().err


def test_prints_the_resume_command_and_reraises_on_a_real_failure(capsys):
    def _boom():
        raise RuntimeError("codex exec: flagged for possible cybersecurity risk")

    with pytest.raises(RuntimeError):
        _run_with_resume_hint(_boom, _ctx("RUN-CRASHED"))
    err = capsys.readouterr().err
    assert "argo resume RUN-CRASHED" in err
    assert "flagged for possible cybersecurity risk" in err


def test_prints_the_resume_command_on_keyboard_interrupt_too(capsys):
    """Ctrl+C is the single most likely way a normal user's run gets interrupted -- it must get
    the same hint as a genuine exception, not vanish silently."""
    def _ctrl_c():
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        _run_with_resume_hint(_ctrl_c, _ctx("RUN-2"))
    assert "argo resume RUN-2" in capsys.readouterr().err


def test_does_not_print_the_hint_for_a_clean_typer_exit(capsys):
    """typer.Exit / SystemExit are the CLI's own normal control-flow signals (e.g. from an earlier
    typer.BadParameter), not a pipeline failure -- must pass through silently."""
    def _clean_exit():
        raise typer.Exit(code=1)

    with pytest.raises(typer.Exit):
        _run_with_resume_hint(_clean_exit, _ctx("RUN-3"))
    assert "argo resume" not in capsys.readouterr().err


@pytest.mark.parametrize("backend,overrides", [
    ("mistral-vibe", []), ("mock", ["--stage-runner", "audit=mistral-vibe"]),
])
def test_show_routing_exposes_vibe_auth(backend, overrides):
    result = CliRunner().invoke(cli.app, ["show-routing", "--runner", backend,
        "--mistral-vibe-auth", "stored", *overrides])
    assert result.exit_code == 0, result.output
    body = json.loads(result.output)
    assert body["mistral_vibe_auth"] == "stored"
    assert body["stages"]["audit"]["runner"] == "mistral-vibe"
    assert body["stages"]["audit"]["mistral_vibe_auth"] == "stored"


def test_build_config_accepts_stored_vibe_auth(tmp_path):
    cfg = cli._build_config("mock", None, False, None, 1, tmp_path, "happy",
                            mistral_vibe_auth="stored",
                            stage_runners=["audit=mistral-vibe"])
    assert cfg.mistral_vibe_auth == "stored"


@pytest.mark.parametrize("command,args", [
    ("ingest", ["--repo", "."]), ("estimate", ["--repo", "."]),
    ("pipeline", ["--repo", "."]), ("pipeline", ["--smoke"]),
])
def test_new_run_commands_propagate_stored_auth(monkeypatch, tmp_path, command, args):
    seen = []
    def capture(cfg, run):
        seen.append(cfg)
        raise RuntimeError("stop before any runner call")
    monkeypatch.setattr(cli, "build_context", capture)
    result = CliRunner().invoke(cli.app, [command, "--runner", "mock",
        "--runs-dir", str(tmp_path), "--mistral-vibe-auth", "stored", *args])
    assert seen, result.output
    assert seen[0].mistral_vibe_auth == "stored"


def test_bench_propagates_stored_auth(monkeypatch, tmp_path):
    from argo import benchmark
    seen = []
    def fake_suite(cfg, suite, **kwargs):
        seen.append(cfg)
        return {"fake": True}
    monkeypatch.setattr(benchmark, "run_suite", fake_suite)
    result = CliRunner().invoke(cli.app, ["bench", "--suite", str(tmp_path),
        "--runner", "mock", "--mistral-vibe-auth", "stored"])
    assert result.exit_code == 0, result.output
    assert seen[0].mistral_vibe_auth == "stored"


@pytest.mark.parametrize("mode", [None, "stored"])
def test_resume_retains_saved_auth_without_cli_default(monkeypatch, tmp_path, mode):
    run_dir = tmp_path / "SAVED"
    run_dir.mkdir()
    saved = {"runner": "mock", "runs_dir": str(tmp_path)}
    if mode:
        saved["mistral_vibe_auth"] = mode
    (run_dir / "config.json").write_text(json.dumps(saved), encoding="utf-8")
    seen = []
    def fake_context(cfg, run):
        seen.append(cfg)
        return SimpleNamespace(config=cfg, run_id=run)
    monkeypatch.setattr(cli, "build_context", fake_context)
    monkeypatch.setattr(cli, "resume_pipeline", lambda ctx: {"fake": True})
    result = CliRunner().invoke(cli.app, ["resume", "--run", "SAVED", "--runs-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert seen[0].mistral_vibe_auth == (mode or "key")
