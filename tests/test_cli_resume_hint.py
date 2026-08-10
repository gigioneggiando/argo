"""``cli._run_with_resume_hint`` — the wrapper around ``run_pipeline``/``resume_pipeline`` that
prints a clear pointer to ``argo resume <run_id>`` on any interruption, so a stopped run doesn't
read as total data loss to someone who doesn't already know the resume command exists.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
import typer

from argo.cli import _run_with_resume_hint


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
