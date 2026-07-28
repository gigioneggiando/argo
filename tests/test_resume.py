import json
from datetime import datetime, timedelta, timezone

import pytest
from typer.testing import CliRunner

import argo.orchestrator as orchestrator
from argo.cli import app
from argo.config import PipelineConfig, load_pipeline_config
from argo.ledger import Ledger
from argo.orchestrator import build_context, resume_pipeline, run_pipeline
from argo.runner import AgentRunner, FallbackRunner, RunnerError, parse_retry_after

from conftest import BRIEF, FIXED_NOW, REPO


def _log_stages(run_dir):
    p = run_dir / "llm_log.jsonl"
    if not p.exists():
        return []
    return [json.loads(line)["stage"] for line in p.read_text(encoding="utf-8").splitlines()]


def test_resume_from_failed_validate_skips_done_stages_and_uses_persisted_config(env, monkeypatch):
    ctx = env(verify_enabled=True, corroborate_enabled=False, sca_enabled=False)
    retry_after = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    original_validate = orchestrator.do_validate

    def fail_validate(_ctx):
        raise RunnerError("session limit", retry_after=retry_after, retryable=True)

    monkeypatch.setattr(orchestrator, "do_validate", fail_validate)
    with pytest.raises(RunnerError):
        run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)

    status = json.loads((ctx.run_dir / "status.json").read_text(encoding="utf-8"))
    failed = {s["name"]: s for s in status["stages"]}["validate"]
    assert failed["state"] == "failed"
    assert failed["retry_after"] == retry_after

    cfg = load_pipeline_config(ctx.run_dir / "config.json")
    assert cfg.research_enabled is False
    assert cfg.corroborate_enabled is False
    assert cfg.verify_enabled is True

    before = _log_stages(ctx.run_dir)
    monkeypatch.setattr(orchestrator, "do_validate", original_validate)
    for name in ("do_ingest", "do_research", "do_recon", "do_audit", "do_corroborate"):
        monkeypatch.setattr(
            orchestrator, name,
            lambda *_a, _name=name, **_k: pytest.fail(f"{_name} should not be re-run"))

    resumed = build_context(cfg, ctx.run_id, now=FIXED_NOW)
    summary = resume_pipeline(resumed)
    assert summary["resumed_from"] == "validate"
    assert (ctx.run_dir / "REPORT.md").exists()

    after = _log_stages(ctx.run_dir)
    appended = after[len(before):]
    assert appended[0] == "validate"
    assert "audit" not in appended and "recon" not in appended and "corroborate" not in appended
    status = json.loads((ctx.run_dir / "status.json").read_text(encoding="utf-8"))
    states = {s["name"]: s["state"] for s in status["stages"]}
    assert states["validate"] == "done"
    assert states["verify"] == "done"
    assert states["report"] == "done"
    assert "corroborate" not in states


def test_resume_cli_missing_config_fails_clear(tmp_path):
    run_id = "OLD-RUN"
    run_dir = tmp_path / "runs" / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "status.json").write_text(json.dumps({
        "run_id": run_id,
        "state": "failed",
        "stages": [{"name": "validate", "state": "failed"}],
    }), encoding="utf-8")

    result = CliRunner().invoke(app, ["resume", "--run", run_id, "--runs-dir", str(tmp_path / "runs")])
    assert result.exit_code != 0
    assert "config.json is missing" in result.output
    assert "manual per-stage commands" in result.output


class _NoStatusErrorRunner(AgentRunner):
    def _invoke(self, **_kw):
        return {
            "is_error": True,
            "api_error_status": None,
            "result": "codex crashed without structured status",
            "usage": {"input_tokens": 1, "output_tokens": 1},
            "total_cost_usd": 0.0,
            "num_turns": 1,
            "session_id": "s",
            "stop_reason": "crash",
        }


class _Backend:
    def __init__(self, name, behavior):
        self.config = PipelineConfig(runner=name)
        self.cancel_event = None
        self.behavior = behavior
        self.calls = 0

    def run(self, **kw):
        self.calls += 1
        return self.behavior(kw)


def test_is_error_without_api_status_falls_back_to_next_backend(tmp_path):
    ledger = Ledger(tmp_path / "l.sqlite")
    try:
        primary = _NoStatusErrorRunner(PipelineConfig(runner="headless"), ledger)
        fallback = _Backend("codex", lambda _kw: "FALLBACK-OK")
        runner = FallbackRunner(PipelineConfig(), ledger, [primary, fallback])
        got = runner.run(
            prompt="p", run_dir=tmp_path / "run", work_dir=tmp_path / "run" / "work",
            model="m", stage="audit", run_id="R")
        assert got == "FALLBACK-OK"
        assert fallback.calls == 1
    finally:
        ledger.close()


def test_fallback_backend_rearms_after_retry_after(tmp_path):
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    primary = _Backend(
        "headless",
        lambda _kw: (_ for _ in ()).throw(
            RunnerError("session limit", retry_after=future, retryable=True)))
    fallback = _Backend("codex", lambda _kw: "FALLBACK")
    runner = FallbackRunner(PipelineConfig(), None, [primary, fallback])

    assert runner.run(prompt="p", run_dir=tmp_path, work_dir=tmp_path, model="m",
                      stage="validate", run_id="R") == "FALLBACK"
    primary.behavior = lambda _kw: "PRIMARY"
    assert runner.run(prompt="p", run_dir=tmp_path, work_dir=tmp_path, model="m",
                      stage="validate", run_id="R") == "FALLBACK"
    assert primary.calls == 1

    runner._disabled[0] = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert runner.run(prompt="p", run_dir=tmp_path, work_dir=tmp_path, model="m",
                      stage="validate", run_id="R") == "PRIMARY"
    assert primary.calls == 2


def test_parse_retry_after_malformed_timezone_does_not_raise():
    # A reset hint like "5pm (<garbage>)" must never crash the fallback chain just because the
    # parenthetical isn't a real IANA zone -- ZoneInfo raises plain ValueError (not
    # ZoneInfoNotFoundError) for a malformed key (path-traversal-shaped, embedded NUL, ...).
    for hint in ("5pm (Not/AZone)", "5pm (../../etc)", "5pm (\x00)"):
        assert parse_retry_after(hint) is not None
