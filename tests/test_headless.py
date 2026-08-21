"""Headless-seam hardening: strict parser over the REAL captured envelope, per-session caps,
and robust error handling on the subprocess path. No tokens spent."""

import json
import shutil
from pathlib import Path

import pytest

import argo.runner as runner_mod
from argo.config import HAIKU, PipelineConfig
from argo.ledger import Ledger
from argo.runner import (ClaudeRunner, HeadlessClaudeRunner, RunnerError,
                             parse_result_envelope)

from conftest import FIXTURES

REAL = json.loads((FIXTURES / "real_envelope.json").read_text(encoding="utf-8"))

#: _build_cmd/_invoke resolve the real `claude` binary via shutil.which() before doing anything
#: else (even with _exec mocked away) -- these tests need it actually installed, unlike the rest
#: of the suite (mock runner, zero tokens). Same skip-if-tool-missing pattern as the Docker-gated
#: test in test_runtime.py.
needs_claude_cli = pytest.mark.skipif(not shutil.which("claude"), reason="claude CLI not installed")


# --------------------------------------------------------------------- parser (Step 2)
def test_parser_over_real_envelope():
    r = parse_result_envelope(REAL, model="m", prompt_sha256="h", work_dir=Path("."))
    assert r.text == "ok"
    assert r.cost_usd == 0.0160078                 # real total_cost_usd
    assert r.input_tokens == 9 and r.output_tokens == 42
    assert r.num_turns == 1
    assert r.session_id == "de1a6cc6-03e3-4ab0-a614-1c8594feff6a"
    assert r.stop_reason == "end_turn"             # real stop_reason field
    assert r.is_error is False and r.api_error_status is None


def test_parser_fails_loud_on_shape_drift():
    drifted = {"is_error": False, "result": "x", "usage": {},
               "num_turns": 1, "session_id": "s"}   # missing total_cost_usd
    with pytest.raises(RunnerError) as e:
        parse_result_envelope(drifted, model="m", prompt_sha256="h", work_dir=Path("."))
    assert "total_cost_usd" in str(e.value)


def test_parser_rejects_non_envelope():
    with pytest.raises(RunnerError):
        parse_result_envelope({"foo": "bar"}, model="m", prompt_sha256="h", work_dir=Path("."))


# ---- a runner that returns a crafted envelope (drives run() without a subprocess) ----
class _EnvelopeRunner(ClaudeRunner):
    def __init__(self, config, ledger, envelope):
        super().__init__(config, ledger)
        self._env = envelope

    def _invoke(self, **kw):
        return self._env


def _run(cfg, ledger, env, tmp_path, *, stage="audit"):
    return _EnvelopeRunner(cfg, ledger, env).run(
        prompt="p", run_dir=tmp_path / "r", work_dir=tmp_path / "r" / "w",
        model="m", stage=stage, run_id="R")


# --------------------------------------------------------------------- caps (Step 3)
def test_recoverable_is_error_raises_after_logging(tmp_path):
    ledger = Ledger(tmp_path / "l.sqlite")
    env = {"is_error": True, "api_error_status": None, "result": "partial",
           "usage": {"input_tokens": 1, "output_tokens": 2}, "total_cost_usd": 0.02,
           "num_turns": 2, "session_id": "s", "stop_reason": "max_budget"}
    with pytest.raises(RunnerError) as e:
        _run(PipelineConfig(), ledger, env, tmp_path)
    assert e.value.retryable is True
    assert ledger.run_call_count("R") == 1                   # logged even on error
    ledger.close()


def test_api_error_raises_loud_after_logging(tmp_path):
    ledger = Ledger(tmp_path / "l.sqlite")
    env = {"is_error": True, "api_error_status": "authentication_error", "result": "bad key",
           "usage": {}, "total_cost_usd": 0.0, "num_turns": 0, "session_id": None}
    with pytest.raises(RunnerError) as e:
        _run(PipelineConfig(), ledger, env, tmp_path, stage="ingest")
    assert "authentication_error" in str(e.value)
    assert ledger.run_call_count("R") == 1                   # cost logged before raising
    ledger.close()


def test_failure_kind_and_duration_are_persisted_to_the_ledger(tmp_path):
    """Latency + refusal classification are now persisted at the SAME chokepoint every backend
    funnels through (_run_attempt), for the cross-backend/refusal-rate benchmarks -- previously
    failure_kind existed only inside a raised RunnerError's attributes, never queryable after the
    fact."""
    ledger = Ledger(tmp_path / "l.sqlite")
    env = {"is_error": True, "api_error_status": None,
           "result": "API Error: Opus 4.8's safeguards flagged this message.",
           "usage": {"input_tokens": 1, "output_tokens": 1}, "total_cost_usd": 0.0,
           "num_turns": 1, "session_id": "s"}
    with pytest.raises(RunnerError) as e:
        _run(PipelineConfig(), ledger, env, tmp_path, stage="audit")
    assert e.value.failure_kind == "moderation_flagged"
    rows = ledger.run_calls("R")
    assert len(rows) == 1
    assert rows[0]["failure_kind"] == "moderation_flagged"
    assert rows[0]["duration_ms"] >= 0
    ledger.close()


def test_classify_failure_text_called_exactly_once_per_attempt(tmp_path, monkeypatch):
    """Regression for the classify-once refactor: previously _classify_failure_text was invoked
    separately by the 'hard API error' and 'recoverable error' branches -- now it's computed once
    and reused by both."""
    import argo.runner as runner_mod
    calls = []
    real = runner_mod._classify_failure_text

    def _spy(text):
        calls.append(text)
        return real(text)

    monkeypatch.setattr(runner_mod, "_classify_failure_text", _spy)
    ledger = Ledger(tmp_path / "l.sqlite")
    env = {"is_error": True, "api_error_status": "authentication_error", "result": "bad key",
           "usage": {}, "total_cost_usd": 0.0, "num_turns": 0, "session_id": None}
    with pytest.raises(RunnerError):
        _run(PipelineConfig(), ledger, env, tmp_path, stage="ingest")
    assert len(calls) == 1
    ledger.close()


def test_max_turns_tripwire(tmp_path):
    ledger = Ledger(tmp_path / "l.sqlite")
    env = {"is_error": False, "result": "x", "usage": {"input_tokens": 1, "output_tokens": 1},
           "total_cost_usd": 0.0, "num_turns": 99, "session_id": "s"}
    with pytest.raises(RunnerError) as e:
        _run(PipelineConfig(session_max_turns=5), ledger, env, tmp_path)
    assert "max_turns" in str(e.value)
    ledger.close()


def test_session_cost_cap(tmp_path):
    ledger = Ledger(tmp_path / "l.sqlite")
    env = {"is_error": False, "result": "x", "usage": {"input_tokens": 1, "output_tokens": 1},
           "total_cost_usd": 5.0, "num_turns": 1, "session_id": "s"}
    with pytest.raises(RunnerError) as e:
        _run(PipelineConfig(session_max_cost_usd=0.10), ledger, env, tmp_path)
    assert "cost cap" in str(e.value)
    ledger.close()


def test_session_budget_uses_remaining_run_budget(tmp_path):
    ledger = Ledger(tmp_path / "l.sqlite")
    runner = HeadlessClaudeRunner(PipelineConfig(budget_usd=1.0), ledger)
    assert runner._session_budget("R") == 1.0
    ledger.log_call(run_id="R", stage="audit", model="m", prompt_sha256="h", cost_usd=0.7)
    assert abs(runner._session_budget("R") - 0.3) < 1e-9
    tighter = HeadlessClaudeRunner(
        PipelineConfig(budget_usd=1.0, session_max_cost_usd=0.1), ledger)
    assert tighter._session_budget("R") == 0.1               # min(0.1, remaining 0.3)
    ledger.close()


# --------------------------------------------------------------------- flags (Step 1/3)
@needs_claude_cli
def test_build_cmd_caps_and_no_max_turns(tmp_path):
    ledger = Ledger(tmp_path / "l.sqlite")
    cmd = HeadlessClaudeRunner(PipelineConfig(), ledger)._build_cmd(
        model="m", repo_dir=None, allowed=["Read"], disallowed=["Bash"], session_budget_usd=0.5)
    assert "--max-budget-usd" in cmd and cmd[cmd.index("--max-budget-usd") + 1] == "0.5000"
    assert "--max-turns" not in cmd                          # this CLI version has no such flag
    ledger.close()


# --------------------------------------------------------------------- subprocess errors (Step 4)
class _FakeProc:
    def __init__(self, stdout, stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


def _invoke(runner, tmp_path):
    return runner._invoke(prompt="p", work_dir=tmp_path, model="m", repo_dir=None,
                          allowed=["Read"], disallowed=["Bash"], stage="ingest",
                          run_id="R", label="x", timeout_s=5)


@needs_claude_cli
def test_invoke_raises_on_empty_stdout(tmp_path, monkeypatch):
    ledger = Ledger(tmp_path / "l.sqlite")
    runner = HeadlessClaudeRunner(PipelineConfig(), ledger)
    monkeypatch.setattr(runner, "_exec", lambda *a, **k: _FakeProc("", "auth failed", 1))
    with pytest.raises(RunnerError) as e:
        _invoke(runner, tmp_path)
    assert "no parseable JSON envelope" in str(e.value)
    assert "auth failed" in str(e.value)                     # stderr surfaced
    ledger.close()


def test_invoke_raises_on_malformed_json(tmp_path, monkeypatch):
    ledger = Ledger(tmp_path / "l.sqlite")
    runner = HeadlessClaudeRunner(PipelineConfig(), ledger)
    monkeypatch.setattr(runner, "_exec", lambda *a, **k: _FakeProc("not json {", "", 0))
    with pytest.raises(RunnerError):
        _invoke(runner, tmp_path)
    ledger.close()


@needs_claude_cli
def test_invoke_returns_envelope_even_on_nonzero_exit(tmp_path, monkeypatch):
    ledger = Ledger(tmp_path / "l.sqlite")
    runner = HeadlessClaudeRunner(PipelineConfig(), ledger)
    env = json.dumps({"is_error": True, "api_error_status": None, "result": "x", "usage": {},
                      "total_cost_usd": 0.0, "num_turns": 1, "session_id": "s"})
    monkeypatch.setattr(runner, "_exec", lambda *a, **k: _FakeProc(env, "", 2))
    out = _invoke(runner, tmp_path)                          # non-zero exit but valid envelope
    assert out["is_error"] is True
    ledger.close()


@needs_claude_cli
def test_invoke_injects_anthropic_api_key_env(tmp_path, monkeypatch):
    ledger = Ledger(tmp_path / "l.sqlite")
    runner = HeadlessClaudeRunner(PipelineConfig(claude_api_key="sk-ant-test"), ledger)
    captured = {}
    def fake_exec(cmd, prompt, cwd, timeout, env=None):
        captured["env"] = env
        return _FakeProc("not json {")
    monkeypatch.setattr(runner, "_exec", fake_exec)
    with pytest.raises(RunnerError):
        _invoke(runner, tmp_path)
    assert captured["env"]["ANTHROPIC_API_KEY"] == "sk-ant-test"
    ledger.close()


@needs_claude_cli
def test_invoke_injects_both_claude_config_dir_and_api_key_additively(tmp_path, monkeypatch):
    """claude_api_key is a SEPARATE mechanism from claude_config_dir (a directory path, not a
    secret value) -- when both are set they're additive (two different env vars, no collision),
    not mutually exclusive."""
    ledger = Ledger(tmp_path / "l.sqlite")
    runner = HeadlessClaudeRunner(
        PipelineConfig(claude_config_dir=str(tmp_path), claude_api_key="sk-ant-test"), ledger)
    captured = {}
    def fake_exec(cmd, prompt, cwd, timeout, env=None):
        captured["env"] = env
        return _FakeProc("not json {")
    monkeypatch.setattr(runner, "_exec", fake_exec)
    with pytest.raises(RunnerError):
        _invoke(runner, tmp_path)
    assert captured["env"]["ANTHROPIC_API_KEY"] == "sk-ant-test"
    assert captured["env"]["CLAUDE_CONFIG_DIR"] == str(tmp_path)
    ledger.close()


@needs_claude_cli
def test_invoke_env_stays_none_when_neither_claude_knob_set(tmp_path, monkeypatch):
    """Regression: byte-identical to pre-feature behavior when neither claude_config_dir nor
    claude_api_key is configured."""
    ledger = Ledger(tmp_path / "l.sqlite")
    runner = HeadlessClaudeRunner(PipelineConfig(), ledger)
    captured = {}
    def fake_exec(cmd, prompt, cwd, timeout, env=None):
        captured["env"] = env
        return _FakeProc("not json {")
    monkeypatch.setattr(runner, "_exec", fake_exec)
    with pytest.raises(RunnerError):
        _invoke(runner, tmp_path)
    assert captured["env"] is None
    ledger.close()


# --------------------------------------------------------------------- partial recovery (Step 4)
class _DyingRunner(ClaudeRunner):
    """Writes a valid findings file into the scratch dir, then dies hard (RunnerError)."""
    FINDINGS = {
        "program_name": "Acme Widgets", "audit_focus": "x",
        "generated_at": "2026-06-16T12:00:00Z",
        "findings": [{
            "id": "X-1", "title": "t", "severity": "High", "confidence": "High",
            "cwe": "CWE-89", "affected": ["src/api/search.py:42"],
            "vulnerable_flow": "f", "why_vulnerable": "w", "exploit_scenario": "e",
            "impact": "i", "recommended_fix": "r"}],
    }

    def _invoke(self, *, work_dir, **kw):
        (work_dir / f"SECURITY_FINDINGS__{work_dir.name}.json").write_text(
            json.dumps(self.FINDINGS), encoding="utf-8")
        raise RunnerError("session crashed mid-write")


def test_audit_recovers_partial_artifact_on_hard_failure(env, monkeypatch):
    from argo.orchestrator import do_audit, do_ingest, do_recon
    from conftest import BRIEF, REPO
    ctx = env()
    do_ingest(ctx, BRIEF, str(REPO))
    do_recon(ctx)
    ctx.runner = _DyingRunner(ctx.config, ctx.ledger)        # sessions now die mid-write
    findings = do_audit(ctx)
    assert findings, "partial findings should be recovered from the scratch dir"
    assert all(p.exists() for p in findings)


def test_api_and_cli_claude_api_key_passthrough(tmp_path):
    # API: RunConfig -> PipelineConfig mapping
    from server.jobs import JobManager
    from server.schemas import RunConfig, RunRequest
    jm = JobManager(PipelineConfig(runs_dir=tmp_path / "runs", ledger_path=tmp_path / "l.sqlite"))
    cfg = jm._config_for(RunRequest(brief="b", repo="r", config=RunConfig(
        runner="headless", claude_api_key="sk-ant-api-test")))
    assert cfg.runner == "headless" and cfg.claude_api_key == "sk-ant-api-test"
    # CLI: _build_config passthrough (single value + comma-split multi-account list)
    from argo.cli import _build_config
    c2 = _build_config("headless", None, False, None, 3, tmp_path / "runs", "happy",
                       claude_api_key="sk-ant-cli-test", claude_api_keys="sk-a,sk-b")
    assert c2.claude_api_key == "sk-ant-cli-test"
    assert c2.claude_api_keys == ["sk-a", "sk-b"]


def test_claude_cli_key_options_offer_non_argv_environment_ingress():
    from argo.cli import ClaudeApiKeyOpt, ClaudeApiKeysOpt
    assert ClaudeApiKeyOpt.envvar == "ARGO_CLAUDE_API_KEY"
    assert ClaudeApiKeysOpt.envvar == "ARGO_CLAUDE_API_KEYS"


@needs_claude_cli
def test_claude_failure_diagnostics_redact_configured_key(tmp_path, monkeypatch):
    ledger = Ledger(tmp_path / "l.sqlite")
    key = "sk-ant-must-not-persist"
    runner = HeadlessClaudeRunner(PipelineConfig(claude_api_key=key), ledger)
    monkeypatch.setattr(runner, "_exec", lambda *a, **k: _FakeProc("bad " + key, "oops " + key, 1))
    with pytest.raises(RunnerError) as exc_info:
        _invoke(runner, tmp_path)
    assert key not in str(exc_info.value)
    assert str(exc_info.value).count("<redacted>") == 2
    ledger.close()
