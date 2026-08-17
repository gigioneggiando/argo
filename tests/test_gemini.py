"""Gemini backend: command-construction guardrails (Policy Engine, not --sandbox — see
argo/runner.py's module comments for why), envelope parsing over a REAL captured call, and the
heuristic soft-refusal -> moderation_flagged bridge.

Every design choice under test was verified against a real `gemini` CLI (v0.49.0, 2026-08-17)
before being written, per the Gemini backend plan's Phase 0 — this file's docstrings cite what was
actually observed, not assumed.
"""

import json
import subprocess
from pathlib import Path

import pytest

from argo.config import GEMINI_FLASH, GEMINI_FLASH_LITE, GEMINI_PRO, PipelineConfig, estimate_cost_usd
from argo.guardrails import session_policy
from argo.ledger import Ledger
from argo.runner import (GeminiRunner, RunnerError, _GEMINI_MODERATION_MARKER,
                         _GEMINI_POLICY_NETWORK, _GEMINI_POLICY_OFFLINE, _classify_failure_text,
                         _looks_like_gemini_refusal, build_runner)

from conftest import FIXTURES

REAL = json.loads((FIXTURES / "real_gemini_envelope.json").read_text(encoding="utf-8"))


def _runner(tmp_path, **cfg):
    r = GeminiRunner(PipelineConfig(runner="gemini", **cfg), Ledger(tmp_path / "l.sqlite"))
    r._resolved_bin = "gemini"   # avoid a PATH dependency in CI
    return r


# --------------------------------------------------------------- command construction
def test_build_cmd_is_headless_safe_and_stdin_only(tmp_path):
    r = _runner(tmp_path)
    cmd = r._build_gemini_cmd(model="m", repo_dir=None, policy_file=tmp_path / "p.toml")
    # stdin-only: no -p anywhere (confirmed live -- stdin alone triggers the same JSON path)
    assert "-p" not in cmd
    # trusted-folder + non-interactive auto-approve (confirmed live: --skip-trust is REQUIRED or
    # the CLI exits 55 in a fresh, never-interactively-trusted scratch dir)
    assert "--skip-trust" in cmd
    assert cmd[cmd.index("--approval-mode") + 1] == "yolo"
    assert cmd[cmd.index("-m") + 1] == "m"
    assert cmd[cmd.index("--output-format") + 1] == "json"
    # NEVER a sandbox dependency (confirmed live: --sandbox failed outright, hard Docker/Podman
    # dependency, replaced by the Policy Engine -- see _GEMINI_POLICY_OFFLINE's docstring)
    assert "--sandbox" not in cmd
    r.ledger.close()


def test_build_cmd_includes_repo_dir_for_read_access(tmp_path):
    r = _runner(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    cmd = r._build_gemini_cmd(model="m", repo_dir=repo, policy_file=tmp_path / "p.toml")
    assert cmd[cmd.index("--include-directories") + 1] == str(repo.resolve())
    without = r._build_gemini_cmd(model="m", repo_dir=None, policy_file=tmp_path / "p.toml")
    assert "--include-directories" not in without
    r.ledger.close()


# --------------------------------------------------------------- Policy Engine guardrails (_invoke)
class _FakeProc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


def _invoke(r, tmp_path, **overrides):
    kw = dict(prompt="p", work_dir=tmp_path, model="m", repo_dir=None,
              allowed=["Read"], disallowed=[], policy=session_policy("audit"), stage="audit",
              run_id="R", label="x", timeout_s=5)
    kw.update(overrides)
    return r._invoke(**kw)


def _success_envelope(text="ok", session_id="s1"):
    return json.dumps({"session_id": session_id, "response": text, "stats": {"models": {}}})


def test_offline_stage_denies_shell_and_web_tools(tmp_path, monkeypatch):
    r = _runner(tmp_path)
    monkeypatch.setattr(r, "_exec", lambda *a, **k: _FakeProc(_success_envelope(), "", 0))
    _invoke(r, tmp_path, policy=session_policy("audit"))
    written = (tmp_path / ".argo_gemini_policy.toml").read_text(encoding="utf-8")
    assert written == _GEMINI_POLICY_OFFLINE
    assert "run_shell_command" in written and "google_web_search" in written and "web_fetch" in written
    r.ledger.close()


def test_only_research_and_corroborate_get_network(tmp_path, monkeypatch):
    r = _runner(tmp_path)
    monkeypatch.setattr(r, "_exec", lambda *a, **k: _FakeProc(_success_envelope(), "", 0))
    for stage in ("research", "corroborate"):
        _invoke(r, tmp_path, policy=session_policy(stage))
        written = (tmp_path / ".argo_gemini_policy.toml").read_text(encoding="utf-8")
        assert written == _GEMINI_POLICY_NETWORK
        assert "google_web_search" not in written and "web_fetch" not in written
        assert "run_shell_command" in written   # shell stays denied even here
    for stage in ("ingest", "recon", "audit", "validate", "report", "remediate", "verify"):
        _invoke(r, tmp_path, policy=session_policy(stage))
        assert (tmp_path / ".argo_gemini_policy.toml").read_text(encoding="utf-8") == _GEMINI_POLICY_OFFLINE
    r.ledger.close()


# --------------------------------------------------------------- envelope parsing (real capture)
def test_parser_over_real_envelope_sums_all_stats_models():
    """The real capture has TWO entries in stats.models (an unpinned call -- omitting -m triggers
    an extra internal 'utility_router' model pick, confirmed live 2026-08-17): gemini-3.1-flash-lite
    (prompt=2929, candidates=38) and gemini-3.5-flash (prompt=9373, candidates=1). Argo always pins
    -m so this specific shape is rare in practice, but parse_envelope must not assume exactly one
    entry -- this fixture organically exercises that without a synthetic multi-model construction."""
    r = GeminiRunner.__new__(GeminiRunner)  # parse_envelope doesn't touch self; skip __init__
    res = r.parse_envelope(REAL, model="gemini-3.5-flash", prompt_sha256="h", work_dir=Path("."))
    assert res.text == "OK"
    assert res.input_tokens == 2929 + 9373
    assert res.output_tokens == 38 + 1
    assert res.session_id == "30fae387-c78c-4f36-8976-48caced18ed5"
    assert res.is_error is False
    assert res.cost_usd > 0


def test_parser_error_shape():
    """Real observed error envelope shape (a 429 quota error, captured live 2026-08-17): a clean
    {"error": {type, message, code}} JSON on stdout alongside exit 1 -- NOT the 'no output at all'
    shape (that's handled in _invoke, before parse_envelope ever sees it)."""
    raw = {"session_id": "s2", "error": {"type": "Error",
           "message": "You exceeded your current quota, please check your plan and billing "
                      "details. ... Please retry in 23.229712457s.", "code": 1}, "_exit_code": 1}
    r = GeminiRunner.__new__(GeminiRunner)
    res = r.parse_envelope(raw, model="gemini-3.1-pro", prompt_sha256="h", work_dir=Path("."))
    assert res.is_error is True
    assert "exceeded your current quota" in res.text
    assert res.stop_reason == "exit_1"
    assert _classify_failure_text(res.text) == "rate_limited"   # "quota" hint, real observed wording


# --------------------------------------------------------------- heuristic refusal -> moderation bridge
def test_looks_like_gemini_refusal_requires_cooccurrence():
    real_observed = ("I cannot provide a command or instructions intended to destroy filesystems "
                     "or disrupt production servers as part of an unauthorized attack.")
    assert _looks_like_gemini_refusal(real_observed) is True
    # "I cannot provide X" alone (no safety-flavored word) is a mundane, non-refusal reply --
    # must NOT false-positive, or a normal clarifying answer would get treated as a moderation flag.
    mundane = "I cannot provide the exact commit hash without more context, can you clarify?"
    assert _looks_like_gemini_refusal(mundane) is False


def test_parse_envelope_bridges_soft_refusal_to_moderation_flagged():
    """THE bridge test: a soft refusal arrives as a NORMAL SUCCESS envelope (confirmed live
    2026-08-17 -- no structured finishReason field is surfaced by the CLI). parse_envelope must
    still force is_error=True and embed a marker the SHARED _classify_failure_text can match, so
    _run_attempt's generic error path (and run()'s neutral-register retry) fires exactly like it
    does for Claude's/Codex's own fixed refusal signatures -- proving the bridge actually plugs
    into the unmodified fallback machinery, not just that the heuristic itself works standalone."""
    raw = {"session_id": "s3", "response": (
        "I cannot provide a command or instructions intended to destroy filesystems or disrupt "
        "production servers as part of an unauthorized attack."), "stats": {"models": {}}}
    r = GeminiRunner.__new__(GeminiRunner)
    res = r.parse_envelope(raw, model="m", prompt_sha256="h", work_dir=Path("."))
    assert res.is_error is True
    assert _GEMINI_MODERATION_MARKER in res.text
    assert _classify_failure_text(res.text) == "moderation_flagged"


def test_parse_envelope_normal_success_is_not_flagged():
    raw = {"session_id": "s4", "response": "Findings written to SECURITY_FINDINGS__auth.json.",
           "stats": {"models": {}}}
    r = GeminiRunner.__new__(GeminiRunner)
    res = r.parse_envelope(raw, model="m", prompt_sha256="h", work_dir=Path("."))
    assert res.is_error is False


# --------------------------------------------------------------- exit codes (_invoke)
def test_invoke_exit_42_invalid_input_is_not_retryable(tmp_path, monkeypatch):
    r = _runner(tmp_path)
    monkeypatch.setattr(r, "_exec", lambda *a, **k: _FakeProc("", "bad prompt", 42))
    with pytest.raises(RunnerError) as exc_info:
        _invoke(r, tmp_path)
    assert exc_info.value.retryable is False
    r.ledger.close()


def test_invoke_exit_53_turn_limit_is_retryable_new_kind(tmp_path, monkeypatch):
    r = _runner(tmp_path)
    monkeypatch.setattr(r, "_exec", lambda *a, **k: _FakeProc("", "turn limit reached", 53))
    with pytest.raises(RunnerError) as exc_info:
        _invoke(r, tmp_path)
    assert exc_info.value.retryable is True
    assert exc_info.value.failure_kind == "turn_limit_exceeded"
    r.ledger.close()


def test_invoke_timeout_is_retryable(tmp_path, monkeypatch):
    r = _runner(tmp_path)

    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd=["gemini"], timeout=5)

    monkeypatch.setattr(r, "_exec", _boom)
    with pytest.raises(RunnerError) as exc_info:
        _invoke(r, tmp_path)
    assert exc_info.value.retryable is True
    assert exc_info.value.failure_kind == "timeout"
    r.ledger.close()


def test_invoke_no_stdout_startup_crash_is_retryable_unknown(tmp_path, monkeypatch):
    """Real observed shape of a FatalSandboxError-style startup crash (confirmed live: nothing on
    stdout, everything on stderr, exit 1) -- must not be confused with the exit-42/53 special cases."""
    r = _runner(tmp_path)
    monkeypatch.setattr(r, "_exec", lambda *a, **k: _FakeProc("", "some unrelated startup error", 1))
    with pytest.raises(RunnerError) as exc_info:
        _invoke(r, tmp_path)
    assert exc_info.value.retryable is True
    assert exc_info.value.failure_kind == "unknown_retryable"
    r.ledger.close()


# --------------------------------------------------------------- model tiering (config)
def test_model_for_gemini_per_stage_tiering():
    cfg = PipelineConfig(runner="gemini")
    assert cfg.model_for("recon") == GEMINI_PRO
    assert cfg.model_for("audit") == GEMINI_FLASH
    assert cfg.model_for("verify") == GEMINI_PRO


def test_gemini_model_override_and_calibrated():
    cfg = PipelineConfig(runner="gemini").with_stage_model("audit", GEMINI_PRO)
    assert cfg.model_for("audit") == GEMINI_PRO
    assert cfg.model_for("recon") == GEMINI_PRO   # untouched stages unaffected
    assert cfg.calibrated().model_for("audit") == GEMINI_PRO


def test_for_smoke_primes_gemini_stage_models_too():
    cfg = PipelineConfig(runner="gemini").for_smoke()
    assert cfg.gemini_stage_models["audit"] == GEMINI_FLASH_LITE
    assert cfg.gemini_stage_models["recon"] == GEMINI_FLASH


def test_gemini_cost_estimate():
    assert estimate_cost_usd(GEMINI_PRO, 1_000_000, 0) == 2.00
    assert estimate_cost_usd(GEMINI_FLASH_LITE, 0, 1_000_000) == 1.50


# --------------------------------------------------------------- dispatch
def test_build_runner_dispatches_gemini(tmp_path):
    r = build_runner(PipelineConfig(runner="gemini"), Ledger(tmp_path / "l.sqlite"))
    assert isinstance(r, GeminiRunner)
    r.ledger.close()


# --------------------------------------------------------------- API + CLI passthrough
def test_api_and_cli_gemini_config_passthrough(tmp_path):
    # API: RunConfig -> PipelineConfig mapping
    from server.jobs import JobManager
    from server.schemas import RunConfig, RunRequest
    jm = JobManager(PipelineConfig(runs_dir=tmp_path / "runs", ledger_path=tmp_path / "l.sqlite"))
    cfg = jm._config_for(RunRequest(brief="b", repo="r", config=RunConfig(
        runner="gemini", gemini_model=GEMINI_PRO, gemini_api_key="sk-test")))
    assert cfg.runner == "gemini" and cfg.gemini_api_key == "sk-test"
    assert all(m == GEMINI_PRO for m in cfg.gemini_stage_models.values())
    # CLI: _build_config passthrough
    from argo.cli import _build_config
    c2 = _build_config("gemini", None, False, None, 3, tmp_path / "runs", "happy",
                       gemini_model=GEMINI_FLASH, gemini_api_key="sk-test-2",
                       gemini_accounts="k1,k2")
    assert c2.runner == "gemini" and c2.gemini_api_key == "sk-test-2"
    assert all(m == GEMINI_FLASH for m in c2.gemini_stage_models.values())
    assert c2.gemini_accounts == ["k1", "k2"]
    # --gemini-model applies BEFORE --calibration, so calibration can still bump audit on top
    c3 = _build_config("gemini", None, True, None, 3, tmp_path / "runs", "happy",
                       gemini_model=GEMINI_FLASH_LITE)
    assert c3.model_for("audit") == GEMINI_PRO           # calibration won
    assert c3.model_for("recon") == GEMINI_FLASH_LITE     # untouched stage kept the flat override
