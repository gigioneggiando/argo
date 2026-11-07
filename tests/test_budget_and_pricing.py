"""Budget gate at the runner chokepoint, failed-session ledgering, effective-dated pricing, and
model_unavailable handling. Mock/fake runners only -- no model calls."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from argo.config import PipelineConfig, estimate_cost_usd
from argo.context import BudgetExceeded as ContextBudgetExceeded
from argo.ledger import Ledger
from argo.model_catalog import resolve_pricing
from argo.orchestrator import _NO_AUTO_RETRY_FAILURE_KINDS
from argo.runner import (TERMINAL_FAILURE_KINDS, _COOLDOWN_BY_FAILURE_KIND, BudgetExceeded,
                         ClaudeRunner, FallbackRunner, RunnerError, _codex_error_events,
                         _codex_model_unavailable)


class _CostRunner(ClaudeRunner):
    """Each session costs $1 (reported in the envelope), like the review's mock repro."""

    calls = 0

    def _invoke(self, *, prompt, work_dir, model, repo_dir, allowed, disallowed, policy=None,
                stage, run_id, label, session_budget_usd=None, timeout_s=None):
        type(self).calls += 1
        return {"is_error": False, "result": "ok", "usage": {"input_tokens": 1, "output_tokens": 1},
                "total_cost_usd": 1.0, "num_turns": 1, "session_id": "s", "subtype": "success"}


class _TimeoutRunner(ClaudeRunner):
    def _invoke(self, **kw):
        raise RunnerError("timed out", retryable=True, failure_kind="timeout")


def _run(r, tmp_path, label="x", run_id="R"):
    return r.run(prompt="p", run_dir=tmp_path / "run", work_dir=tmp_path / "run" / label,
                 model="m", stage="audit", run_id=run_id, label=label)


def test_budget_gate_refuses_launch_once_spent(tmp_path):
    led = Ledger(tmp_path / "l.sqlite")
    _CostRunner.calls = 0
    r = _CostRunner(PipelineConfig(budget_usd=2.5), led)
    _run(r, tmp_path, "a")
    _run(r, tmp_path, "b")
    _run(r, tmp_path, "c")                      # $2 < $2.5: still launches (at most one over)
    with pytest.raises(BudgetExceeded) as ei:
        _run(r, tmp_path, "d")
    assert ei.value.failure_kind == "budget_reached" and not ei.value.retryable
    assert _CostRunner.calls == 3 and led.run_cost("R") == 3.0
    led.close()


def test_budget_exceeded_is_one_type_everywhere():
    # stages catch context.BudgetExceeded; the runner raises runner.BudgetExceeded
    assert ContextBudgetExceeded is BudgetExceeded
    assert issubclass(BudgetExceeded, RunnerError)
    assert "budget_reached" in TERMINAL_FAILURE_KINDS
    assert "budget_reached" in _NO_AUTO_RETRY_FAILURE_KINDS


def test_fallback_does_not_fall_through_on_budget(tmp_path):
    led = Ledger(tmp_path / "l.sqlite")
    led.log_call(run_id="R", stage="audit", model="m", prompt_sha256="x", cost_usd=5.0)
    cfg = PipelineConfig(budget_usd=1.0)
    _CostRunner.calls = 0
    fb = FallbackRunner(cfg, led, [_CostRunner(cfg, led), _CostRunner(cfg, led)])
    with pytest.raises(BudgetExceeded):
        _run(fb, tmp_path)
    assert _CostRunner.calls == 0
    led.close()


def test_failed_session_is_ledgered(tmp_path):
    led = Ledger(tmp_path / "l.sqlite")
    with pytest.raises(RunnerError):
        _run(_TimeoutRunner(PipelineConfig(), led), tmp_path)
    assert led.run_call_count("R") == 1
    row = led._conn.execute("SELECT failure_kind, cost_usd FROM llm_calls").fetchone()
    assert row[0] == "timeout" and row[1] == 0
    led.close()


# ------------------------------------------------------------------------------ pricing (C-01)
def test_estimate_defaults_to_todays_effective_price():
    today = datetime.now(timezone.utc).date().isoformat()
    m = "gemini-4-argon"
    assert estimate_cost_usd(m, 1_000_000, 1_000_000) == \
        estimate_cost_usd(m, 1_000_000, 1_000_000, as_of=today)
    assert resolve_pricing(m, as_of="2026-11-15") == (2.0, 10.0)
    assert resolve_pricing(m, as_of="2026-12-15") == (4.0, 20.0)


# ------------------------------------------------------------------- model_unavailable (C-02)
def test_model_unavailable_is_not_auto_retried_and_benched():
    assert "model_unavailable" in _NO_AUTO_RETRY_FAILURE_KINDS
    assert _COOLDOWN_BY_FAILURE_KIND["model_unavailable"].days >= 1


def test_model_unavailable_ignores_tool_output_in_stdout():
    phrase = "model is not supported when using Codex with a ChatGPT account"
    tool_output = json.dumps({"type": "item.completed", "item": {
        "type": "command_execution", "aggregated_output": phrase}})
    assert _codex_model_unavailable(_codex_error_events(tool_output)) is None
    err = json.dumps({"type": "error", "message": f"The '{phrase}'"})
    assert _codex_model_unavailable(_codex_error_events(err)) is not None
