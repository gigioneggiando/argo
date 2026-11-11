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


# ------------------------------------------------------------------------------ metadata + accounting
from argo.runner import sanitize_metadata  # noqa: E402


def test_metadata_allowlist_keeps_valid_fields_and_drops_the_rest():
    md = sanitize_metadata({
        "accounting_version": 1, "accounting_id": "acct-0123456789abcdef",
        "request_count": 3, "unknown_request_count": 1, "usage_complete": False,
        "accounting_complete": False, "unknown_reserved_usd": 0.25,
        "input_cache_hit_tokens": 10, "input_cache_miss_tokens": 90,
        "cache_breakdown_unavailable": False, "deepseek_thinking": "enabled",
        "deepseek_reasoning_effort": "high", "pricing_snapshot_id": "deepseek-2026-11-09-peak",
        "catalog_declared_version": "DeepSeek-V4.1-Flash-1017", "catalog_as_of": "2026-11-09",
        "api_returned_model": "deepseek-flash", "system_fingerprint": "fp_abc123",
        "resolved_effort": "high", "mistral_vibe_auth": "stored", "auth_source": "unknown",
        "vibe_version": "2.4.1",
        # dropped:
        "reasoning_content": "PRIVATE-COT", "raw_body": {"x": 1}, "authorization": "Bearer k",
    })
    assert "reasoning_content" not in md and "raw_body" not in md and "authorization" not in md
    assert md["request_count"] == 3 and md["deepseek_thinking"] == "enabled"
    assert md["mistral_vibe_auth"] == "stored" and md["vibe_version"] == "2.4.1"
    assert len(md) == 21


@pytest.mark.parametrize("key,value", [
    ("request_count", -1), ("request_count", True), ("request_count", 1.5),
    ("unknown_reserved_usd", float("nan")), ("unknown_reserved_usd", float("inf")),
    ("unknown_reserved_usd", -0.01), ("usage_complete", "yes"), ("deepseek_thinking", "auto"),
    ("deepseek_reasoning_effort", "medium"), ("api_returned_model", "x" * 200),
    ("system_fingerprint", "has spaces and\nnewlines"), ("accounting_id", "../../etc"),
    ("mistral_vibe_auth", "password"),
])
def test_invalid_metadata_values_are_dropped_not_coerced(key, value):
    assert key not in sanitize_metadata({key: value})


def test_vibe_version_may_be_absent_but_recorded():
    assert sanitize_metadata({"vibe_version": None}) == {"vibe_version": None}


class _MetaRunner(ClaudeRunner):
    meta: dict = {}
    cost = 0.5

    def _invoke(self, **kw):
        return {"is_error": False, "result": "ok", "usage": {"input_tokens": 7, "output_tokens": 3},
                "total_cost_usd": type(self).cost, "num_turns": 1, "session_id": "s",
                "subtype": "success"}

    def parse_envelope(self, raw, **kw):
        res = super().parse_envelope(raw, **kw)
        res.metadata = dict(type(self).meta)
        return res


def test_ledger_and_jsonl_carry_the_same_sanitized_metadata_and_resolved_effort(tmp_path):
    led = Ledger(tmp_path / "l.sqlite")
    _MetaRunner.meta = {"request_count": 2, "deepseek_reasoning_effort": "max",
                        "resolved_effort": "max", "reasoning_content": "PRIVATE-COT"}
    _run(_MetaRunner(PipelineConfig(), led), tmp_path)
    row = led._conn.execute("SELECT metadata_json, effort FROM llm_calls").fetchone()
    lines = (tmp_path / "run" / "llm_log.jsonl").read_text(encoding="utf-8").splitlines()
    jsonl = json.loads(lines[-1])
    stored = json.loads(row["metadata_json"])
    assert stored == {"request_count": 2, "deepseek_reasoning_effort": "max", "resolved_effort": "max"}
    assert {k: jsonl[k] for k in stored} == stored
    assert "PRIVATE-COT" not in json.dumps(jsonl) and "PRIVATE-COT" not in row["metadata_json"]
    assert row["effort"] == "max"
    led.close()


def test_launch_gate_counts_unknown_reserves(tmp_path):
    led = Ledger(tmp_path / "l.sqlite")
    _MetaRunner.meta, _MetaRunner.cost = {"unknown_reserved_usd": 1.6}, 0.5
    r = _MetaRunner(PipelineConfig(budget_usd=2.0), led)
    _run(r, tmp_path, "a")                               # known 0.5 + reserved 1.6 = 2.1
    with pytest.raises(BudgetExceeded):
        _run(r, tmp_path, "b")
    assert led.run_cost("R") == 0.5
    _MetaRunner.meta = {}
    led.close()


class _PartialRunner(ClaudeRunner):
    def _invoke(self, *, work_dir, **kw):
        from argo.runner import LLMResult
        partial = LLMResult(text="", model="m", prompt_sha256="p", work_dir=work_dir,
                            input_tokens=1000, output_tokens=100, cost_usd=0.0123,
                            cost_source="estimated_partial", failure_kind="credits_exhausted",
                            metadata={"request_count": 2, "usage_complete": False})
        raise RunnerError("provider: insufficient balance", retryable=True,
                          failure_kind="credits_exhausted", partial_result=partial)


def test_known_usage_survives_a_raised_failure(tmp_path):
    led = Ledger(tmp_path / "l.sqlite")
    with pytest.raises(RunnerError):
        _run(_PartialRunner(PipelineConfig(), led), tmp_path)
    row = led._conn.execute("SELECT input_tokens, output_tokens, cost_usd, cost_source, "
                            "failure_kind, metadata_json FROM llm_calls").fetchone()
    assert (row["input_tokens"], row["output_tokens"]) == (1000, 100)
    assert abs(row["cost_usd"] - 0.0123) < 1e-12 and row["cost_source"] == "estimated_partial"
    assert row["failure_kind"] == "credits_exhausted"
    assert json.loads(row["metadata_json"]) == {"request_count": 2, "usage_complete": False}
    led.close()
