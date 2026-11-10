"""runner=deepseek-api: DeepSeek Chat Completions (cloud) + Argo-owned tool loop (argo/deepseek_api.py).

Configuration/catalog/routing, the cloud-vs-local separation, the wire codec, the transport
(deadline, cancel, body cap, redirects), the tool loop (batch validation, P-REASON, caps), usage and
cost accounting, error classification and the AgentRunner integration. The API is simulated with
httpx.MockTransport or a loopback server -- no network, no real key."""

from __future__ import annotations

import json

import pytest

from argo.config import (DEEPSEEK_FLASH, DEEPSEEK_PRO, NO_WEB_BACKENDS, OPUS, PipelineConfig,
                         networked_stage_conflicts, pipeline_config_from_dict,
                         pipeline_config_to_dict)
from argo.ledger import Ledger
from argo.model_catalog import get_model_spec, resolve_pricing, validate_selection

KEY = "sk-ds-TEST_SENTINEL_KEY_0123456789"


@pytest.fixture(autouse=True)
def _no_ambient_keys(monkeypatch):
    monkeypatch.delenv("ARGO_DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)


# ============================================================================ config + routing
def test_defaults_are_the_designed_initial_values():
    cfg = PipelineConfig()
    assert cfg.runner == "headless"                                   # default runner unchanged
    assert (cfg.deepseek_api_model, cfg.deepseek_api_stage_models) == (None, {})
    assert (cfg.deepseek_thinking, cfg.deepseek_reasoning_effort) == ("enabled", "high")
    assert (cfg.deepseek_api_max_tokens, cfg.deepseek_api_context_window,
            cfg.deepseek_api_max_requests) == (32768, 262144, 128)


def test_model_precedence_stage_over_flat_over_flash_default():
    cfg = PipelineConfig(runner="deepseek-api")
    assert cfg.model_for("audit") == DEEPSEEK_FLASH
    cfg = cfg.with_overrides(deepseek_api_model=DEEPSEEK_PRO)
    assert cfg.model_for("recon") == DEEPSEEK_PRO
    cfg = cfg.with_stage_model("recon", DEEPSEEK_FLASH)
    assert (cfg.model_for("recon"), cfg.model_for("audit")) == (DEEPSEEK_FLASH, DEEPSEEK_PRO)
    assert cfg.deepseek_api_stage_models == {"recon": DEEPSEEK_FLASH}


def test_stage_routed_to_deepseek_from_another_primary():
    cfg = PipelineConfig(runner="headless", stage_runners={"audit": "deepseek-api"})
    assert cfg.model_for("audit") == DEEPSEEK_FLASH
    out = cfg.with_stage_model("audit", DEEPSEEK_PRO)
    assert out.model_for("audit") == DEEPSEEK_PRO and out.stage_models == cfg.stage_models


def test_calibration_uses_pro_never_opus():
    assert PipelineConfig(runner="deepseek-api").calibrated().model_for("audit") == DEEPSEEK_PRO
    routed = PipelineConfig(runner="headless", stage_runners={"audit": "deepseek-api"}).calibrated()
    assert routed.model_for("audit") == DEEPSEEK_PRO
    assert OPUS not in routed.deepseek_api_stage_models.values()


def test_smoke_preset_uses_flash_and_one_focus():
    cfg = PipelineConfig(runner="deepseek-api", deepseek_api_model=DEEPSEEK_PRO,
                         deepseek_api_stage_models={"audit": DEEPSEEK_PRO})
    smoke = cfg.for_smoke().with_overrides(runner="deepseek-api")
    assert {smoke.model_for(s) for s in ("recon", "audit", "validate")} == {DEEPSEEK_FLASH}
    assert smoke.max_focuses == 1 and smoke.max_parallel_audits == 1


@pytest.mark.parametrize("field,value", [
    ("deepseek_thinking", "auto"), ("deepseek_thinking", "on"),
    ("deepseek_reasoning_effort", "medium"), ("deepseek_reasoning_effort", "none"),
    ("deepseek_api_max_tokens", 0), ("deepseek_api_max_tokens", True),
    ("deepseek_api_max_tokens", 393217), ("deepseek_api_max_tokens", "1024"),
    ("deepseek_api_max_tokens", 1.5),
    ("deepseek_api_context_window", 1_048_577), ("deepseek_api_context_window", 0),
    ("deepseek_api_max_requests", 0), ("deepseek_api_max_requests", -1),
    ("deepseek_api_max_requests", True),
])
def test_invalid_deepseek_values_are_rejected(field, value):
    with pytest.raises(ValueError):
        PipelineConfig(**{field: value})


def test_output_plus_margin_must_fit_the_context_cap():
    with pytest.raises(ValueError, match="context"):
        PipelineConfig(deepseek_api_max_tokens=100_000, deepseek_api_context_window=100_000)
    PipelineConfig(deepseek_api_max_tokens=100_000, deepseek_api_context_window=200_000)


def test_context_cap_matches_provider_million_token_limit():
    cfg = PipelineConfig(deepseek_api_context_window=1_048_576)
    assert cfg.deepseek_api_context_window == 1_048_576
    with pytest.raises(ValueError, match="deepseek_api_context_window"):
        PipelineConfig(deepseek_api_context_window=1_048_577)


def test_key_is_secret_in_repr_and_serialization():
    cfg = PipelineConfig(runner="deepseek-api", deepseek_api_key=KEY)
    assert KEY not in repr(cfg)
    dumped = json.dumps(pipeline_config_to_dict(cfg))
    assert KEY not in dumped and '"deepseek_api_key": "<redacted>"' in dumped
    assert pipeline_config_from_dict(json.loads(dumped)).deepseek_api_key is None


def test_deepseek_is_a_no_web_backend_for_the_common_preflight():
    assert "deepseek-api" in NO_WEB_BACKENDS
    cfg = PipelineConfig(runner="deepseek-api", research_enabled=True)
    assert any("research" in p for p in networked_stage_conflicts(cfg))
    assert networked_stage_conflicts(cfg.with_overrides(research_enabled=False,
                                                        corroborate_enabled=False)) == []


# ============================================================================ catalog
def test_catalog_has_both_cloud_models_with_peak_prices_and_cache_hit():
    flash, pro = get_model_spec(DEEPSEEK_FLASH), get_model_spec(DEEPSEEK_PRO)
    assert flash.provider == pro.provider == "deepseek"
    assert (flash.input_per_million, flash.output_per_million,
            flash.input_cache_hit_per_million) == (0.30, 1.20, 0.006)
    assert (pro.input_per_million, pro.output_per_million,
            pro.input_cache_hit_per_million) == (1.32, 3.96, 0.044)
    assert flash.declared_version == "DeepSeek-V4.1-Flash-1017"
    assert pro.declared_version == "DeepSeek-V4-Pro-0813"
    assert flash.exact_pinning is False and pro.exact_pinning is False      # aliases, not pins
    assert resolve_pricing(DEEPSEEK_FLASH) == (0.30, 1.20)


def test_official_legacy_flash_name_is_an_alias():
    assert get_model_spec("deepseek-v4-flash").model_id == DEEPSEEK_FLASH


def test_selection_is_provider_checked():
    assert validate_selection(DEEPSEEK_FLASH, "deepseek-api")["selectable"] is True
    assert validate_selection("gpt-6-astra", "deepseek-api")["selectable"] is False
    assert validate_selection("mistral-large-4", "deepseek-api")["selectable"] is False
    assert validate_selection(DEEPSEEK_PRO, "headless")["selectable"] is False


# ============================================================================ cloud vs local (ADR-14)
def test_same_id_on_a_local_codex_provider_is_not_rejected():
    local = validate_selection(DEEPSEEK_FLASH, "codex", local=True)
    assert local["selectable"] is True
    assert any("local" in w for w in local.get("warnings", []))
    assert validate_selection(DEEPSEEK_FLASH, "codex")["selectable"] is False   # cloud OpenAI path


def test_cli_stage_model_accepts_a_local_deepseek_on_codex_oss():
    from argo.cli import _apply_stage_assignments
    cfg = PipelineConfig(runner="codex", codex_oss=True)
    out = _apply_stage_assignments(cfg, ["audit=deepseek-flash"], None)
    assert out.model_for("audit") == DEEPSEEK_FLASH


def test_local_codex_session_is_never_priced_at_cloud_rates(tmp_path):
    from argo.runner import CodexRunner
    led = Ledger(tmp_path / "l.sqlite")
    stdout = json.dumps({"type": "turn.completed",
                         "usage": {"input_tokens": 100_000, "output_tokens": 10_000}})
    raw = {"returncode": 0, "text": "ok", "stdout": stdout, "stderr": ""}
    local = CodexRunner(PipelineConfig(runner="codex", codex_oss=True), led).parse_envelope(
        raw, model=DEEPSEEK_FLASH, prompt_sha256="p", work_dir=tmp_path)
    assert local.cost_usd == 0.0 and local.cost_source == "local_unpriced"
    assert (local.input_tokens, local.output_tokens) == (100_000, 10_000)
    led.close()


# ============================================================================ factory
def test_factory_builds_deepseek_without_a_key_and_keeps_other_backends(tmp_path):
    from argo.deepseek_api import DeepSeekApiRunner
    from argo.runner import FallbackRunner, MockClaudeRunner, build_runner
    led = Ledger(tmp_path / "l.sqlite")
    assert isinstance(build_runner(PipelineConfig(runner="deepseek-api"), led), DeepSeekApiRunner)
    assert isinstance(build_runner(PipelineConfig(runner="mock"), led), MockClaudeRunner)
    chain = build_runner(PipelineConfig(runner="deepseek-api", runner_fallbacks=["mock"]), led)
    assert isinstance(chain, FallbackRunner)
    led.close()


def test_cli_stage_runner_accepts_deepseek():
    from argo.cli import _apply_stage_assignments
    out = _apply_stage_assignments(PipelineConfig(runner="headless"),
                                   ["audit=deepseek-v4-pro"], ["audit=deepseek-api"])
    assert out.stage_runners["audit"] == "deepseek-api"
    assert out.model_for("audit") == DEEPSEEK_PRO


def test_adaptive_escalation_stays_inside_deepseek():
    from argo.adaptive import _set_stage_model, _strong_model
    cfg = PipelineConfig(runner="deepseek-api")
    assert _strong_model("deepseek-api", cfg, "audit") == DEEPSEEK_PRO
    assert _set_stage_model(cfg, "deepseek-api", "audit", DEEPSEEK_PRO).model_for("audit") == DEEPSEEK_PRO


def test_a_web_stage_never_falls_back_onto_a_no_web_backend():
    """research on headless with a deepseek-api fallback: the candidate is skipped for that stage
    instead of being discovered (and refused) after the primary already failed."""
    from argo.runner import FallbackRunner, RunnerError

    class _Fake:
        def __init__(self, name, fail):
            self.config, self.cancel_event = PipelineConfig(runner=name), None
            self.fail, self.calls = fail, 0

        def run(self, **kw):
            self.calls += 1
            if self.fail:
                raise RunnerError("synthetic transient", retryable=True, failure_kind="rate_limited")
            return "ok"

    deepseek = _Fake("deepseek-api", False)
    kw = dict(prompt="x", run_dir=None, work_dir=None, model="m", run_id="r")
    with pytest.raises(RunnerError):
        FallbackRunner(PipelineConfig(), None, [_Fake("headless", True), deepseek]).run(
            stage="research", **kw)
    assert deepseek.calls == 0
    assert FallbackRunner(PipelineConfig(), None, [_Fake("headless", True), deepseek]).run(
        stage="audit", **kw) == "ok"                       # non-web stages still fall back
