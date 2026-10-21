from argo.config import (CODEX_BALANCED, CODEX_CHEAP, CODEX_TOP, PipelineConfig,
                          estimate_cost_usd, model_cost_source)
from argo.model_catalog import get_model_spec, resolve_pricing, validate_selection


def test_exact_pricing_does_not_use_substring_order():
    assert resolve_pricing("gpt-6.1-sol") == (2.0, 10.0)
    assert estimate_cost_usd("gpt-6.1-sol", 1_000_000, 0) == 2.0
    assert estimate_cost_usd("gpt-6-astra", 1_000_000, 0) == 10.0


def test_unknown_and_unpriced_are_distinct_from_known_zero():
    assert resolve_pricing("made-up-model") is None
    assert model_cost_source("made-up-model") == "unknown"
    assert get_model_spec("gemini-3.6-flash") is not None


def test_codex_stage_routing_and_precedence():
    cfg = PipelineConfig(runner="codex")
    assert cfg.model_for("recon") == CODEX_TOP
    assert cfg.model_for("audit") == CODEX_BALANCED
    assert cfg.model_for("ingest") == CODEX_CHEAP
    assert cfg.with_overrides(codex_model="custom").model_for("audit") == "custom"
    assert cfg.with_overrides(codex_model="custom").with_stage_model("audit", CODEX_TOP).model_for("audit") == CODEX_TOP


def test_catalog_contains_current_defaults():
    cfg = PipelineConfig(runner="codex")
    for stage in ("recon", "audit", "validate"):
        assert get_model_spec(cfg.model_for(stage)) is not None
    gemini = PipelineConfig(runner="gemini")
    assert get_model_spec(gemini.model_for("verify")).model_id == "gemini-4-argon"


def test_effective_dated_prices_and_backend_preflight():
    assert resolve_pricing("gemini-4-argon", as_of="2026-10-21") == (2.0, 10.0)
    assert resolve_pricing("gemini-4-argon", as_of="2027-01-01") == (4.0, 20.0)
    assert validate_selection("claude-opus-5-5", "codex")["selectable"] is False
    assert validate_selection("vendor-new-model", "codex")["status"] == "custom/unverified"

