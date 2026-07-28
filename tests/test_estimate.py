import json
from pathlib import Path

from argo.archetype import run_archetypes
from argo.config import PipelineConfig
from argo.estimate import estimate_cost
from argo.ledger import Ledger


def _meta(runs_dir: Path, run_id: str, archetype: str) -> None:
    rd = runs_dir / run_id
    rd.mkdir(parents=True, exist_ok=True)
    (rd / "meta.json").write_text(json.dumps({"archetype": archetype}), encoding="utf-8")


def _call(ledger: Ledger, run_id: str, stage: str, cost: float,
          model: str = "sonnet", output_tokens: int = 1000) -> None:
    ledger.log_call(run_id=run_id, stage=stage, model=model, prompt_sha256="h",
                    input_tokens=100, output_tokens=output_tokens, cost_usd=cost)


def test_historical_archetype_estimate_is_a_range_bracketing_history(tmp_path):
    runs_dir = tmp_path / "runs"
    led = Ledger(tmp_path / "ledger.sqlite")
    try:
        _meta(runs_dir, "RUN-A", "web_api_cms")
        _meta(runs_dir, "RUN-B", "web_api_cms")
        _meta(runs_dir, "RUN-C", "plugin_extension")
        _call(led, "RUN-A", "audit", 10.0)
        _call(led, "RUN-A", "validate", 2.0, model="opus")
        _call(led, "RUN-B", "audit", 20.0)
        _call(led, "RUN-B", "validate", 4.0, model="opus")
        _call(led, "RUN-C", "audit", 5.0)

        cfg = PipelineConfig(runs_dir=runs_dir, ledger_path=led.path)
        est = estimate_cost(led, runs_dir, "web_api_cms", cfg)

        assert est["mode"] == "historical"
        assert est["history"]["runs"] == 2
        assert est["estimate"]["low_usd"] <= 12.0
        assert est["estimate"]["high_usd"] >= 24.0
        assert est["estimate"]["low_usd"] < est["estimate"]["high_usd"]
    finally:
        led.close()


def test_cold_start_estimate_is_labeled_rough(tmp_path):
    runs_dir = tmp_path / "runs"
    led = Ledger(tmp_path / "ledger.sqlite")
    try:
        # Price history only; no run meta maps these rows to the target archetype.
        _call(led, "PRICE-A", "audit", 1.0, model="sonnet", output_tokens=1000)
        _call(led, "PRICE-B", "validate", 2.0, model="opus", output_tokens=1000)
        rd = runs_dir / "NEW"
        (rd / "prompts").mkdir(parents=True)
        (rd / "prompts" / "audit_main.md").write_text("audit prompt\n" * 400, encoding="utf-8")
        (rd / "repo_profile.json").write_text(
            json.dumps({"loc": 4000, "file_count": 40, "archetype": "firmware"}),
            encoding="utf-8")

        cfg = PipelineConfig(runs_dir=runs_dir, ledger_path=led.path,
                             stage_models={**PipelineConfig().stage_models,
                                           "audit": "sonnet", "validate": "opus"})
        est = estimate_cost(led, runs_dir, "firmware", cfg, run_id="NEW")

        assert est["mode"] == "cold_start"
        assert "rough" in est["note"]
        assert est["estimate"]["high_usd"] > est["estimate"]["low_usd"] > 0
    finally:
        led.close()


def test_run_archetypes_reads_meta_mapping(tmp_path):
    runs_dir = tmp_path / "runs"
    _meta(runs_dir, "A", "web_api_cms")
    _meta(runs_dir, "B", "plugin_extension")
    (runs_dir / "C").mkdir()
    (runs_dir / "not-a-run.txt").write_text("x", encoding="utf-8")

    assert run_archetypes(runs_dir) == {
        "A": "web_api_cms",
        "B": "plugin_extension",
    }


def test_extra_stage_config_estimates_higher_than_baseline(tmp_path):
    runs_dir = tmp_path / "runs"
    led = Ledger(tmp_path / "ledger.sqlite")
    try:
        _meta(runs_dir, "RUN-A", "web_api_cms")
        _meta(runs_dir, "RUN-B", "web_api_cms")
        for run_id, audit_cost in (("RUN-A", 10.0), ("RUN-B", 20.0)):
            _call(led, run_id, "audit", audit_cost)
            _call(led, run_id, "validate", 5.0, model="opus")
            _call(led, run_id, "corroborate", 5.0, model="sonnet")

        base = PipelineConfig(runs_dir=runs_dir, ledger_path=led.path,
                              sca_enabled=False, research_enabled=False,
                              corroborate_enabled=False)
        extra = base.with_overrides(corroborate_enabled=True, second_opinion_passes=2)

        base_est = estimate_cost(led, runs_dir, "web_api_cms", base)
        extra_est = estimate_cost(led, runs_dir, "web_api_cms", extra)

        assert extra_est["estimate"]["median_usd"] > base_est["estimate"]["median_usd"]
        assert extra_est["config_multiplier"] > base_est["config_multiplier"]
    finally:
        led.close()
