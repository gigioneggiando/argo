import json
from pathlib import Path

from argo.config import PipelineConfig
from argo.planner import make_plan
from argo.profiles import apply_profile, profile_data
from argo.screening import screen_target
from argo.context import RunContext
from argo.ledger import Ledger
from argo.runner import MockClaudeRunner, CodexRunner


def test_screening_is_deterministic_and_content_keyed(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "parser.py").write_text("def parse(data):\n    return data\n", encoding="utf-8")
    cache = tmp_path.parent / (tmp_path.name + "-cache")
    first = screen_target(tmp_path, cache_dir=cache)
    second = screen_target(tmp_path, cache_dir=cache)
    assert first == second
    assert first["schema_version"] == 1
    assert "parser" in first["surfaces"]
    assert list(cache.glob("*.json"))


def test_planner_exposes_reasons_and_stable_plan_id(tmp_path):
    fp = {"schema_version": 1, "fingerprint_id": "abc", "revision": "deadbeef",
          "languages": {"C++": 3}, "surfaces": {"parser": 2},
          "verification": {"sanitizers": 1, "fuzzers": 1, "tests": 2},
          "manifests": ["CMakeLists.txt"], "monorepo": False, "approx_loc": 1000}
    cfg = PipelineConfig(runner="codex")
    a = make_plan(fp, cfg, objective="balanced")
    b = make_plan(fp, cfg, objective="balanced")
    assert a["plan_id"] == b["plan_id"]
    assert "NATIVE_MEMORY_RISK_HIGH" in {r["code"] for r in a["reasons"]}
    assert "verify" in a["enabled_stages"]
    assert a["estimated_cost_usd"]["high"] >= a["estimated_cost_usd"]["low"]


def test_profiles_never_contain_credentials_and_apply_routing():
    data = profile_data("maximum-quality")
    assert "api_key" not in json.dumps(data).lower()
    cfg = apply_profile(PipelineConfig(runner="codex"), "cost-saver")
    assert cfg.model_for("audit") == "gpt-6-luna"


def test_context_creates_stage_backend_lazily_with_shared_cancel(tmp_path):
    cfg = PipelineConfig(runner="mock", runs_dir=tmp_path / "runs",
                         ledger_path=tmp_path / "ledger.sqlite", stage_runners={"audit": "codex"})
    ledger = Ledger(cfg.ledger_path)
    ctx = RunContext("run-1", cfg, MockClaudeRunner(cfg, ledger), ledger)
    assert not ctx._runner_cache
    stage = ctx.runner_for("audit")
    assert isinstance(stage, CodexRunner)
    ctx.set_cancel_event(object())
    assert stage.cancel_event is ctx.runner.cancel_event
