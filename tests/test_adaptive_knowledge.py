import json

from argo.adaptive import maybe_escalate_after_audit
from argo.benchmark_knowledge import aggregate_reports, evidence_for


def test_adaptive_escalation_is_explicit_and_persisted(env, tmp_path):
    ctx = env(adaptive_escalation="balanced", runner_fallbacks=["codex"])
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    ctx.findings_dir.mkdir(parents=True, exist_ok=True)
    (ctx.findings_dir / "audit.findings.json").write_text(json.dumps({"findings": [{
        "id": "F-1", "severity": "High"
    }]}), encoding="utf-8")
    events = maybe_escalate_after_audit(ctx)
    assert events and events[0]["result"] == "applied"
    assert ctx.config.stage_runners["validate"] == "codex"
    assert (ctx.run_dir / "adaptive_events.jsonl").exists()


def test_adaptive_escalation_defers_when_session_cap_exceeds_remaining_budget(env):
    ctx = env(adaptive_escalation="balanced", runner_fallbacks=["codex"],
              budget_usd=0.50, session_max_cost_usd=0.75)
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    ctx.findings_dir.mkdir(parents=True, exist_ok=True)
    (ctx.findings_dir / "audit.findings.json").write_text(
        json.dumps({"findings": [{"id": "F-1", "severity": "High"}]}), encoding="utf-8")
    events = maybe_escalate_after_audit(ctx)
    assert events[0]["result"] == "deferred"
    assert events[0]["reason_code"] == "BUDGET_HEADROOM_INSUFFICIENT"
    assert events[0]["estimated_incremental_cost_usd"] == 0.75


def test_benchmark_knowledge_ignores_invalid_trials_and_exposes_low_confidence():
    report = {"provenance": {"benchmark_mode": True, "catalog_snapshot": {"version": "v1"}},
              "cases": [
                  {"archetype": "native_parser", "valid_trial": True, "tp": 1,
                   "precision": 1.0, "recall": 1.0, "f1": 1.0, "cost_usd": 0.2},
                  {"archetype": "native_parser", "valid_trial": False, "tp": 0,
                   "precision": 0.0, "recall": 0.0, "f1": 0.0, "cost_usd": 9.0},
              ]}
    knowledge = aggregate_reports([report])
    assert knowledge["groups"]["native_parser"]["sample_count"] == 1
    fp = {"languages": {"C++": 1}, "surfaces": {"parser": 1}, "manifests": [],
          "verification": {}}
    ev = evidence_for(fp, knowledge)
    assert ev["target_class"] == "native_parser" and ev["confidence"] == "low"

