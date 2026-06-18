"""Cost analytics (Phase 8) — turns the ledger's ``llm_calls`` into actionable economics.

All figures are **observed** (the real ``total_cost_usd`` each call reported), not estimates from
a static price list — so they reflect your actual model mix, caching, and run sizes. Answers:
how much does a run cost on average, where does the money go (by stage), and which models are the
most cost-effective ($/call and $/1k output tokens).
"""

from __future__ import annotations

from .archetype import label as archetype_label
from .ledger import Ledger


def _div(a: float, b: float) -> float:
    return a / b if b else 0.0


def _by_archetype(ledger: Ledger, run_archetypes: dict) -> list[dict]:
    """Aggregate per-run costs by the run's canonical archetype (Phase 7 calibration prep)."""
    buckets: dict[str, dict] = {}
    for r in ledger.recent_run_costs(10_000):
        key = run_archetypes.get(r["run_id"]) or "other"
        b = buckets.setdefault(key, {"runs": 0, "cost": 0.0, "calls": 0})
        b["runs"] += 1
        b["cost"] += r["cost"]
        b["calls"] += r["calls"]
    rows = [{
        "archetype": k,
        "label": archetype_label(k),
        "runs": v["runs"],
        "calls": v["calls"],
        "cost_usd": round(v["cost"], 6),
        "avg_cost_per_run": round(_div(v["cost"], v["runs"]), 4),
    } for k, v in buckets.items()]
    rows.sort(key=lambda x: x["cost_usd"], reverse=True)
    return rows


def cost_report(ledger: Ledger, run_archetypes: dict | None = None) -> dict:
    """Observed cost economics. If ``run_archetypes`` (run_id -> canonical archetype) is given,
    add a ``by_archetype`` breakdown so costs can be compared/calibrated across software types."""
    totals = ledger.totals()
    total_cost = totals["cost_usd"]
    runs = totals["runs"]

    by_model = []
    for m in ledger.cost_by_model():
        out = m["output_tokens"] or 0
        by_model.append({
            "model": m["model"],
            "calls": m["calls"],
            "cost_usd": round(m["cost"], 6),
            "input_tokens": m["input_tokens"],
            "output_tokens": out,
            "avg_cost_per_call": round(_div(m["cost"], m["calls"]), 6),
            "cost_per_1k_output": round(_div(m["cost"], out) * 1000, 6) if out else None,
            "pct_of_total": round(_div(m["cost"], total_cost) * 100, 1),
        })

    by_stage = []
    for s in ledger.cost_by_stage():
        by_stage.append({
            "stage": s["stage"],
            "calls": s["calls"],
            "cost_usd": round(s["cost"], 6),
            "avg_cost_per_call": round(_div(s["cost"], s["calls"]), 6),
            "pct_of_total": round(_div(s["cost"], total_cost) * 100, 1),
        })

    recent = [{"run_id": r["run_id"], "calls": r["calls"],
               "cost_usd": round(r["cost"], 6), "ts": r["ts"]}
              for r in ledger.recent_run_costs(20)]

    # cheapest model by unit economics (only models that actually produced output tokens)
    priced = [m for m in by_model if m["cost_per_1k_output"]]
    cheapest = min(priced, key=lambda m: m["cost_per_1k_output"])["model"] if priced else None

    report = {
        "totals": {
            "calls": totals["calls"],
            "runs": runs,
            "cost_usd": round(total_cost, 6),
            "avg_cost_per_run": round(_div(total_cost, runs), 4),
        },
        "by_model": by_model,
        "by_stage": by_stage,
        "recent_runs": recent,
        "cheapest_model_per_1k_output": cheapest,
    }
    if run_archetypes is not None:
        report["by_archetype"] = _by_archetype(ledger, run_archetypes)
    return report
