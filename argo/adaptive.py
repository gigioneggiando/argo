"""Explicit, bounded adaptive escalation for normal (non-benchmark) runs.

Adaptive routing is intentionally conservative and opt-in.  It only reacts to evidence already
written by the audit stage, never executes the target, never enables a missing safety stage, and
persists every decision in ``adaptive_events.jsonl``.  Benchmark mode disables it completely so
repeated trials remain comparable.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .config import (CODEX_TOP, GEMINI_ARGON, OPUS, PipelineConfig, write_pipeline_config)
from .context import RunContext

POLICIES = {"off", "conservative", "balanced", "aggressive"}


def _read_audit_findings(ctx: RunContext) -> list[dict]:
    findings: list[dict] = []
    root = Path(ctx.findings_dir)
    if not root.exists():
        return findings
    for path in sorted(root.glob("*.findings.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            continue
        rows = raw.get("findings", []) if isinstance(raw, dict) else raw
        if isinstance(rows, list):
            findings.extend(x for x in rows if isinstance(x, dict))
    return findings


def _strong_model(backend: str, config: PipelineConfig, stage: str) -> str | None:
    if backend == "headless":
        return OPUS
    if backend == "codex":
        return CODEX_TOP
    if backend == "gemini":
        return GEMINI_ARGON
    return None


def _set_stage_model(config: PipelineConfig, backend: str, stage: str, model: str) -> PipelineConfig:
    if backend == "codex":
        values = dict(config.codex_stage_models)
        values[stage] = model
        return config.with_overrides(codex_stage_models=values)
    if backend == "gemini":
        values = dict(config.gemini_stage_models)
        values[stage] = model
        return config.with_overrides(gemini_stage_models=values)
    values = dict(config.stage_models)
    values[stage] = model
    return config.with_overrides(stage_models=values)


def _append_event(ctx: RunContext, event: dict) -> None:
    event = {"ts": datetime.now(timezone.utc).isoformat(), **event}
    path = ctx.run_dir / "adaptive_events.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, sort_keys=True) + "\n")


def _escalation_budget(ctx: RunContext) -> tuple[float | None, str]:
    """Return a conservative upper-bound estimate and its basis.

    Adaptive routing must not turn an opt-in policy into an unbounded spend.  A per-session cap is
    the tightest estimate; otherwise the remaining per-run cap is the only honest bound.  With no
    cap configured we report ``None`` instead of pretending to know a provider-dependent amount.
    """
    session_cap = ctx.config.session_max_cost_usd
    if session_cap is not None:
        return float(session_cap), "session_max_cost_usd"
    run_cap = ctx.config.budget_usd
    if run_cap is not None:
        spent = ctx.ledger.run_cost(ctx.run_id)
        return max(0.0, float(run_cap) - spent), "remaining_budget_usd"
    return None, "unbounded"


def maybe_escalate_after_audit(ctx: RunContext) -> list[dict]:
    """Apply one bounded escalation before validation and return persisted event records.

    The only automatic action is to strengthen (and, at balanced/aggressive levels, optionally
    diversify) the *validate* stage.  We do not silently add runtime/ASan stages, rerun an audit,
    or exceed a configured budget.  Findings that need those expensive actions receive an
    explicit ``deferred`` event for human review instead.
    """
    policy = str(ctx.config.adaptive_escalation or "off").lower()
    if policy not in POLICIES:
        raise ValueError(f"unknown adaptive escalation policy: {policy}")
    if policy == "off" or ctx.config.benchmark_mode:
        return []
    findings = _read_audit_findings(ctx)
    severe = [f for f in findings if str(f.get("severity", "")).lower() in {"critical", "high"}]
    if not severe:
        estimate, basis = _escalation_budget(ctx)
        event = {"policy": policy, "trigger": "low_audit_coverage", "reason_code": "NO_HIGH_SEVERITY_AUDIT_FINDING",
                 "old_stage": "audit", "new_stage": "validate", "result": "deferred",
                 "detail": "No high/critical audit finding; no automatic audit rerun is performed.",
                 "estimated_incremental_cost_usd": 0.0, "estimate_basis": "no_escalation"}
        _append_event(ctx, event)
        return [event]

    stage = "validate"
    old_backend = ctx.config.stage_runners.get(stage, ctx.config.runner)
    old_model = ctx.config.model_for(stage)
    new_backend = old_backend
    if policy in {"balanced", "aggressive"}:
        # A configured fallback is an explicit user choice for a second provider.  Never invent a
        # credential or silently pick a backend that was not configured for this run.
        for candidate in ctx.config.runner_fallbacks:
            if candidate != old_backend and candidate in {"headless", "codex", "gemini"}:
                new_backend = candidate
                break
    new_model = _strong_model(new_backend, ctx.config, stage)
    if not new_model or (new_backend == old_backend and old_model == new_model):
        event = {"policy": policy, "trigger": "high_severity_finding", "reason_code": "STRONG_VALIDATION_ALREADY_SELECTED",
                 "old_stage": stage, "old_backend": old_backend, "old_model": old_model,
                 "new_stage": stage, "new_backend": old_backend, "new_model": old_model,
                 "result": "no_change", "finding_count": len(severe),
                 "estimated_incremental_cost_usd": 0.0, "estimate_basis": "no_change"}
        _append_event(ctx, event)
        return [event]

    runners = dict(ctx.config.stage_runners)
    estimate, basis = _escalation_budget(ctx)
    remaining = None
    if ctx.config.budget_usd is not None:
        remaining = max(0.0, float(ctx.config.budget_usd) - ctx.ledger.run_cost(ctx.run_id))
    if remaining is not None and estimate is not None and estimate > remaining:
        event = {"policy": policy, "trigger": "high_severity_finding", "reason_code": "BUDGET_HEADROOM_INSUFFICIENT",
                 "old_stage": stage, "old_backend": old_backend, "old_model": old_model,
                 "new_stage": stage, "new_backend": new_backend, "new_model": new_model,
                 "result": "deferred", "finding_count": len(severe),
                 "estimated_incremental_cost_usd": estimate, "estimate_basis": basis,
                 "remaining_budget_usd": remaining}
        _append_event(ctx, event)
        return [event]
    runners[stage] = new_backend
    new_config = ctx.config.with_overrides(stage_runners=runners)
    new_config = _set_stage_model(new_config, new_backend, stage, new_model)
    ctx.apply_config(new_config)
    # Persist the effective routing immediately, before any paid validation call begins.
    write_pipeline_config(ctx.run_dir / "config.json", ctx.config)
    event = {"policy": policy, "trigger": "high_severity_finding", "reason_code": "INDEPENDENT_STRONG_VALIDATOR",
             "old_stage": stage, "old_backend": old_backend, "old_model": old_model,
             "new_stage": stage, "new_backend": new_backend, "new_model": new_model,
             "result": "applied", "finding_count": len(severe),
             "estimated_incremental_cost_usd": estimate, "estimate_basis": basis}
    _append_event(ctx, event)
    return [event]

