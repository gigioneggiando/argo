"""Explainable, deterministic screening-to-plan planner.

The planner is deliberately rule based.  It never executes a target and never calls an LLM; the
result can be reviewed and overridden before a pipeline spends tokens.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .config import PipelineConfig
from .benchmark_knowledge import evidence_for
from .model_catalog import resolve_pricing

PLAN_VERSION = 1
_STAGES = ("ingest", "research", "recon", "audit", "sca", "validate", "corroborate", "verify", "report")


def _hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def make_plan(fingerprint: dict[str, Any], config: PipelineConfig, *, objective: str = "balanced",
              max_cost: float | None = None, max_duration_minutes: int | None = None,
              benchmark_knowledge: dict | None = None,
              duration_history_minutes: list[float] | None = None) -> dict[str, Any]:
    objective = objective.lower()
    if objective not in {"fast", "economy", "balanced", "deep", "custom"}:
        raise ValueError("objective must be fast, economy, balanced, deep, or custom")
    surfaces = fingerprint.get("surfaces", {})
    verification = fingerprint.get("verification", {})
    reasons: list[dict[str, str]] = []
    def reason(code: str, text: str): reasons.append({"code": code, "reason": text})
    native = sum(fingerprint.get("languages", {}).get(x, 0) for x in ("C", "C/C++", "C++", "Rust"))
    if native:
        reason("NATIVE_MEMORY_RISK_HIGH", "native/unsafe source is present")
    if fingerprint.get("ffi_files"):
        reason("FFI_BOUNDARY_PRESENT", "foreign-function/native binding indicators were found")
    if surfaces.get("parser", 0):
        reason("PARSER_SURFACE_HIGH", "parser/deserialization indicators were found")
    if surfaces.get("auth", 0):
        reason("AUTHZ_SURFACE_PRESENT", "authentication/authorization indicators were found")
    if surfaces.get("crypto", 0):
        reason("CRYPTO_SURFACE_PRESENT", "cryptographic material or protocol code was found")
    if surfaces.get("archive_file", 0):
        reason("FILE_ARCHIVE_SURFACE_PRESENT", "file/archive handling indicators were found")
    if (fingerprint.get("monorepo") or fingerprint.get("approx_loc", 0) > 100_000 or
            (fingerprint.get("context") or {}).get("pressure") == "high"):
        reason("CONTEXT_PRESSURE_HIGH", "large or multi-package repository increases context pressure")
    if verification.get("sanitizers") or verification.get("fuzzers"):
        reason("RUNTIME_SUPPORT_AVAILABLE", "sanitizer/fuzzing evidence makes runtime checks more valuable")
    if fingerprint.get("manifests"):
        reason("DEPENDENCY_SURFACE_PRESENT", "dependency manifests were found")
    if objective == "fast":
        enabled = ["ingest", "recon", "audit", "report"]
    elif objective == "economy":
        enabled = ["ingest", "recon", "audit", "validate", "report"]
    elif objective == "deep":
        enabled = list(_STAGES) + (["runtime"] if verification.get("tests") else [])
    else:
        enabled = ["ingest", "research", "recon", "audit", "sca", "validate", "corroborate", "report"]
        if native and (verification.get("sanitizers") or verification.get("fuzzers")):
            enabled.insert(-1, "verify")
    # Fast/economy are the only objectives allowed to lower the default safety-sensitive stages.
    if max_duration_minutes is not None:
        estimated_high = max(2, round(15 * max(1.0, (fingerprint.get("approx_loc", 0) / 50_000)
                                             + (len(reasons) / 5))))
        if estimated_high > max_duration_minutes:
            before = list(enabled)
            for stage in ("runtime", "verify", "corroborate", "research"):
                if estimated_high <= max_duration_minutes:
                    break
                if stage in enabled:
                    enabled.remove(stage)
                    estimated_high = max(2, round(estimated_high * 0.72))
            if before != enabled:
                reason("DURATION_CONSTRAINT", "optional deep/networked stages removed to fit requested duration")
            if estimated_high > max_duration_minutes:
                raise ValueError(f"no plan fits max duration {max_duration_minutes}m; minimum estimated duration is {estimated_high}m")
    stage_runners = {s: config.stage_runners.get(s, config.runner) for s in enabled}
    stage_models = {s: config.model_for(s) for s in enabled}
    evidence = evidence_for(fingerprint, benchmark_knowledge)
    if evidence["sample_count"] >= 3:
        reason("BENCHMARK_EVIDENCE_AVAILABLE",
               f"{evidence['sample_count']} labeled trial(s) for target class {evidence['target_class']}")
    elif evidence["sample_count"]:
        reason("BENCHMARK_EVIDENCE_WEAK",
               f"only {evidence['sample_count']} labeled trial(s); heuristics remain primary")
    scale = max(1.0, (fingerprint.get("approx_loc", 0) / 50_000) + (len(reasons) / 5))
    if objective == "fast": scale *= .45
    if objective == "economy": scale *= .7
    if objective == "deep": scale *= 1.6
    # Token ranges are intentionally broad.  They are not a billing quote; unknown/custom model
    # prices remain unknown and lower confidence rather than being reported as free.
    token_low = max(1200, int(2500 * scale))
    token_high = max(token_low * 2, int(18_000 * scale))
    stage_estimates = []
    unknown_pricing = []
    low_cost = high_cost = 0.0
    for stage in enabled:
        model = stage_models[stage]
        rates = resolve_pricing(model)
        if rates is None:
            unknown_pricing.append(model)
            stage_estimates.append({"stage": stage, "model": model, "cost": "unknown"})
            continue
        input_rate, output_rate = rates
        # Most stages are input-heavy; validation/reporting have smaller output envelopes.  Keep
        # the stage split deterministic so the plan ID remains reproducible.
        multiplier = 0.55 if stage in {"ingest", "research", "report", "sca"} else 1.0
        lo = (token_low * multiplier * input_rate + token_low * .20 * output_rate) / 1_000_000
        hi = (token_high * multiplier * input_rate + token_high * .35 * output_rate) / 1_000_000
        low_cost += lo
        high_cost += hi
        stage_estimates.append({"stage": stage, "model": model, "input_rate": input_rate,
                                "output_rate": output_rate, "low_usd": round(lo, 4),
                                "high_usd": round(hi, 4)})
    if unknown_pricing:
        low_cost = None
        high_cost = None
        reason("UNKNOWN_PRICING", "one or more selected models have no catalog price")
    else:
        low_cost = round(low_cost, 2)
        high_cost = round(high_cost, 2)
    if max_cost is not None and low_cost is not None and low_cost > max_cost:
        raise ValueError(f"no plan fits max cost ${max_cost:.2f}; minimum estimate is ${low_cost:.2f}")
    confidence = "high" if (fingerprint.get("revision") and fingerprint.get("schema_version") == 1
                             and not unknown_pricing) else "low" if unknown_pricing else "medium"
    inputs = {"fingerprint_id": fingerprint.get("fingerprint_id"), "objective": objective,
              "enabled": enabled, "runners": stage_runners, "models": stage_models,
              "effort": {s: config.stage_effort.get(s, "provider_default") for s in enabled},
              "catalog_snapshot_hash": config.model_catalog_snapshot.get("snapshot_hash"),
              "max_cost": max_cost, "max_duration_minutes": max_duration_minutes,
              "duration_history_count": len(duration_history_minutes or []),
              "benchmark_evidence": evidence}
    duration_low = max(1, round(3 * scale))
    duration_high = max(2, round(15 * scale))
    duration_basis = "heuristic"
    if duration_history_minutes and len(duration_history_minutes) >= 3:
        ordered = sorted(float(x) for x in duration_history_minutes if float(x) > 0)
        if len(ordered) >= 3:
            duration_low = max(1, round(ordered[max(0, len(ordered) // 10)]))
            duration_high = max(duration_low, round(ordered[min(len(ordered) - 1, (len(ordered) * 9) // 10)]))
            duration_basis = "historical_runs"
    if max_duration_minutes is not None and duration_high > max_duration_minutes:
        raise ValueError(f"no plan fits max duration {max_duration_minutes}m; minimum estimated duration is {duration_high}m")
    return {
        "plan_version": PLAN_VERSION, "plan_id": _hash(inputs), "objective": objective,
        "fingerprint_id": fingerprint.get("fingerprint_id"), "enabled_stages": enabled,
        "stage_runners": stage_runners, "stage_models": stage_models,
        "stage_effort": {s: config.stage_effort.get(s, "provider_default") for s in enabled},
        "parallelism": config.max_parallel_audits,
        "stage_budgets": {s: config.session_max_cost_usd for s in enabled
                           if config.session_max_cost_usd is not None},
        "estimated_cost_usd": {"low": low_cost, "high": high_cost, "confidence": confidence,
                               "unknown_models": sorted(set(unknown_pricing))},
        "stage_estimates": stage_estimates,
        "estimated_duration_minutes": {"low": duration_low, "high": duration_high,
                                       "confidence": "medium" if duration_basis == "historical_runs" else "low",
                                       "basis": duration_basis},
        "reasons": reasons, "benchmark_evidence": evidence,
        "target_class": evidence["target_class"],
        "model_catalog_version": config.model_catalog_snapshot.get("version"),
        "inputs": inputs,
    }
