"""Pre-audit cost estimation.

The estimator is deliberately read-side only: historical ranges come from the existing ledger,
archetype grouping comes from meta.json, and cold-start sizing uses the repo profile/prompts that
recon already emitted before audit spend begins.
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path
from typing import Iterable

from .archetype import label as archetype_label
from .archetype import run_archetypes
from .config import PipelineConfig
from .costs import cost_report
from .ledger import Ledger

MIN_HISTORY_RUNS = 2

_BASELINE = PipelineConfig()

_DEFAULT_STAGE_SHARES = {
    "ingest": 0.05,
    "research": 0.05,
    "recon": 0.15,
    "audit": 0.45,
    "sca": 0.05,
    "validate": 0.20,
    "corroborate": 0.05,
    "verify": 0.35,
    "runtime": 0.12,
    "live": 0.12,
    "freshness_check": 0.01,
}

_SOURCE_EXTS = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js", ".jsx", ".kt",
    ".m", ".mm", ".php", ".py", ".rb", ".rs", ".scala", ".swift", ".ts", ".tsx",
    ".vue", ".yaml", ".yml", ".toml", ".json", ".xml", ".sol", ".tf",
}
_SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv"}


def estimate_cost(
    ledger: Ledger,
    runs_dir: Path,
    archetype: str,
    config: PipelineConfig,
    *,
    run_id: str | None = None,
) -> dict:
    """Estimate full-run cost for ``archetype`` under ``config``.

    Uses a historical range when at least ``MIN_HISTORY_RUNS`` prior runs exist for this archetype.
    Falls back to a rough prompt/model-rate estimate when history is absent or too thin.
    """
    runs_dir = Path(runs_dir)
    archetype = archetype or "other"
    mapping = run_archetypes(runs_dir)
    excluded = {run_id} if run_id else set()
    run_arch = {rid: arch for rid, arch in mapping.items() if rid not in excluded}

    report = cost_report(ledger, run_archetypes=run_arch)
    row = next((r for r in report.get("by_archetype", []) if r["archetype"] == archetype), None)
    costs = _historical_costs(ledger, run_arch, archetype)
    if row and len(costs) >= MIN_HISTORY_RUNS:
        return _historical_estimate(archetype, row, costs, ledger, config)
    return _cold_start_estimate(ledger, runs_dir, archetype, config, run_id=run_id,
                                sample_count=len(costs))


def format_estimate(estimate: dict) -> str:
    """Human-readable rendering for CLI/status output."""
    label = estimate.get("archetype_label") or estimate.get("archetype") or "unknown"
    rng = estimate.get("estimate", {})
    low = _money(rng.get("low_usd", 0.0))
    high = _money(rng.get("high_usd", 0.0))
    median = _money(rng.get("median_usd", rng.get("center_usd", 0.0)))
    if estimate.get("mode") == "historical":
        hist = estimate.get("history", {})
        mult = estimate.get("config_multiplier", 1.0)
        return (
            f"Cost estimate ({label}): {low}-{high}, median {median}.\n"
            f"Basis: {hist.get('runs', 0)} past run(s), observed "
            f"{_money(hist.get('min_usd', 0.0))}-{_money(hist.get('max_usd', 0.0))}, "
            f"historical median {_money(hist.get('median_usd', 0.0))}; "
            f"config multiplier {mult:.2f}x."
        )
    basis = estimate.get("basis", {})
    return (
        f"Rough cost estimate ({label}, no sufficient history yet): {low}-{high}, "
        f"center {median}.\n"
        f"Basis: {basis.get('prompt_count', 0)} audit prompt(s), about "
        f"{basis.get('prompt_tokens_est', 0)} prompt tokens and observed model token rates. "
        "Treat this as a wide cold-start estimate, not a historical range."
    )


def _historical_estimate(
    archetype: str,
    row: dict,
    costs: list[float],
    ledger: Ledger,
    config: PipelineConfig,
) -> dict:
    costs = sorted(float(c) for c in costs)
    mult = _config_multiplier(ledger, config)
    low = costs[0] * mult
    high = costs[-1] * mult
    median = statistics.median(costs) * mult
    return {
        "mode": "historical",
        "archetype": archetype,
        "archetype_label": archetype_label(archetype),
        "history": {
            "runs": len(costs),
            "calls": row.get("calls", 0),
            "min_usd": round(costs[0], 6),
            "max_usd": round(costs[-1], 6),
            "median_usd": round(statistics.median(costs), 6),
            "avg_usd": round(sum(costs) / len(costs), 6),
        },
        "config_multiplier": round(mult, 4),
        "estimate": {
            "low_usd": round(low, 6),
            "high_usd": round(high, 6),
            "median_usd": round(median, 6),
        },
        "note": "historical range from observed runs of the same archetype",
    }


def _cold_start_estimate(
    ledger: Ledger,
    runs_dir: Path,
    archetype: str,
    config: PipelineConfig,
    *,
    run_id: str | None,
    sample_count: int,
) -> dict:
    run_dir = runs_dir / run_id if run_id else None
    basis = _prompt_and_repo_basis(run_dir)
    rates, fallback_rate = _model_rates(ledger)
    spent = ledger.run_cost(run_id) if run_id else 0.0
    future, stages = _cold_future_cost(config, basis, rates, fallback_rate)
    center = spent + future
    low = spent + future * 0.60
    high = spent + future * 1.80
    return {
        "mode": "cold_start",
        "archetype": archetype,
        "archetype_label": archetype_label(archetype),
        "history": {"runs": sample_count},
        "estimate": {
            "low_usd": round(low, 6),
            "high_usd": round(high, 6),
            "center_usd": round(center, 6),
        },
        "basis": basis,
        "stage_estimates": stages,
        "spent_pre_audit_usd": round(spent, 6),
        "note": "rough (no sufficient history for this archetype yet)",
    }


def _historical_costs(ledger: Ledger, mapping: dict[str, str], archetype: str) -> list[float]:
    return [
        float(r["cost"])
        for r in ledger.recent_run_costs(10_000)
        if mapping.get(r["run_id"]) == archetype and float(r["cost"]) > 0
    ]


def _stage_shares(ledger: Ledger) -> dict[str, float]:
    rows = ledger.cost_by_stage()
    total = sum(float(r["cost"]) for r in rows)
    if total <= 0:
        return {}
    return {str(r["stage"]): float(r["cost"]) / total for r in rows if float(r["cost"]) > 0}


def _share(shares: dict[str, float], stage: str) -> float:
    return shares.get(stage, _DEFAULT_STAGE_SHARES.get(stage, 0.0))


def _config_multiplier(ledger: Ledger, config: PipelineConfig) -> float:
    shares = _stage_shares(ledger)
    scale = 1.0

    audit_share = _share(shares, "audit")
    base_audit_sessions = 1 + max(0, _BASELINE.audit_critic_passes)
    cfg_audit_sessions = 1 + max(0, config.audit_critic_passes)
    if base_audit_sessions:
        scale += audit_share * ((cfg_audit_sessions / base_audit_sessions) - 1.0)

    # Each blind pass repeats a fresh recon + audit cycle over the same scope/repo.
    so_delta = max(0, config.second_opinion_passes - _BASELINE.second_opinion_passes)
    if so_delta:
        scale += so_delta * (_share(shares, "recon") + audit_share *
                             (cfg_audit_sessions / base_audit_sessions))

    toggles = [
        ("research", "research_enabled"),
        ("sca", "sca_enabled"),
        ("corroborate", "corroborate_enabled"),
        ("verify", "verify_enabled"),
        ("runtime", "runtime_enabled"),
        ("freshness_check", "freshness_check_enabled"),
    ]
    for stage, attr in toggles:
        base_on = bool(getattr(_BASELINE, attr))
        cfg_on = bool(getattr(config, attr))
        if cfg_on == base_on:
            continue
        delta = _share(shares, stage)
        scale += delta if cfg_on else -delta
    return max(0.05, scale)


def _model_rates(ledger: Ledger) -> tuple[dict[str, float], float]:
    rates: dict[str, float] = {}
    for row in ledger.cost_by_model():
        out = int(row.get("output_tokens") or 0)
        cost = float(row.get("cost") or 0.0)
        model = str(row.get("model") or "")
        if model and out > 0 and cost > 0:
            rates[model] = cost / out * 1000.0
    fallback = statistics.median(rates.values()) if rates else 0.0
    return rates, fallback


def _rate_for(config: PipelineConfig, stage: str, rates: dict[str, float],
              fallback: float) -> tuple[str, float]:
    model = config.model_for(stage)
    return model, rates.get(model, fallback)


def _cost_for_tokens(config: PipelineConfig, stage: str, output_tokens: int,
                     rates: dict[str, float], fallback_rate: float) -> dict:
    model, rate = _rate_for(config, stage, rates, fallback_rate)
    cost = rate * max(0, output_tokens) / 1000.0
    return {
        "stage": stage,
        "model": model,
        "output_tokens_est": int(output_tokens),
        "rate_per_1k_output_usd": round(rate, 6),
        "cost_usd": round(cost, 6),
    }


def _cold_future_cost(
    config: PipelineConfig,
    basis: dict,
    rates: dict[str, float],
    fallback_rate: float,
) -> tuple[float, list[dict]]:
    prompt_count = max(1, int(basis.get("prompt_count") or 1))
    prompt_tokens = max(1000, int(basis.get("prompt_tokens_est") or 0))
    first_prompt = max(800, int(basis.get("first_prompt_tokens_est") or prompt_tokens))
    loc = int(basis.get("loc_est") or 0)
    expected_findings = max(1, prompt_count * 2 + loc // 25_000)
    critic_factor = 1 + max(0, config.audit_critic_passes)

    stages: list[dict] = []

    def add(stage: str, tokens: int) -> None:
        stages.append(_cost_for_tokens(config, stage, tokens, rates, fallback_rate))

    audit_one_pass = max(1200 * prompt_count, int(first_prompt * 0.35) * prompt_count)
    add("audit", audit_one_pass * critic_factor)

    if config.sca_enabled:
        add("sca", max(700, min(3000, 400 + loc // 80)))

    if config.second_opinion_passes > 0:
        for _i in range(config.second_opinion_passes):
            add("recon", max(1000, int(prompt_tokens * 0.18)))
            add("audit", audit_one_pass * critic_factor)

    validate_tokens = max(900, expected_findings * 850)
    add("validate", validate_tokens)

    if config.corroborate_enabled:
        add("corroborate", max(650, expected_findings * 650))
    if config.verify_enabled:
        n = expected_findings if config.verify_max_findings is None else min(
            expected_findings, max(0, config.verify_max_findings))
        add("verify", max(0, n) * 1800)
    if config.runtime_enabled:
        add("runtime", 900 + expected_findings * 500)

    return sum(float(s["cost_usd"]) for s in stages), stages


def _prompt_and_repo_basis(run_dir: Path | None) -> dict:
    prompt_files: list[Path] = []
    if run_dir:
        prompt_dir = run_dir / "prompts"
        if prompt_dir.exists():
            prompt_files = sorted(prompt_dir.glob("audit_*.md"))
    prompt_lengths = [_safe_len(p) for p in prompt_files]
    prompt_tokens = sum(_tokens_from_chars(n) for n in prompt_lengths)
    first_prompt_tokens = _tokens_from_chars(prompt_lengths[0]) if prompt_lengths else 0
    loc, files = _repo_stats(run_dir)
    if prompt_tokens <= 0:
        prompt_tokens = max(1000, loc * 2 + files * 25)
        first_prompt_tokens = prompt_tokens
    return {
        "prompt_count": len(prompt_files),
        "prompt_tokens_est": int(prompt_tokens),
        "first_prompt_tokens_est": int(first_prompt_tokens),
        "loc_est": int(loc),
        "file_count_est": int(files),
    }


def _safe_len(path: Path) -> int:
    try:
        return len(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return 0


def _tokens_from_chars(chars: int) -> int:
    return max(0, int(chars / 4))


def _repo_stats(run_dir: Path | None) -> tuple[int, int]:
    if not run_dir:
        return 0, 0
    profile = _safe_json(run_dir / "repo_profile.json")
    loc = _first_number(profile, ("loc", "lines_of_code", "total_loc", "sloc"))
    files = _first_number(profile, ("file_count", "files", "total_files"))
    if loc and files:
        return loc, files
    scan_loc, scan_files = _scan_repo(run_dir / "repo")
    return loc or scan_loc, files or scan_files


def _safe_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _first_number(data: dict, names: Iterable[str]) -> int:
    wanted = {n.lower() for n in names}

    def walk(obj) -> int:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if str(k).lower() in wanted and isinstance(v, (int, float)):
                    return int(v)
            for v in obj.values():
                found = walk(v)
                if found:
                    return found
        return 0

    return walk(data)


def _scan_repo(repo_dir: Path) -> tuple[int, int]:
    if not repo_dir.exists():
        return 0, 0
    loc = files = 0
    for p in repo_dir.rglob("*"):
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if not p.is_file() or p.suffix.lower() not in _SOURCE_EXTS:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files += 1
        loc += len(text.splitlines())
        if files >= 2000:
            break
    return loc, files


def _money(value: float | int | None) -> str:
    value = float(value or 0.0)
    return f"${value:.2f}"
