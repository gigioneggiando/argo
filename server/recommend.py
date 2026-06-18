"""'Let the AI choose' — a deterministic config recommender (no LLM call, per the roadmap).

Picks a model/budget/parallelism tier from the user's stated target value, then nudges it by a
quick LOCAL repo size measurement when a local path is given (URL repos are not cloned here).
The recommended runner stays ``mock`` — we never auto-enable real spend; the rationale states the
budget to set when the user switches to a real run.
"""

from __future__ import annotations

from pathlib import Path

OPUS = "claude-opus-4-8"
SONNET = "claude-sonnet-4-6"

_TIERS = {
    "quick": {
        "models": {"recon": SONNET, "audit": SONNET, "validate": SONNET},
        "budget_usd": 10.0, "parallel": 4, "calibration": False,
        "rationale": "Cheap broad sweep — Sonnet across all stages, higher parallelism.",
    },
    "standard": {
        "models": {},
        "budget_usd": 30.0, "parallel": 3, "calibration": False,
        "rationale": "Balanced default — Opus recon + validation, Sonnet audit.",
    },
    "thorough": {
        "models": {"audit": OPUS},
        "budget_usd": 60.0, "parallel": 2, "calibration": True,
        "rationale": "High-value target — audit on Opus (lowest missed-bug rate), tighter parallelism.",
    },
}

_CODE_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".vue", ".java", ".kt", ".scala", ".go",
             ".rb", ".php", ".cs", ".cpp", ".cc", ".c", ".h", ".hpp", ".rs", ".swift", ".sol",
             ".m", ".mm", ".dart", ".ex", ".erl", ".clj"}


def _measure_loc(path: Path) -> int | None:
    """Best-effort LOC count of a local repo (capped). Returns None if not a local dir."""
    if not path.is_dir():
        return None
    loc = files = 0
    for f in path.rglob("*"):
        if files > 6000:
            break
        if f.is_file() and f.suffix.lower() in _CODE_EXT:
            files += 1
            try:
                with f.open("r", encoding="utf-8", errors="ignore") as fh:
                    loc += sum(1 for _ in fh)
            except OSError:
                pass
    return loc


def recommend(repo: str | None, target: str) -> dict:
    tier = _TIERS.get(target, _TIERS["standard"])
    budget = tier["budget_usd"]
    parallel = tier["parallel"]
    rationale = tier["rationale"]

    note = ""
    try:
        loc = _measure_loc(Path(repo)) if repo else None
        if loc and loc > 120_000:
            budget = round(budget * 1.6, 2); parallel = min(6, parallel + 1)
            note = f" Large codebase (~{loc // 1000}k LOC): budget and parallelism raised."
        elif loc and loc < 8_000:
            budget = round(budget * 0.6, 2)
            note = f" Small codebase (~{loc} LOC): budget trimmed."
        elif loc:
            note = f" ~{loc // 1000}k LOC."
    except Exception:
        pass

    config = {
        "runner": "mock",                       # never auto-enable real spend
        "budget_usd": budget,
        "parallel": parallel,
        "calibration": tier["calibration"],
        "audit_model": tier["models"].get("audit"),
        "models": dict(tier["models"]),
    }
    return {"config": config, "rationale": rationale + note}
