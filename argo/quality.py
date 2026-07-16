"""Quality report (A2) — pair the real-world **triager accept-rate** (a human-precision proxy)
with the **benchmark recall** (labeled corpus). Two numbers, one place: the paper's headline result.

The accept-rate is sourced from the **Fleece** registry via ``argo feedback`` and lives only in the
local ledger — it is never bundled with the public repo. Recall comes from the latest
``benchmark_report.json``. Neither number alone is the result; the pair is.
"""

from __future__ import annotations

import json
from pathlib import Path


def quality_report(ledger, *, program_name: str | None = None,
                   benchmark_report_path=None) -> dict:
    """Pair accept-rate (from the ledger) with benchmark recall (from a report file, if given)."""
    ar = ledger.accept_rate(program_name)
    bench = None
    if benchmark_report_path:
        p = Path(benchmark_report_path)
        if p.exists():
            try:
                rep = json.loads(p.read_text(encoding="utf-8-sig"))
                t = rep.get("totals", {})
                bench = {"suite": rep.get("suite"), "recall": t.get("recall"),
                         "precision": t.get("precision"), "f1": t.get("f1"),
                         "cases": t.get("cases")}
            except (json.JSONDecodeError, OSError):
                bench = None
    return {
        "accept_rate": ar,                  # real-world human precision proxy
        "benchmark": bench,                 # controlled labeled recall / precision / F1
        "headline": {
            "real_world_accept_rate": ar.get("accept_rate"),
            "real_world_n": ar.get("judged"),
            "benchmark_recall": (bench or {}).get("recall"),
        },
        "note": ("Real-world triager accept-rate (precision proxy) paired with benchmark recall "
                 "(labeled corpus). n = judged findings; small samples are noisy. Feedback "
                 "originates in the Fleece registry and is never published from the public repo."),
    }


def write_quality(ledger, runs_dir, *, program_name: str | None = None) -> dict:
    """Compute the quality report (using the latest benchmark in ``runs_dir`` if present) and write
    it to ``<runs_dir>/quality.json``. Returns the report."""
    runs_dir = Path(runs_dir)
    bench = runs_dir / "benchmark_report.json"
    rep = quality_report(ledger, program_name=program_name,
                         benchmark_report_path=bench if bench.exists() else None)
    runs_dir.mkdir(parents=True, exist_ok=True)
    (runs_dir / "quality.json").write_text(json.dumps(rep, indent=2), encoding="utf-8")
    return rep
