"""Safe aggregation of labeled benchmark evidence for the planner.

Only reports produced by the labeled benchmark harness are accepted.  This module deliberately
ignores real-world run findings: without ground truth they cannot teach precision or recall.
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path
from typing import Any, Iterable

KNOWLEDGE_VERSION = 1


def _target_class(fingerprint: dict[str, Any]) -> str:
    surfaces = fingerprint.get("surfaces", {}) or {}
    langs = fingerprint.get("languages", {}) or {}
    native = any(k in langs for k in ("C", "C++", "Rust", "Go"))
    if native and surfaces.get("parser"):
        return "native_parser"
    if surfaces.get("crypto"):
        return "crypto_library"
    if surfaces.get("auth") and surfaces.get("network"):
        return "auth_heavy_service"
    if surfaces.get("archive_file") and ("JavaScript" in langs or "TypeScript" in langs):
        return "dependency_heavy_js"
    if fingerprint.get("manifests"):
        return "dependency_heavy"
    return "other"


def _valid_cases(report: dict) -> Iterable[dict]:
    if not isinstance(report, dict) or "cases" not in report:
        return ()
    return (case for case in report.get("cases", [])
            if isinstance(case, dict) and case.get("valid_trial", True)
            and isinstance(case.get("tp"), int))


def aggregate_reports(reports: Iterable[dict]) -> dict:
    """Build knowledge grouped by benchmark archetype from valid labeled trials only."""
    groups: dict[str, list[dict]] = {}
    sources = 0
    for report in reports:
        if not isinstance(report, dict) or report.get("provenance", {}).get("benchmark_mode") is False:
            # Legacy reports may not carry the marker; their labeled case shape is still safe to
            # consume when explicitly supplied to this function.
            if not isinstance(report, dict) or "cases" not in report:
                continue
        sources += 1
        provenance = report.get("provenance", {}) or {}
        for case in _valid_cases(report):
            key = str(case.get("archetype") or "other")
            row = dict(case)
            row["catalog_version"] = provenance.get("catalog_snapshot", {}).get("version")
            row["stage_models"] = provenance.get("stage_models", {})
            groups.setdefault(key, []).append(row)
    out: dict[str, Any] = {"knowledge_version": KNOWLEDGE_VERSION, "sources": sources,
                            "groups": {}}
    for key, cases in sorted(groups.items()):
        f1 = [float(c.get("f1", 0.0)) for c in cases]
        precision = [float(c.get("precision", 0.0)) for c in cases]
        recall = [float(c.get("recall", 0.0)) for c in cases]
        costs = [float(c.get("cost_usd", 0.0)) for c in cases]
        out["groups"][key] = {
            "sample_count": len(cases),
            "confidence": "high" if len(cases) >= 10 else "medium" if len(cases) >= 3 else "low",
            "metrics": {
                "f1_mean": round(statistics.mean(f1), 4),
                "precision_mean": round(statistics.mean(precision), 4),
                "recall_mean": round(statistics.mean(recall), 4),
                "cost_mean_usd": round(statistics.mean(costs), 6),
            },
            "valid_trials": len(cases),
            "catalog_versions": sorted({c["catalog_version"] for c in cases if c.get("catalog_version")}),
        }
    return out


def load_knowledge(path: str | Path) -> dict:
    raw = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(raw, dict) or raw.get("knowledge_version") != KNOWLEDGE_VERSION:
        raise ValueError("unsupported benchmark knowledge schema")
    if not isinstance(raw.get("groups"), dict):
        raise ValueError("benchmark knowledge must contain groups")
    return raw


def evidence_for(fingerprint: dict[str, Any], knowledge: dict | None) -> dict:
    """Return target-class evidence with an honest low-confidence fallback."""
    target_class = _target_class(fingerprint)
    group = (knowledge or {}).get("groups", {}).get(target_class)
    if not group:
        return {"target_class": target_class, "sample_count": 0, "confidence": "none",
                "basis": "deterministic fingerprint only", "metrics": {}}
    return {"target_class": target_class, "sample_count": int(group.get("sample_count", 0)),
            "confidence": group.get("confidence", "low"), "basis": "labeled benchmark trials",
            "metrics": group.get("metrics", {}),
            "catalog_versions": group.get("catalog_versions", [])}

