"""Phase 7 — benchmarks & evaluation.

Measure findings quality so prompt/model changes are *decisions, not guesses*. A **suite** is a set
of labeled cases (a brief + a repo + ``expected_findings.json`` ground truth). The harness runs the
pipeline on each case, matches the validated findings against the labels, and scores
**precision / recall / F1** — overall and sliced **by archetype** and **by CWE**.

Two zero-token modes mirror the rest of Argo:
  * ``runner="mock"`` scores the deterministic fixtures (used to test the harness itself);
  * ``runner="headless"`` measures real model quality.

An **A/B** helper runs the same suite under two configs (e.g. two audit models) and reports the
precision/recall deltas. Patch quality (Phase 6) can be folded in (``fixes=True``): the share of
confirmed findings whose proposed fix verified (applies + compiles + no new errors).

Matching is deliberately lenient on line numbers (labels are approximate): a reported finding
matches an expected one when the **normalized CWE** agrees (or is listed in the label's
``aliases``) and the **file** matches (path-suffix), optionally within a line tolerance.
For a controlled suite the labels are treated as exhaustive: an unmatched reported finding is a
false positive, an unmatched expected vuln is a false negative.
"""

from __future__ import annotations

import json
import re
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .config import CODEX_CHEAP, GEMINI_FLASH, GEMINI_FLASH_LITE, HAIKU, SONNET
from .context import RunContext
from .orchestrator import build_context, new_run_id, run_pipeline
from .stages.ingest import _is_url


def _norm_cwe(s) -> str:
    m = re.search(r"\d+", str(s or ""))
    return m.group(0) if m else ""


def _file_of(ref: str) -> str:
    return str(ref).split(":", 1)[0].replace("\\", "/").strip().lstrip("./")


def _line_of(ref: str):
    parts = str(ref).split(":")
    return int(parts[1]) if len(parts) > 1 and parts[1].strip().isdigit() else None


def _files_match(a: str, b: str) -> bool:
    a, b = a.lower(), b.lower()
    return a == b or a.endswith("/" + b) or b.endswith("/" + a) or a.endswith(b) or b.endswith(a)


@dataclass
class Case:
    name: str
    brief: Path | None            # None => local/general-audit mode (scope synthesized from repo)
    repo: str
    expected: list[dict]
    archetype: str | None = None
    scenario: str | None = None        # mock fixtures scenario for this case
    commit: str | None = None          # pin the repo at this revision (reproducible CVE checkout)
    # provenance (optional; for seeded-bug corpora at scale — surfaced in the report)
    corpus_id: str | None = None       # which labeled corpus this case belongs to
    cve_ids: list[str] = field(default_factory=list)   # associated CVE ids, if any
    seeded_from: str | None = None     # source repo@commit the bug was seeded from


def _resolve(base: Path, p: str) -> Path:
    """Resolve a case path relative to the case dir, then the cwd (repo root)."""
    cand = (base / p)
    return cand if cand.exists() else Path(p)


def load_suite(suite_dir) -> list[Case]:
    """Load every case under ``suite_dir`` (each a dir with ``case.json`` +
    ``expected_findings.json``)."""
    suite_dir = Path(suite_dir)
    cases: list[Case] = []
    for case_json in sorted(suite_dir.glob("*/case.json")):
        cdir = case_json.parent
        meta = json.loads(case_json.read_text(encoding="utf-8-sig"))
        exp_path = cdir / meta.get("expected", "expected_findings.json")
        expected = json.loads(exp_path.read_text(encoding="utf-8-sig")) if exp_path.exists() else []
        repo_raw = meta["repo"]
        # a URL repo is used verbatim (never path-resolved); a local path resolves case-dir-first
        repo = repo_raw if _is_url(repo_raw) else str(_resolve(cdir, repo_raw))
        cases.append(Case(
            name=meta.get("name", cdir.name),
            brief=_resolve(cdir, meta["brief"]) if meta.get("brief") else None,
            repo=repo,
            expected=expected,
            archetype=meta.get("archetype"),
            scenario=meta.get("scenario"),
            commit=meta.get("commit"),
            corpus_id=meta.get("corpus_id"),
            cve_ids=list(meta.get("cve_ids") or []),
            seeded_from=meta.get("seeded_from"),
        ))
    if not cases:
        raise FileNotFoundError(f"no cases (<dir>/case.json) found under {suite_dir}")
    return cases


def validate_suite(suite_dir) -> dict:
    """Validate corpus metadata without cloning, executing, or spending model tokens.

    A URL-backed case must pin an exact commit.  Local cases are accepted for offline fixtures but
    are marked ``portable=false`` unless their metadata declares a commit.  The command is useful
    in CI before adding a case to the frozen Argo corpus.
    """
    root = Path(suite_dir)
    errors: list[str] = []
    warnings: list[str] = []
    rows: list[dict] = []
    for path in sorted(root.glob("*/case.json")):
        cdir = path.parent
        try:
            meta = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as exc:
            errors.append(f"{path}: invalid case.json ({exc})")
            continue
        name = str(meta.get("name") or cdir.name)
        repo = str(meta.get("repo") or "")
        expected_path = cdir / str(meta.get("expected", "expected_findings.json"))
        commit = str(meta.get("commit") or "").strip()
        if not repo:
            errors.append(f"{name}: missing repo")
        if not expected_path.exists():
            errors.append(f"{name}: missing {expected_path.name}")
        else:
            try:
                labels = json.loads(expected_path.read_text(encoding="utf-8-sig"))
                if not isinstance(labels, list):
                    errors.append(f"{name}: expected findings must be a list")
                elif not labels:
                    warnings.append(f"{name}: empty ground truth (negative-only case?)")
            except (OSError, ValueError) as exc:
                errors.append(f"{name}: invalid ground truth ({exc})")
        is_url = _is_url(repo)
        if is_url and not re.fullmatch(r"[0-9a-fA-F]{7,64}", commit):
            errors.append(f"{name}: URL-backed case requires an exact commit SHA")
        if not is_url and not commit:
            warnings.append(f"{name}: local case has no commit; not portable outside this workspace")
        rows.append({"name": name, "repo": repo, "commit": commit or None,
                     "portable": bool(commit), "archetype": meta.get("archetype"),
                     "corpus_id": meta.get("corpus_id")})
    if not rows:
        errors.append(f"no case.json files found under {root}")
    return {"suite": str(root), "schema_version": 1, "cases": rows,
            "case_count": len(rows), "errors": errors, "warnings": warnings,
            "valid": not errors}


def _matches(finding: dict, exp: dict) -> bool:
    want_cwe = {_norm_cwe(exp.get("cwe"))} | {_norm_cwe(a) for a in exp.get("aliases", [])}
    want_cwe.discard("")
    fcwe = _norm_cwe(finding.get("cwe"))
    if want_cwe and fcwe and fcwe not in want_cwe:
        return False
    exp_file = _file_of(exp.get("file", ""))
    tol = exp.get("line_tolerance")
    exp_line = exp.get("line")
    for ref in finding.get("affected") or []:
        if exp_file and not _files_match(_file_of(ref), exp_file):
            continue
        if tol is not None and exp_line is not None:
            ln = _line_of(ref)
            if ln is not None and abs(ln - int(exp_line)) > int(tol):
                continue
        return True
    return False


def score_run(findings: list[dict], expected: list[dict]) -> dict:
    """Greedy one-to-one match of reported findings against expected labels."""
    vulns = [e for e in expected if e.get("kind", "vuln") != "safe"]
    used: set[int] = set()
    matched, missed = [], []
    for exp in vulns:
        hit = next((i for i, f in enumerate(findings)
                    if i not in used and _matches(f, exp)), None)
        if hit is None:
            missed.append(exp.get("label") or exp.get("cwe") or "?")
        else:
            used.add(hit)
            matched.append({"label": exp.get("label"), "finding_id": findings[hit].get("id")})
    spurious = [f.get("id") for i, f in enumerate(findings) if i not in used]
    tp, fp, fn = len(matched), len(spurious), len(missed)
    precision = tp / (tp + fp) if (tp + fp) else (1.0 if tp == 0 and fn == 0 else 0.0)
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
            "matched": matched, "missed": missed, "spurious": spurious}


def _prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if (tp + fp) else 1.0
    r = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4)}


def _aggregate(case_results: list[dict], suite: str) -> dict:
    valid = [c for c in case_results if c.get("valid_trial", True)]
    tp = sum(c["tp"] for c in valid)
    fp = sum(c["fp"] for c in valid)
    fn = sum(c["fn"] for c in valid)
    cost_total = sum(c.get("cost_usd", 0.0) for c in valid)
    call_counts = [c["latency_ms"]["calls"] for c in valid if c.get("latency_ms")]
    latency_total = sum(c["latency_ms"]["total"] for c in valid if c.get("latency_ms"))
    by_arch: dict[str, list[int]] = {}
    by_cwe: dict[str, list[int]] = {}
    for c in valid:
        a = by_arch.setdefault(c.get("archetype") or "unknown", [0, 0, 0])
        a[0] += c["tp"]; a[1] += c["fp"]; a[2] += c["fn"]
        for cwe, counts in (c.get("cwe_breakdown") or {}).items():
            k = by_cwe.setdefault(cwe, [0, 0, 0])
            k[0] += counts[0]; k[1] += counts[1]; k[2] += counts[2]
    total_calls = sum(call_counts)
    invalid_reasons: dict[str, int] = {}
    for c in case_results:
        if c.get("valid_trial", True):
            continue
        for reason in c.get("invalid_reasons", []) or ["unknown"]:
            invalid_reasons[reason] = invalid_reasons.get(reason, 0) + 1
    costs = [float(c.get("cost_usd", 0.0)) for c in valid]
    latencies = [float((c.get("latency_ms") or {}).get("total", 0.0)) for c in valid]
    def _stats(values: list[float]) -> dict:
        if not values:
            return {"mean": 0.0, "median": 0.0, "stdev": 0.0}
        return {"mean": round(statistics.mean(values), 6),
                "median": round(statistics.median(values), 6),
                "stdev": round(statistics.stdev(values), 6) if len(values) > 1 else 0.0}
    return {
        "suite": suite,
        "totals": {**_prf(tp, fp, fn), "cases": len(case_results),
                   "valid_trials": len(valid), "invalid_trials": len(case_results) - len(valid),
                   "cost_usd_total": round(cost_total, 6),
                   "latency_ms_total": latency_total,
                   "latency_ms_mean_per_call": (round(latency_total / total_calls, 1)
                                                if total_calls else 0.0)},
        "statistics": {"cost_usd": _stats(costs), "latency_ms_total": _stats(latencies)},
        "invalid_reasons": invalid_reasons,
        "by_archetype": {k: _prf(*v) for k, v in sorted(by_arch.items())},
        "by_cwe": {k: _prf(*v) for k, v in sorted(by_cwe.items(), key=lambda kv: -sum(kv[1]))},
        "cases": case_results,
    }


def _cwe_breakdown(findings: list[dict], expected: list[dict], score: dict) -> dict:
    """Per-CWE [tp, fp, fn] for the by-cwe rollup."""
    out: dict[str, list[int]] = {}
    matched_ids = {m["finding_id"] for m in score["matched"]}
    for exp in expected:
        if exp.get("kind", "vuln") == "safe":
            continue
        cwe = "CWE-" + _norm_cwe(exp.get("cwe")) if _norm_cwe(exp.get("cwe")) else "CWE-?"
        out.setdefault(cwe, [0, 0, 0])
        if (exp.get("label") or exp.get("cwe") or "?") in score["missed"]:
            out[cwe][2] += 1   # fn
        else:
            out[cwe][0] += 1   # tp
    for f in findings:
        if f.get("id") in score["spurious"]:
            cwe = "CWE-" + _norm_cwe(f.get("cwe")) if _norm_cwe(f.get("cwe")) else "CWE-?"
            out.setdefault(cwe, [0, 0, 0])[1] += 1   # fp
    return out


def _run_case(base_config, case: Case, *, fixes: bool, re_audit: bool = False) -> dict:
    """Run the pipeline on one case and score it. Safe to call concurrently — each case gets its
    own run_id / run_dir; the ledger is opened in WAL mode for concurrent writes."""
    cfg = base_config
    if case.scenario:
        cfg = cfg.with_overrides(fixtures_scenario=case.scenario)
    ctx = build_context(cfg, new_run_id())
    try:
        run_pipeline(ctx, case.brief, case.repo, commit=case.commit)
        vf = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        return {"name": case.name, "run_id": ctx.run_id, "archetype": case.archetype,
                "valid_trial": False, "invalid_reasons": ["pipeline_error"],
                "error": f"{type(exc).__name__}: {exc}", "tp": 0, "fp": 0, "fn": 0,
                "precision": 0.0, "recall": 0.0, "f1": 0.0, "matched": [], "missed": [],
                "spurious": [], "cost_usd": 0.0,
                "latency_ms": {"total": 0.0, "calls": 0, "mean": 0.0},
                "provenance": {"target_commit": case.commit, "case": case.name}}
    findings = vf.get("findings", [])
    score = score_run(findings, case.expected)
    meta = (json.loads(ctx.meta_path.read_text(encoding="utf-8-sig"))
            if ctx.meta_path.exists() else {})
    archetype = case.archetype or meta.get("archetype")
    try:
        cost = ctx.ledger.run_cost(ctx.run_id)
    except Exception:
        cost = 0.0
    try:
        durations = ctx.ledger.call_durations(ctx.run_id)
    except Exception:
        durations = []
    latency_ms = {"total": sum(durations), "calls": len(durations),
                  "mean": round(sum(durations) / len(durations), 1) if durations else 0.0}
    entry = {"name": case.name, "run_id": ctx.run_id, "archetype": archetype,
             "cost_usd": round(cost, 6), "latency_ms": latency_ms,
             "cwe_breakdown": _cwe_breakdown(findings, case.expected, score), **score}
    mismatches = ctx.ledger.run_model_mismatches(ctx.run_id)
    audited_commit = str(meta.get("repo_commit") or "")
    requested_commit = str(case.commit or "")
    # A case may use a sufficiently long immutable SHA prefix (Git resolves it before ingest).
    target_pin_ok = (not requested_commit or audited_commit == requested_commit or
                     audited_commit.startswith(requested_commit))
    entry["valid_trial"] = not mismatches and target_pin_ok
    entry["invalid_reasons"] = ((["model_mismatch"] if mismatches else []) +
                                 ([] if target_pin_ok else ["target_commit_mismatch"]))
    entry["provenance"] = {
        "target_commit": meta.get("repo_commit"), "requested_ref": meta.get("requested_ref"),
        "stage_runners": meta.get("stage_runners", {}), "stage_models": meta.get("stage_models", {}),
        "codex_stage_models": meta.get("codex_stage_models", {}),
        "gemini_stage_models": meta.get("gemini_stage_models", {}),
        "cli_versions": meta.get("cli_versions", {}),
        "model_catalog_version": (meta.get("model_catalog_snapshot") or {}).get("version"),
    }
    prov = {k: v for k, v in (("corpus_id", case.corpus_id),
                              ("cve_ids", case.cve_ids or None),
                              ("seeded_from", case.seeded_from)) if v}
    if prov:
        entry["provenance"].update(prov)
    if fixes:
        from .fixes import generate_fixes
        rep = generate_fixes(ctx, verify=True, re_audit=re_audit)
        patch = {"patched": rep["patched"], "verified": rep["verified"]}
        if re_audit:
            patch["re_audit_ran"] = rep.get("re_audit_ran", 0)
            patch["re_audit_confirmed"] = rep.get("re_audit_confirmed", 0)
        entry["patch"] = patch
    return entry


def run_suite(base_config, suite_dir, *, fixes: bool = False, label: str | None = None,
              parallel_cases: int = 1, re_audit: bool = False, repeats: int = 1) -> dict:
    """Run + score every case in a suite. Returns the aggregated report (also written to
    ``<runs_dir>/benchmark_report.json``).

    ``parallel_cases`` > 1 runs that many cases concurrently — useful for **corpora at scale**;
    note real (headless) cost adds up and each case still fans out its own audit sessions, so keep
    it modest. Case order (and thus the report) is preserved regardless.

    ``re_audit`` (needs ``fixes``) additionally re-audits each patched copy and folds the
    "is the bug actually gone?" rate into ``patch_quality`` (A3).
    """
    if repeats < 1:
        raise ValueError("repeats must be >= 1")
    cases = load_suite(suite_dir)
    if repeats > 1:
        cases = [Case(name=f"{case.name}#trial-{trial}", brief=case.brief, repo=case.repo,
                      expected=case.expected, scenario=case.scenario, commit=case.commit,
                      archetype=case.archetype, corpus_id=case.corpus_id,
                      cve_ids=case.cve_ids, seeded_from=case.seeded_from)
                 for trial in range(1, repeats + 1) for case in cases]
    if parallel_cases > 1 and len(cases) > 1:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(parallel_cases, len(cases))) as ex:
            case_results = list(ex.map(
                lambda c: _run_case(base_config, c, fixes=fixes, re_audit=re_audit), cases))
    else:
        case_results = [_run_case(base_config, c, fixes=fixes, re_audit=re_audit) for c in cases]

    report = _aggregate(case_results, label or Path(suite_dir).name)
    report["provenance"] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runner": base_config.runner,
        "stage_runners": dict(base_config.stage_runners),
        "stage_models": {stage: base_config.model_for(stage)
                         for stage in sorted(set(base_config.stage_models) |
                                              set(base_config.codex_stage_models) |
                                              set(base_config.gemini_stage_models))},
        "stage_effort": dict(base_config.stage_effort),
        "catalog_snapshot": base_config.model_catalog_snapshot,
        "benchmark_mode": True,
    }
    if fixes:
        patched = sum(c.get("patch", {}).get("patched", 0) for c in case_results)
        verified = sum(c.get("patch", {}).get("verified", 0) for c in case_results)
        pq = {"patched": patched, "verified": verified,
              "verified_rate": round(verified / patched, 4) if patched else 0.0}
        if re_audit:
            ra_ran = sum(c.get("patch", {}).get("re_audit_ran", 0) for c in case_results)
            ra_ok = sum(c.get("patch", {}).get("re_audit_confirmed", 0) for c in case_results)
            pq["re_audit_ran"] = ra_ran
            pq["re_audit_confirmed"] = ra_ok
            pq["re_audit_confirmed_rate"] = round(ra_ok / ra_ran, 4) if ra_ran else 0.0
        report["patch_quality"] = pq
    out = Path(base_config.runs_dir) / "benchmark_report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def ab_compare(base_config, suite_dir, *, audit_model_b: str, fixes: bool = False,
               parallel_cases: int = 1, re_audit: bool = False) -> dict:
    """Run the suite under the base config (A) and again with ``audit_model_b`` (B); report the
    per-metric deltas (B − A). On the mock runner both are identical (deterministic) — the value is
    in headless A/B of real models."""
    a = run_suite(base_config, suite_dir, fixes=fixes, label="A",
                  parallel_cases=parallel_cases, re_audit=re_audit)
    b = run_suite(base_config.with_stage_model("audit", audit_model_b), suite_dir, fixes=fixes,
                  label=f"B:{audit_model_b}", parallel_cases=parallel_cases, re_audit=re_audit)
    ta, tb = a["totals"], b["totals"]
    delta = {k: round(tb[k] - ta[k], 4) for k in ("precision", "recall", "f1")}
    report = {"a": a, "b": b, "audit_model_b": audit_model_b, "delta_b_minus_a": delta}
    out = Path(base_config.runs_dir) / "benchmark_ab_report.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def _cheap_tier(cfg):
    """The cheap per-backend model selection ``compare_backends(tier="cheap")`` uses — same
    model-selection logic as ``PipelineConfig.for_smoke()`` (Haiku/Flash-Lite everywhere, Sonnet/
    Flash on recon since that stage is guardrail-gated and a too-weak model unreliably reproduces
    the RoE/prohibited-techniques template), but deliberately WITHOUT for_smoke()'s other caps
    (budget_usd, max_focuses=1, tight timeouts) — a real benchmark run must not artificially starve
    audit fan-out or it understates recall relative to a real ``--tier top`` run on the same corpus.
    Also sets ``codex_model=CODEX_CHEAP`` -- for_smoke() itself never touches codex_model (Codex
    has no per-stage tiering to prime), which would otherwise leave a "cheap" Codex run on whatever
    ``~/.codex/config.toml`` happens to default to."""
    stage_models = {k: HAIKU for k in cfg.stage_models}
    stage_models["recon"] = SONNET
    gemini_stage_models = {k: GEMINI_FLASH_LITE for k in cfg.gemini_stage_models}
    gemini_stage_models["recon"] = GEMINI_FLASH
    return cfg.with_overrides(stage_models=stage_models, gemini_stage_models=gemini_stage_models,
                              codex_model=CODEX_CHEAP)


def _aggregate_cross_backend(backend_reports: dict[str, dict], *, suite: str, tier: str) -> dict:
    totals_by_backend = {}
    for name, rep in backend_reports.items():
        t = rep["totals"]
        totals_by_backend[name] = {
            "precision": t["precision"], "recall": t["recall"], "f1": t["f1"],
            "cost_usd_total": t["cost_usd_total"],
            "valid_trials": t.get("valid_trials", t.get("cases", 0)),
            "invalid_trials": t.get("invalid_trials", 0),
            "mean_latency_ms": t["latency_ms_mean_per_call"],
            "statistics": rep.get("statistics", {}),
            "invalid_reasons": rep.get("invalid_reasons", {}),
        }
    return {
        "suite": suite, "tier": tier,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "backends": backend_reports,
        "totals_by_backend": totals_by_backend,
    }


def compare_backends(base_config, suite_dir, *, backends: list[str], tier: str = "cheap",
                     fixes: bool = False, parallel_cases: int = 1, re_audit: bool = False,
                     repeats: int = 1) -> dict:
    """Run the SAME suite once per backend (Claude/Codex/Gemini/...), each on a comparable model
    tier, and report an N-way comparison — the cross-backend counterpart to ``ab_compare``'s
    same-backend, two-model A/B (which stays untouched; it answers a different question).

    Each backend's config is derived from ``base_config.with_overrides(runner=b)`` — NOT a fresh
    ``PipelineConfig(runner=b)`` — so budget/runs_dir/credentials (gemini_api_key, codex_home,
    claude_config_dir) the caller already configured survive, exactly like ``ab_compare`` already
    derives its B config from ``base_config`` rather than starting over. ``tier="top"`` applies
    ``.calibrated()`` per backend (now fixed to actually affect Codex too — see
    ``PipelineConfig.calibrated``); ``tier="cheap"`` applies ``_cheap_tier`` above.

    NOTE: each per-backend ``run_suite`` call still writes the single shared
    ``benchmark_report.json`` (unchanged, existing behavior) — after this function returns, that
    file reflects only the LAST backend run. The authoritative output of THIS function is
    ``benchmark_crossbackend_report.json``, written below; use that, not ``benchmark_report.json``,
    to read cross-backend results.
    """
    if tier not in ("top", "cheap"):
        raise ValueError(f"tier must be 'top' or 'cheap', got {tier!r}")
    backend_reports: dict[str, dict] = {}
    for b in backends:
        cfg = base_config.with_overrides(runner=b)
        cfg = cfg.calibrated() if tier == "top" else _cheap_tier(cfg)
        backend_reports[b] = run_suite(cfg, suite_dir, fixes=fixes,
                                       parallel_cases=parallel_cases, re_audit=re_audit, repeats=repeats)
    report = _aggregate_cross_backend(backend_reports, suite=Path(suite_dir).name, tier=tier)
    out = Path(base_config.runs_dir) / "benchmark_crossbackend_report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
