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
from dataclasses import dataclass, field
from pathlib import Path

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
    tp = sum(c["tp"] for c in case_results)
    fp = sum(c["fp"] for c in case_results)
    fn = sum(c["fn"] for c in case_results)
    by_arch: dict[str, list[int]] = {}
    by_cwe: dict[str, list[int]] = {}
    for c in case_results:
        a = by_arch.setdefault(c.get("archetype") or "unknown", [0, 0, 0])
        a[0] += c["tp"]; a[1] += c["fp"]; a[2] += c["fn"]
        for cwe, counts in (c.get("cwe_breakdown") or {}).items():
            k = by_cwe.setdefault(cwe, [0, 0, 0])
            k[0] += counts[0]; k[1] += counts[1]; k[2] += counts[2]
    return {
        "suite": suite,
        "totals": {**_prf(tp, fp, fn), "cases": len(case_results)},
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
    run_pipeline(ctx, case.brief, case.repo, commit=case.commit)
    vf = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8-sig"))
    findings = vf.get("findings", [])
    score = score_run(findings, case.expected)
    archetype = case.archetype or (json.loads(ctx.meta_path.read_text(encoding="utf-8-sig"))
                                   .get("archetype") if ctx.meta_path.exists() else None)
    try:
        cost = ctx.ledger.run_cost(ctx.run_id)
    except Exception:
        cost = 0.0
    entry = {"name": case.name, "run_id": ctx.run_id, "archetype": archetype,
             "cost_usd": round(cost, 6),
             "cwe_breakdown": _cwe_breakdown(findings, case.expected, score), **score}
    prov = {k: v for k, v in (("corpus_id", case.corpus_id),
                              ("cve_ids", case.cve_ids or None),
                              ("seeded_from", case.seeded_from)) if v}
    if prov:
        entry["provenance"] = prov
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
              parallel_cases: int = 1, re_audit: bool = False) -> dict:
    """Run + score every case in a suite. Returns the aggregated report (also written to
    ``<runs_dir>/benchmark_report.json``).

    ``parallel_cases`` > 1 runs that many cases concurrently — useful for **corpora at scale**;
    note real (headless) cost adds up and each case still fans out its own audit sessions, so keep
    it modest. Case order (and thus the report) is preserved regardless.

    ``re_audit`` (needs ``fixes``) additionally re-audits each patched copy and folds the
    "is the bug actually gone?" rate into ``patch_quality`` (A3).
    """
    cases = load_suite(suite_dir)
    if parallel_cases > 1 and len(cases) > 1:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(parallel_cases, len(cases))) as ex:
            case_results = list(ex.map(
                lambda c: _run_case(base_config, c, fixes=fixes, re_audit=re_audit), cases))
    else:
        case_results = [_run_case(base_config, c, fixes=fixes, re_audit=re_audit) for c in cases]

    report = _aggregate(case_results, label or Path(suite_dir).name)
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
