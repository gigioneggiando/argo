"""Stage 3 — Audit.

For each generated prompt, run a separate Claude session in its OWN isolated scratch dir with
READ-ONLY repo access. Each emits a findings JSON validated against ``findings_schema.json``.
Focuses run in parallel up to a cap; a per-run USD budget can abort further launches (the skip
is logged, never silent).
"""

from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ..config import ARTIFACT_TOOLS
from ..context import BudgetExceeded, RunContext, collect_output_files
from ..guardrails import assert_prohibited_present
from ..rendering import with_artifact_contract
from ..runner import RunnerError
from ..schemas import SchemaValidationError, validate_findings


def _log(msg: str) -> None:
    print(f"[audit] {msg}", file=sys.stderr)


# Findings-schema string-typed fields. Real models sometimes emit these as structured
# objects/arrays (e.g. impact: {confidentiality, integrity, availability}); we JSON-stringify
# them so the information is preserved AND the file passes the schema gate.
_TEXT_FIELDS = ("title", "cwe", "owasp", "vulnerable_flow", "why_vulnerable",
                "exploit_scenario", "impact", "recommended_fix", "action_plan",
                "missing_tests", "variants", "live_verification_plan")


_SEVERITY_FIX = {"critical": "Critical", "crit": "Critical", "high": "High",
                 "medium": "Medium", "moderate": "Medium", "med": "Medium",
                 "low": "Low", "informational": "Informational", "info": "Informational",
                 "none": "Informational", "negligible": "Informational"}
_CONFIDENCE_FIX = {"confirmed": "Confirmed", "confirm": "Confirmed", "certain": "Confirmed",
                   "high": "High", "medium": "Medium", "moderate": "Medium", "med": "Medium",
                   "low": "Low", "tentative": "Low"}
# Required finding fields (mirrors findings_schema.json). A finding missing any of these is
# REPAIRED (backfilled) rather than dropped — losing a whole focus to model drift (e.g. the
# Umbraco files-uploads focus) is worse than keeping a flagged, reviewable finding.
_REQUIRED_STR_FIELDS = ("id", "title", "cwe", "vulnerable_flow", "why_vulnerable",
                        "exploit_scenario", "impact", "recommended_fix")
_REPAIR_PLACEHOLDER = "(missing from audit output — schema-repaired; verify manually)"
# Common field-name divergences seen from real models (the prose per-finding format does not
# spell the exact JSON keys). Only applied when the canonical key is absent.
_FIELD_ALIASES = {
    "affected_files": "affected", "affected_components": "affected",
    "exploit_scenarios": "exploit_scenario", "root_cause": "why_vulnerable",
}


def _coerce_finding(f: dict) -> tuple[dict, bool]:
    out = dict(f)
    changed = False
    for alias, canonical in _FIELD_ALIASES.items():
        if alias in out and canonical not in out:
            out[canonical] = out.pop(alias)
            changed = True
    for key, fix in (("severity", _SEVERITY_FIX), ("confidence", _CONFIDENCE_FIX)):
        v = out.get(key)
        if isinstance(v, str) and v.strip().lower() in fix and v != fix[v.strip().lower()]:
            out[key] = fix[v.strip().lower()]
            changed = True
    for k in _TEXT_FIELDS:
        if isinstance(out.get(k), (dict, list)):
            out[k] = json.dumps(out[k], ensure_ascii=False)
            changed = True
    if isinstance(out.get("affected"), list):
        new = [a if isinstance(a, str) else json.dumps(a, ensure_ascii=False)
               for a in out["affected"]]
        if new != out["affected"]:
            out["affected"], changed = new, True
    return out, changed


def _repair_finding(f: dict, slug: str, idx: int) -> dict:
    """Last-resort backfill so a drifted finding survives the schema gate instead of being dropped.
    Only ever ADDS minimal valid values for missing/invalid REQUIRED fields and flags the finding
    ``schema_repair_failed`` so a human (and the validator) treats it with suspicion."""
    out = dict(f)
    repaired: list[str] = []
    if not isinstance(out.get("id"), str) or not out.get("id", "").strip():
        out["id"] = f"{slug.upper()}-REPAIR-{idx:03d}"
        repaired.append("id")
    sev = str(out.get("severity", "")).strip().lower()
    if out.get("severity") not in {"Critical", "High", "Medium", "Low", "Informational"}:
        out["severity"] = _SEVERITY_FIX.get(sev, "Medium")
        repaired.append("severity")
    conf = str(out.get("confidence", "")).strip().lower()
    if out.get("confidence") not in {"Confirmed", "High", "Medium", "Low"}:
        out["confidence"] = _CONFIDENCE_FIX.get(conf, "Low")
        repaired.append("confidence")
    aff = out.get("affected")
    if not isinstance(aff, list) or not aff:
        # Try to salvage a location from any field; else placeholder (never silently lose it).
        salvage = out.get("location") or out.get("file") or out.get("component")
        out["affected"] = [str(salvage)] if salvage else ["(location unspecified — schema-repaired)"]
        repaired.append("affected")
    for k in _REQUIRED_STR_FIELDS:
        if not isinstance(out.get(k), str) or not out.get(k, "").strip():
            out[k] = _REPAIR_PLACEHOLDER
            repaired.append(k)
    if repaired:
        out["schema_repair_failed"] = True
        out["schema_repaired_fields"] = repaired
    return out


def _normalize_findings_doc(raw_doc: dict, ctx: RunContext, scope, slug: str):
    """Make a real-model findings file robust to the schema gate WITHOUT discarding findings:
    backfill required top-level fields, coerce structured string-fields, validate EACH finding,
    and for any that still fail, REPAIR (backfill required fields, flag ``schema_repair_failed``)
    rather than drop — a drifted finding kept-for-review beats a whole focus silently lost."""
    doc = dict(raw_doc)
    doc.setdefault("program_name", scope.program_name)
    doc.setdefault("audit_focus", slug)
    if not isinstance(doc.get("generated_at"), str) or not doc.get("generated_at"):
        doc["generated_at"] = ctx.timestamp()
    kept: list[dict] = []
    repaired_ids: list[str] = []
    unrecoverable: list[str] = []
    coerced = 0
    for idx, f in enumerate(doc.get("findings", [])):
        if not isinstance(f, dict):
            unrecoverable.append("?")
            continue
        cf, changed = _coerce_finding(f)
        coerced += int(changed)
        try:
            validate_findings({**doc, "findings": [cf]}, ctx.assets_dir)
            kept.append(cf)
            continue
        except SchemaValidationError:
            pass
        rf = _repair_finding(cf, slug, idx)
        try:
            validate_findings({**doc, "findings": [rf]}, ctx.assets_dir)
            kept.append(rf)
            repaired_ids.append(str(rf.get("id", "?")))
        except SchemaValidationError:
            unrecoverable.append(str(cf.get("id", "?")))   # genuinely unparseable; the only drop path
    doc["findings"] = kept
    return doc, repaired_ids, unrecoverable, coerced


def _audit_one(ctx: RunContext, scope, prompt_path: Path) -> tuple[str, Path | None, str | None]:
    slug = prompt_path.stem  # e.g. "audit_p1_full_scope"
    prompt_text = prompt_path.read_text(encoding="utf-8")

    # Guardrail (defense-in-depth): the prompt that actually drives the session must still
    # carry the prohibited techniques, even if it was hand-edited after recon.
    assert_prohibited_present(prompt_text, scope.prohibited_techniques)

    findings_filename = f"SECURITY_FINDINGS__{slug}.json"
    prompt = with_artifact_contract(
        prompt_text,
        artifacts=[{
            "type": "findings", "filename": findings_filename, "schema": "findings_schema.json",
            "desc": "the normalized findings for this focus",
        }],
        extra_rules=[
            "Detection and reporting ONLY: do not patch, do not contact any live host.",
        ],
    )
    # The audit template lists per-finding fields in PROSE; give the model the EXACT JSON
    # Schema so it emits the right keys (`affected`, `why_vulnerable`, `exploit_scenario`, ...)
    # and Title-case enums, instead of guessing the structure.
    schema_text = (ctx.assets_dir / "findings_schema.json").read_text(encoding="utf-8")
    prompt += (
        "\n\n## FINDINGS JSON SCHEMA (the `" + findings_filename + "` file MUST validate "
        "against this — use these exact field names and enum values verbatim)\n```json\n"
        + schema_text + "\n```\n")

    work = ctx.work_dir("audit", slug)            # isolated per focus -> no collisions
    partial = False
    try:
        result = ctx.runner.run(
            prompt=prompt,
            run_dir=ctx.run_dir,
            work_dir=work,
            model=ctx.config.model_for("audit"),
            stage="audit",
            run_id=ctx.run_id,
            repo_dir=ctx.repo_dir,                 # READ-ONLY
            allowed_tools=ARTIFACT_TOOLS,
            label=slug,
        )
        files = collect_output_files(result, "SECURITY_FINDINGS__*.json")
        partial = result.is_error
    except RunnerError as exc:
        # Hard session failure (timeout / no-envelope / cap). Don't crash the whole audit —
        # still try to recover any partial findings file from the scratch dir.
        partial = True
        files = sorted(work.glob("SECURITY_FINDINGS__*.json"))
        if not files:
            return slug, None, f"session failed, no partial artifact ({exc})"
        _log(f"{slug}: session failed ({exc}); recovered partial artifact from scratch dir")
    if not files:
        return slug, None, "no findings JSON produced"
    # Prefer the exactly-named file; else take the first JSON found (glob fallback).
    chosen = next((f for f in files if f.name == findings_filename), files[0])
    try:
        raw_doc = json.loads(chosen.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        return slug, None, f"findings file is not valid JSON: {exc}"

    doc, repaired_ids, unrecoverable, coerced = _normalize_findings_doc(raw_doc, ctx, scope, slug)
    if repaired_ids:
        _log(f"{slug}: schema-repaired {len(repaired_ids)} drifted finding(s), kept for review "
             f"(flagged schema_repair_failed): {repaired_ids}")
    if unrecoverable:
        _log(f"{slug}: dropped {len(unrecoverable)} unparseable finding(s): {unrecoverable}")
    if coerced:
        _log(f"{slug}: coerced structured fields to strings in {coerced} finding(s)")
    if not doc.get("findings"):
        return slug, None, "no schema-conformant findings after normalization"
    try:
        validate_findings(doc, ctx.assets_dir)     # final gate on the normalized doc
    except SchemaValidationError as exc:
        return slug, None, f"findings still invalid after normalization: {exc}"

    out = ctx.findings_dir / f"{slug}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    _collect_variant_log(ctx, slug, work)
    n = len(doc.get("findings", []))
    _log(f"{slug}: {n} finding(s){' [partial session]' if partial else ''}")
    return slug, out, None


def _collect_variant_log(ctx: RunContext, slug: str, work: Path) -> Path | None:
    """Preserve the focus's VARIANT_HUNT_LOG (coverage forcing-function) into the run dir, so the
    completeness-critic and the report can see which family members/invariants were checked."""
    logs = sorted(work.glob("VARIANT_HUNT_LOG__*.md")) or sorted(work.glob("VARIANT_HUNT_LOG*.md"))
    if not logs:
        return None
    ctx.variant_logs_dir.mkdir(parents=True, exist_ok=True)
    dst = ctx.variant_logs_dir / f"{slug}.md"
    dst.write_text(logs[0].read_text(encoding="utf-8"), encoding="utf-8")
    return dst


# --------------------------------------------------------------------------- completeness critic
def _finding_key(f: dict) -> str:
    """Coarse identity for dedup across audit + critic passes: title + first affected ref."""
    title = str(f.get("title", "")).strip().lower()
    aff = f.get("affected") or []
    first = str(aff[0]).strip().lower() if aff else ""
    return f"{title}::{first}"


def _critic_pass(ctx: RunContext, scope, slug: str, prompt_path: Path,
                 existing: list[dict]) -> list[dict]:
    """One completeness-critic session for a focus: re-run the SAME ground-truth-laden prompt with
    an addendum that says 'you already produced these; find ONLY what was missed'. Returns the new,
    schema-conformant, deduped findings (empty list if none / on failure)."""
    base = prompt_path.read_text(encoding="utf-8")
    assert_prohibited_present(base, scope.prohibited_techniques)
    findings_filename = f"SECURITY_FINDINGS__{slug}.json"
    log_path = ctx.variant_logs_dir / f"{slug}.md"
    variant_log = log_path.read_text(encoding="utf-8") if log_path.exists() else "(none produced)"
    titles = "\n".join(f"  - {f.get('title','?')}  [{', '.join(map(str, f.get('affected', [])[:2]))}]"
                       for f in existing) or "  (none)"

    addendum = (
        "\n\n---\n\n## COMPLETENESS RE-PASS (this session's ONLY job)\n"
        "A prior pass over THIS focus already produced the findings below. Do NOT repeat them. "
        "Your sole task now is to find what was **MISSED**, using the ground-truth sections above "
        "as the coverage spec:\n"
        "- Every **VARIANT FAMILY** member not yet verified, or marked 🟡/🔴 but not turned into a finding.\n"
        "- Every **INVARIANT** left UNKNOWN or not checked.\n"
        "- Anonymous endpoints / sinks / outbound calls / mass-assignment models not yet traced.\n"
        "- Sibling occurrences of any confirmed root cause that were not enumerated.\n"
        "Emit ONLY genuinely new findings (same schema/file name). If nothing was missed, emit a "
        "findings file with an empty `findings` array. Be precise — do not pad with low-value or "
        "duplicate items.\n\n"
        "### Already-reported findings (do NOT repeat)\n" + titles + "\n\n"
        "### VARIANT_HUNT_LOG produced so far\n```\n" + variant_log[:12000] + "\n```\n"
    )
    prompt = with_artifact_contract(
        base + addendum,
        artifacts=[{"type": "findings", "filename": findings_filename,
                    "schema": "findings_schema.json", "desc": "ONLY the newly-discovered findings"}],
        extra_rules=["Detection and reporting ONLY: do not patch, do not contact any live host."],
    )
    schema_text = (ctx.assets_dir / "findings_schema.json").read_text(encoding="utf-8")
    prompt += ("\n\n## FINDINGS JSON SCHEMA (the `" + findings_filename + "` file MUST validate "
               "against this)\n```json\n" + schema_text + "\n```\n")

    work = ctx.work_dir("audit", f"{slug}__critic")
    try:
        result = ctx.runner.run(
            prompt=prompt, run_dir=ctx.run_dir, work_dir=work,
            model=ctx.config.model_for("audit"), stage="audit", run_id=ctx.run_id,
            repo_dir=ctx.repo_dir, allowed_tools=ARTIFACT_TOOLS, label=f"{slug}-critic")
        files = collect_output_files(result, "SECURITY_FINDINGS__*.json")
    except RunnerError as exc:
        files = sorted(work.glob("SECURITY_FINDINGS__*.json"))
        if not files:
            _log(f"{slug}: critic pass failed ({exc}); keeping prior findings")
            return []
    if not files:
        return []
    chosen = next((f for f in files if f.name == findings_filename), files[0])
    try:
        raw_doc = json.loads(chosen.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError:
        return []
    doc, _rep, _unrec, _coerced = _normalize_findings_doc(raw_doc, ctx, scope, slug)
    _collect_variant_log(ctx, slug, work)   # critic may extend the coverage log
    return doc.get("findings", [])


def _run_critic_for_focus(ctx: RunContext, scope, slug: str, doc_path: Path,
                          prompt_path: Path) -> None:
    """Run up to ``audit_critic_passes`` completeness passes for one focus, appending new findings
    to its file. Stops early when a pass adds nothing (loop-until-dry, capped)."""
    passes = ctx.config.audit_critic_passes
    if passes <= 0:
        return
    doc = json.loads(doc_path.read_text(encoding="utf-8-sig"))
    findings: list[dict] = list(doc.get("findings", []))
    seen = {_finding_key(f) for f in findings}
    for i in range(passes):
        try:
            ctx.assert_budget()
        except BudgetExceeded as exc:
            _log(f"{slug}: skipping critic pass {i+1} (budget reached: {exc})")
            break
        new = _critic_pass(ctx, scope, slug, prompt_path, findings)
        fresh = [f for f in new if _finding_key(f) not in seen]
        for f in fresh:
            seen.add(_finding_key(f))
        if not fresh:
            _log(f"{slug}: critic pass {i+1} found nothing new — stopping")
            break
        findings.extend(fresh)
        _log(f"{slug}: critic pass {i+1} added {len(fresh)} new finding(s) "
             f"({len(findings)} total)")
    if len(findings) != len(doc.get("findings", [])):
        doc["findings"] = findings
        doc_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")


def run(ctx: RunContext) -> list[Path]:
    scope = ctx.load_scope()
    prompts = sorted(ctx.prompts_out_dir.glob("audit_*.md"))
    if not prompts:
        raise RuntimeError("audit: no generated prompts found (run recon first)")

    # Cap the audit fan-out (e.g. --smoke runs one focus). Truncation is logged, never silent.
    cap = ctx.config.max_focuses
    if cap is not None and len(prompts) > cap:
        _log(f"max_focuses={cap}: running {cap} of {len(prompts)} focuses "
             f"(skipping {[p.stem for p in prompts[cap:]]})")
        prompts = prompts[:cap]

    ctx.findings_dir.mkdir(parents=True, exist_ok=True)
    results: list[Path] = []
    skipped: list[str] = []

    # Budget pre-check: only launch focuses while under the cap. Skips are logged, not silent.
    launch: list[Path] = []
    for p in prompts:
        try:
            ctx.assert_budget()
            launch.append(p)
        except BudgetExceeded as exc:
            skipped = [pp.stem for pp in prompts[len(launch):]]
            _log(f"budget reached, skipping {len(skipped)} focus(es): {skipped} ({exc})")
            break

    max_workers = max(1, min(ctx.config.max_parallel_audits, len(launch)))
    produced: dict[str, Path] = {}   # slug -> focus findings doc
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_audit_one, ctx, scope, p): p for p in launch}
        for fut in as_completed(futures):
            slug, path, err = fut.result()
            if err:
                _log(f"{slug}: SKIPPED ({err})")
            elif path is not None:
                results.append(path)
                produced[slug] = path

    # Completeness-critic round: per focus, re-pass to surface missed variant-family members /
    # unverified invariants. Appends new findings in place. Cost-gated; parallel across focuses.
    if ctx.config.audit_critic_passes > 0 and produced:
        crit_workers = max(1, min(ctx.config.max_parallel_audits, len(produced)))
        with ThreadPoolExecutor(max_workers=crit_workers) as ex:
            cfuts = {ex.submit(_run_critic_for_focus, ctx, scope, slug, dpath,
                               ctx.prompts_out_dir / f"{slug}.md"): slug
                     for slug, dpath in produced.items()}
            for fut in as_completed(cfuts):
                try:
                    fut.result()
                except Exception as exc:   # a critic failure must never lose the base findings
                    _log(f"{cfuts[fut]}: critic round error ({type(exc).__name__}: {exc})")

    if skipped:
        _log(f"NOTE: {len(skipped)} focus(es) not run due to budget: {skipped}")
    if not results:
        raise RuntimeError("audit: no valid findings files were produced")
    return sorted(results)
