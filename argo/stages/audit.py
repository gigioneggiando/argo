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


_SEVERITY_FIX = {"critical": "Critical", "high": "High", "medium": "Medium",
                 "low": "Low", "informational": "Informational", "info": "Informational"}
_CONFIDENCE_FIX = {"confirmed": "Confirmed", "high": "High", "medium": "Medium", "low": "Low"}
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


def _normalize_findings_doc(raw_doc: dict, ctx: RunContext, scope, slug: str):
    """Make a real-model findings file robust to the schema gate WITHOUT discarding good
    findings: backfill required top-level fields, coerce structured string-fields, then validate
    EACH finding and keep only the conformant ones (per-finding drop, not all-or-nothing)."""
    doc = dict(raw_doc)
    doc.setdefault("program_name", scope.program_name)
    doc.setdefault("audit_focus", slug)
    if not isinstance(doc.get("generated_at"), str) or not doc.get("generated_at"):
        doc["generated_at"] = ctx.timestamp()
    kept: list[dict] = []
    dropped: list[str] = []
    coerced = 0
    for f in doc.get("findings", []):
        if not isinstance(f, dict):
            dropped.append("?")
            continue
        cf, changed = _coerce_finding(f)
        coerced += int(changed)
        try:
            validate_findings({**doc, "findings": [cf]}, ctx.assets_dir)
            kept.append(cf)
        except SchemaValidationError:
            dropped.append(str(cf.get("id", "?")))
    doc["findings"] = kept
    return doc, dropped, coerced


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
        raw_doc = json.loads(chosen.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return slug, None, f"findings file is not valid JSON: {exc}"

    doc, dropped_ids, coerced = _normalize_findings_doc(raw_doc, ctx, scope, slug)
    if dropped_ids:
        _log(f"{slug}: dropped {len(dropped_ids)} non-conformant finding(s): {dropped_ids}")
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
    n = len(doc.get("findings", []))
    _log(f"{slug}: {n} finding(s){' [partial session]' if partial else ''}")
    return slug, out, None


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
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_audit_one, ctx, scope, p): p for p in launch}
        for fut in as_completed(futures):
            slug, path, err = fut.result()
            if err:
                _log(f"{slug}: SKIPPED ({err})")
            elif path is not None:
                results.append(path)

    if skipped:
        _log(f"NOTE: {len(skipped)} focus(es) not run due to budget: {skipped}")
    if not results:
        raise RuntimeError("audit: no valid findings files were produced")
    return sorted(results)
