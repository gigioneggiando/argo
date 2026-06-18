"""Stage 5 - Report.

Deterministic, code-assembled human-review bundle (no LLM, so the golden-file test is stable):
``REPORT.md`` + one DRAFT submission per confirmed finding. Appends every surviving finding to
the SQLite ledger and flags any dedup_key already seen for this program in a prior run.

This stage NEVER submits. Drafts are marked DRAFT and submission is a manual human action.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..context import RunContext
from ..ranking import confidence_rank, severity_rank

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


def _eff_sev(f: dict) -> str:
    v = (f.get("validation") or {}).get("validated_severity")
    return v or f.get("severity", "")


def _eff_conf(f: dict) -> str:
    v = (f.get("validation") or {}).get("validated_confidence")
    return v or f.get("confidence", "")


def _verdict(f: dict) -> str:
    return (f.get("validation") or {}).get("verdict", "")


def _repo_residual_unknowns(ctx: RunContext) -> list[str]:
    if not ctx.repo_profile_path.exists():
        return []
    try:
        prof = json.loads(ctx.repo_profile_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    ru = prof.get("residual_unknowns")
    if isinstance(ru, list):
        return [str(x) for x in ru]
    return []


def run(ctx: RunContext) -> Path:
    scope = ctx.load_scope()
    doc = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))
    survivors: list[dict] = doc.get("findings", [])
    dropped: list[dict] = doc.get("dropped", [])
    survivors = sorted(
        survivors,
        key=lambda f: (-severity_rank(_eff_sev(f)), -confidence_rank(_eff_conf(f)), f.get("id", "")),
    )

    total_cost = ctx.ledger.run_cost(ctx.run_id)
    n_calls = ctx.ledger.run_call_count(ctx.run_id)

    # --- ledger: record survivors + detect cross-run resubmission --------------------
    resubmissions: list[tuple[dict, list[dict]]] = []
    for f in survivors:
        prior = ctx.ledger.prior_sightings(scope.program_name, f.get("dedup_key", ""), ctx.run_id)
        if prior:
            resubmissions.append((f, prior))
    for f in survivors:
        ctx.ledger.record_finding(
            program_name=scope.program_name,
            run_id=ctx.run_id,
            dedup_key=f.get("dedup_key", ""),
            title=f.get("title"),
            verdict=_verdict(f),
            validated_severity=_eff_sev(f),
        )

    report_md = _render_report(ctx, scope, survivors, dropped, resubmissions,
                               total_cost, n_calls)
    report_path = ctx.run_dir / "REPORT.md"
    report_path.write_text(report_md, encoding="utf-8")

    # --- submission drafts (confirmed only), marked DRAFT ----------------------------
    ctx.drafts_dir.mkdir(parents=True, exist_ok=True)
    n_drafts = 0
    for f in survivors:
        if _verdict(f) == "confirmed":
            draft = _render_draft(ctx, scope, f)
            (ctx.drafts_dir / f"{f.get('id', 'finding')}.md").write_text(draft, encoding="utf-8")
            n_drafts += 1

    print(f"[report] REPORT.md + {n_drafts} draft(s); {len(survivors)} survivor(s); "
          f"cost ${total_cost:.4f} over {n_calls} call(s)")
    return report_path


# ------------------------------------------------------------------------- rendering
def _counts_by_severity(findings: list[dict]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[_eff_sev(f)] = counts.get(_eff_sev(f), 0) + 1
    return counts


def _render_report(ctx, scope, survivors, dropped, resubmissions, total_cost, n_calls) -> str:
    counts = _counts_by_severity(survivors)
    confirmed = [f for f in survivors if _verdict(f) == "confirmed"]
    nrv = [f for f in survivors if _verdict(f) == "needs_runtime_verification"]
    L: list[str] = []

    L.append(f"# Security Audit Report - {scope.program_name}")
    L.append("")
    L.append("> **Automated source-static audit - human-review bundle.** "
             "No live host was contacted, scanned, or exercised by any stage. "
             "Nothing here has been submitted; submission is a manual human action.")
    L.append("")

    # Run metadata
    L.append("## Run metadata")
    L.append("")
    L.append(f"- Run ID: `{ctx.run_id}`")
    L.append(f"- Platform: {scope.platform}")
    L.append(f"- Target type: {scope.target_type}")
    L.append(f"- Generated at: {ctx.timestamp()}")
    L.append(f"- Models: " + ", ".join(f"{k}={v}" for k, v in sorted(scope_models(ctx).items())))
    L.append(f"- LLM cost: ${total_cost:.4f} over {n_calls} call(s)")
    L.append("")

    # Executive summary
    L.append("## Executive summary")
    L.append("")
    L.append(f"- Surviving findings: **{len(survivors)}** "
             f"(confirmed: {len(confirmed)}, needs-runtime-verification: {len(nrv)})")
    L.append(f"- Dropped in validation/scope filtering: **{len(dropped)}**")
    sev_line = ", ".join(f"{s}: {counts[s]}" for s in SEVERITY_ORDER if counts[s])
    L.append(f"- Surviving by severity: {sev_line or 'none'}")
    L.append("")

    # Fix-first ordering
    L.append("## Fix first")
    L.append("")
    if confirmed:
        for i, f in enumerate(confirmed, 1):
            L.append(f"{i}. **{f.get('title')}** ({_eff_sev(f)}/{_eff_conf(f)}, {f.get('cwe')}) "
                     f"- {_primary_ref(f)}")
    else:
        L.append("_No confirmed findings to prioritize._")
    L.append("")

    # Findings, sorted
    L.append("## Findings (sorted by validated severity, then confidence)")
    L.append("")
    if not survivors:
        L.append("_No findings survived validation._")
        L.append("")
    for f in survivors:
        L.extend(_finding_section(f))

    # Residual unknowns
    L.append("## Residual unknowns")
    L.append("")
    if nrv:
        L.append("These need human runtime verification (static evidence strong; exploitability "
                 "depends on runtime/config not visible from source):")
        for f in nrv:
            L.append(f"- **{f.get('title')}** ({f.get('cwe')}, {_primary_ref(f)}) - "
                     f"{_validation_field(f, 'rationale') or 'see finding'}")
    repo_ru = _repo_residual_unknowns(ctx)
    for r in repo_ru:
        L.append(f"- (recon) {r}")
    if not nrv and not repo_ru:
        L.append("_None recorded._")
    L.append("")

    # Dropped
    L.append("## Dropped findings (not reported)")
    L.append("")
    if dropped:
        for d in dropped:
            L.append(f"- `{d.get('id')}` {d.get('title')} ({d.get('cwe')}) - {d.get('reason')}")
    else:
        L.append("_None._")
    L.append("")

    # Resubmission guard
    if resubmissions:
        L.append("## (!) Possible resubmissions (seen in a prior run for this program)")
        L.append("")
        for f, prior in resubmissions:
            runs = ", ".join(p["run_id"] for p in prior)
            L.append(f"- `{f.get('id')}` {f.get('title')} - dedup_key seen in: {runs}")
        L.append("")

    L.append("---")
    L.append("")
    L.append("**Guardrails:** repo mounted read-only | no live interaction performed | "
             "no patching | no auto-submission. Submission drafts in `submission_drafts/` are "
             "marked DRAFT and require manual human review before any submission.")
    L.append("")
    return "\n".join(L)


def _finding_section(f: dict) -> list[str]:
    L = [f"### {f.get('id')} - {f.get('title')}", ""]
    L.append(f"- Severity: **{_eff_sev(f)}** (audit: {f.get('severity')}) | "
             f"Confidence: **{_eff_conf(f)}** | Verdict: **{_verdict(f)}**")
    L.append(f"- CWE: {f.get('cwe')}" + (f" | OWASP: {f.get('owasp')}" if f.get('owasp') else ""))
    L.append(f"- Affected: {', '.join('`' + a + '`' for a in f.get('affected', []))}")
    L.append("")
    L.append(f"**Vulnerable flow.** {f.get('vulnerable_flow', '')}")
    L.append("")
    L.append(f"**Why vulnerable.** {f.get('why_vulnerable', '')}")
    L.append("")
    L.append(f"**Exploit scenario.** {f.get('exploit_scenario', '')}")
    L.append("")
    L.append(f"**Impact.** {f.get('impact', '')}")
    L.append("")
    sdf = _validation_field(f, "surviving_data_flow")
    if sdf:
        L.append(f"**Validated data flow.** {sdf}")
        L.append("")
    L.append(f"**Recommended fix (guidance only).** {f.get('recommended_fix', '')}")
    L.append("")
    if f.get("live_verification_plan"):
        L.append(f"**Live verification plan (for a human, in-scope, non-DoS).** "
                 f"{f.get('live_verification_plan')}")
        L.append("")
    return L


def _render_draft(ctx, scope, f: dict) -> str:
    L: list[str] = []
    L.append("# DRAFT - NOT SUBMITTED")
    L.append("")
    L.append(f"> Platform: **{scope.platform}** | Program: **{scope.program_name}** | "
             f"Source-audit pipeline run `{ctx.run_id}`.")
    L.append("> Human-review draft. The pipeline never submits. Review, verify against the "
             "program's rules of engagement, and submit manually.")
    L.append("")
    L.append(f"## {f.get('title')}")
    L.append("")
    L.append(f"- **Severity:** {_eff_sev(f)} (audit assessment: {f.get('severity')})")
    L.append(f"- **Confidence:** {_eff_conf(f)} | **Verdict:** {_verdict(f)}")
    L.append(f"- **Weakness:** {f.get('cwe')}"
             + (f" | {f.get('owasp')}" if f.get('owasp') else ""))
    L.append(f"- **Affected:** {', '.join('`' + a + '`' for a in f.get('affected', []))}")
    L.append("")
    L.append("### Summary")
    L.append(f.get("why_vulnerable", ""))
    L.append("")
    L.append("### Steps to reproduce / exploit scenario")
    L.append(f.get("exploit_scenario", ""))
    L.append("")
    L.append("### Impact")
    L.append(f.get("impact", ""))
    L.append("")
    sdf = _validation_field(f, "surviving_data_flow")
    if sdf:
        L.append("### Validated data flow")
        L.append(sdf)
        L.append("")
    L.append("### Suggested remediation")
    L.append(f.get("recommended_fix", ""))
    L.append("")
    if scope.target_type == "source_and_live" and f.get("live_verification_plan"):
        L.append("### Live verification plan (human-run, in-scope, non-DoS)")
        L.append(f.get("live_verification_plan"))
        L.append("")
    L.append("---")
    L.append("**DRAFT - verify before submitting. No live testing was performed by the pipeline.**")
    L.append("")
    return "\n".join(L)


def _primary_ref(f: dict) -> str:
    aff = f.get("affected", [])
    return f"`{aff[0]}`" if aff else "(no ref)"


def _validation_field(f: dict, key: str):
    return (f.get("validation") or {}).get(key)


def scope_models(ctx: RunContext) -> dict[str, str]:
    # The model that ACTUALLY ran each pipeline stage (via model_for, so a Codex run reports its
    # model, not the unused Claude stage_models). Excludes post-run helpers like "chat".
    pipeline_stages = ("ingest", "recon", "audit", "validate", "report")
    return {s: ctx.config.model_for(s) for s in pipeline_stages}
