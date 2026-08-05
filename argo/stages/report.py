"""Stage 5 - Report.

Deterministic, code-assembled human-review bundle (no LLM, so the golden-file test is stable):
``REPORT.md`` + one DRAFT submission per confirmed finding. Appends every surviving finding to
the SQLite ledger and flags any dedup_key already seen for this program in a prior run.

This stage NEVER submits. Drafts are marked DRAFT and submission is a manual human action.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..branding import attribution_footer
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


def _corr_verdict(f: dict) -> str:
    return (f.get("corroboration") or {}).get("verdict", "")


def _verify_verdict(f: dict) -> str:
    return (f.get("verification") or {}).get("verdict", "")


def _repo_residual_unknowns(ctx: RunContext) -> list[str]:
    if not ctx.repo_profile_path.exists():
        return []
    try:
        prof = json.loads(ctx.repo_profile_path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError:
        return []
    ru = prof.get("residual_unknowns")
    if isinstance(ru, list):
        return [str(x) for x in ru]
    return []


def run(ctx: RunContext) -> Path:
    scope = ctx.load_scope()
    doc = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8-sig"))
    survivors: list[dict] = doc.get("findings", [])
    dropped: list[dict] = doc.get("dropped", [])
    fixed_upstream: list[dict] = doc.get("fixed_upstream", [])
    split_originals: list[dict] = doc.get("split_originals", [])
    merged_findings: list[dict] = doc.get("merged_findings", [])
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
                               total_cost, n_calls, fixed_upstream,
                               split_originals, merged_findings)
    sig = attribution_footer(ctx.run_id) if ctx.config.attribution else ""   # Argo provenance (default on)
    report_path = ctx.run_dir / "REPORT.md"
    report_path.write_text(report_md + sig, encoding="utf-8")

    # --- submission drafts (confirmed only), marked DRAFT ----------------------------
    ctx.drafts_dir.mkdir(parents=True, exist_ok=True)
    n_drafts = 0
    for f in survivors:
        # Don't draft a submission for something corroboration found to be vendor-documented by design.
        if _verdict(f) == "confirmed" and _corr_verdict(f) != "design_accepted":
            draft = _render_draft(ctx, scope, f)
            (ctx.drafts_dir / f"{f.get('id', 'finding')}.md").write_text(draft + sig, encoding="utf-8")
            n_drafts += 1

    print(f"[report] REPORT.md + {n_drafts} draft(s); {len(survivors)} survivor(s); "
          f"cost ${total_cost:.4f} over {n_calls} call(s)")
    return report_path


def write_pr_draft(ctx: RunContext, finding_id: str, test_command: str | None = None) -> Path:
    """Write a maintainer-facing GitHub PR body scaffold for one confirmed finding."""
    out_dir = ctx.run_dir / "pr_drafts"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{finding_id}.md"
    path.write_text(render_pr_draft(ctx, finding_id, test_command=test_command), encoding="utf-8")
    return path


# ------------------------------------------------------------------------- rendering
def _counts_by_severity(findings: list[dict]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[_eff_sev(f)] = counts.get(_eff_sev(f), 0) + 1
    return counts


def _freshness_rows(findings: list[dict]) -> list[dict]:
    rows: list[dict] = []
    for f in findings:
        flags = f.get("freshness_flag") or []
        if isinstance(flags, dict):
            flags = [flags]
        for flag in flags:
            if not isinstance(flag, dict):
                continue
            commits = []
            for c in flag.get("commits") or []:
                if not isinstance(c, dict):
                    continue
                sha = (c.get("sha") or "")[:12] or "unknown"
                date = c.get("author_date") or "date unknown"
                subject = c.get("subject") or "(no subject)"
                commits.append(f"`{sha}` ({date}) {subject}")
            rows.append({
                "finding_id": f.get("id", "?"),
                "branch": flag.get("branch", "?"),
                "relation": flag.get("relation", "sibling_branch"),
                "file_path": flag.get("file_path", "?"),
                "commits": "; ".join(commits) if commits else "commit details unavailable",
            })
    return rows


def _render_report(ctx, scope, survivors, dropped, resubmissions, total_cost, n_calls,
                   fixed_upstream=None, split_originals=None, merged_findings=None) -> str:
    fixed_upstream = fixed_upstream or []
    split_originals = split_originals or []
    merged_findings = merged_findings or []
    freshness_rows = _freshness_rows(survivors)
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
    if any(_validation_field(f, "runtime") for f in survivors):
        rt_conf = sum(1 for f in survivors
                      if (_validation_field(f, "runtime") or {}).get("verdict") == "runtime_confirmed")
        L.append(f"- Runtime-verified (sandboxed HTTP probes): **{rt_conf}** confirmed")
    if any(f.get("verification") for f in survivors) or split_originals or merged_findings:
        n_reconfirmed = sum(1 for f in survivors if _verify_verdict(f) == "reconfirmed")
        n_corrected = sum(1 for f in survivors if _verify_verdict(f) == "corrected")
        n_split_children = sum(1 for f in survivors if "-split-" in f.get("id", ""))
        L.append(f"- Deep-verified: **{n_reconfirmed}** reconfirmed, **{n_corrected}** corrected, "
                f"**{len(split_originals)}** split into {n_split_children} finding(s), "
                f"**{len(merged_findings)}** merged away")
    n_corroborated_by_passes = sum(1 for f in survivors if len(f.get("corroborating_passes") or []) > 1)
    if n_corroborated_by_passes:
        L.append(f"- **{n_corroborated_by_passes}** finding(s) independently confirmed by "
                f"{'a blind second-opinion pass' if n_corroborated_by_passes == 1 else 'blind second-opinion passes'}")
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

    # Fixed upstream (corroboration appendix — kept, not silently deleted)
    if fixed_upstream:
        L.append("## Already fixed upstream (excluded from active findings)")
        L.append("")
        L.append("Corroboration found these already patched in a newer commit/release than the "
                 "audited revision. Listed for the record; do not report as active:")
        for f in fixed_upstream:
            corr = f.get("corroboration") or {}
            ref = corr.get("fix_commit") or "commit unspecified"
            ev = corr.get("evidence_urls") or []
            tail = f" ({ev[0]})" if ev else ""
            L.append(f"- `{f.get('id')}` {f.get('title')} ({f.get('cwe')}) - fixed in `{ref}`{tail}")
        L.append("")

    # Freshness check appendix - informational only, active findings unchanged.
    if freshness_rows:
        L.append("## Freshness check - verify before sending")
        L.append("")
        L.append("These commits touched files cited by active findings on the audited branch after "
                 "the pinned commit or on version-looking sibling branches. This is informational "
                 "only: a same-file touch is not proof of a fix and does not change severity, "
                 "confidence, or reporting status.")
        for row in freshness_rows:
            relation = {"audited_branch": "audited branch",
                        "sibling_branch": "sibling branch"}.get(row["relation"], row["relation"])
            L.append(f"- `{row['finding_id']}` {relation} `{row['branch']}`, file "
                     f"`{row['file_path']}` - {row['commits']}")
        L.append("")

    # Split originals (deep-verify appendix — kept, not silently deleted)
    if split_originals:
        L.append("## Split at deep-verify (replaced by independent sub-findings, kept for the record)")
        L.append("")
        L.append("Deep-verify found these bundled >=2 independently-triggerable bugs under one "
                 "description. Each sub-finding is reported on its own below (id suffixed "
                 "`-split-N`); the original is kept here for provenance, not as an active finding:")
        for f in split_originals:
            verf = f.get("verification") or {}
            L.append(f"- `{f.get('id')}` {f.get('title')} ({f.get('cwe')}) - {verf.get('rationale', '')}")
        L.append("")

    # Merged findings (deep-verify appendix — kept, not silently deleted)
    if merged_findings:
        L.append("## Merged at deep-verify (duplicate root cause, kept for the record)")
        L.append("")
        L.append("Deep-verify found these share their root cause with another surviving finding "
                 "(by mechanism, not just by dedup key); folded into that finding rather than "
                 "reported twice:")
        for f in merged_findings:
            verf = f.get("verification") or {}
            L.append(f"- `{f.get('id')}` {f.get('title')} ({f.get('cwe')}) - merged into "
                    f"`{verf.get('merged_into', '?')}`. {verf.get('rationale', '')}".rstrip())
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
    passes = f.get("corroborating_passes") or []
    if len(passes) > 1:
        L.append(f"- **Independently confirmed by {len(passes)} blind audit passes**: {', '.join(passes)}")
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
    rt = _validation_field(f, "runtime")
    if rt:
        booted = "sandbox booted" if rt.get("booted") else "sandbox did NOT boot"
        line = f"**Runtime verification.** `{rt.get('verdict', 'runtime_inconclusive')}` ({booted})."
        if rt.get("evidence"):
            line += f" Evidence: {rt.get('evidence')}"
        L.append(line)
        L.append("")
    corr = f.get("corroboration") or {}
    if corr.get("verdict") and corr.get("verdict") != "corroborated":
        note = {"design_accepted": "Vendor-documented design decision / accepted risk",
                "fixed_upstream": "Already fixed upstream",
                "unknown": "Corroboration inconclusive"}.get(corr["verdict"], corr["verdict"])
        line = f"**Corroboration.** {note}. {corr.get('rationale', '')}".rstrip()
        ev = corr.get("evidence_urls") or []
        if corr.get("doc_url"):
            line += f" Docs: {corr['doc_url']}"
        elif ev:
            line += f" Evidence: {ev[0]}"
        L.append(line)
        L.append("")
    verf = f.get("verification") or {}
    if verf.get("verdict"):
        label = {"reconfirmed": "Independently re-derived from source; stands as written.",
                 "corrected": "Mechanism confirmed real; a factual detail was corrected — see below.",
                 "inconclusive": "Could not be independently settled from source alone."
                 }.get(verf["verdict"], verf["verdict"])
        L.append(f"**Deep-verify.** {label}")
        if verf.get("corrections"):
            L.append(f"- Corrected: {verf['corrections']}")
        if verf.get("independent_derivation"):
            L.append(f"- Independent derivation: {verf['independent_derivation']}")
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
    rt = _validation_field(f, "runtime")
    if rt and rt.get("verdict") == "runtime_confirmed":
        L.append("### Runtime verification (sandboxed local instance)")
        L.append(f"Confirmed at runtime via HTTP probe against a sealed local instance. "
                 f"{rt.get('evidence', '')}")
        L.append("")
    verf = f.get("verification") or {}
    if verf.get("verdict") == "corrected" and verf.get("corrections"):
        L.append("### Correction (deep-verify)")
        L.append("An independent re-derivation from source confirmed the mechanism but corrected "
                 f"the following detail: {verf['corrections']}")
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


def render_pr_draft(ctx: RunContext, finding_id: str, test_command: str | None = None) -> str:
    scope = ctx.load_scope()
    doc = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8-sig"))
    finding = next((f for f in doc.get("findings", []) if f.get("id") == finding_id), None)
    if finding is None:
        raise ValueError(f"finding {finding_id!r} was not found in validated_findings.json")
    if _verdict(finding) != "confirmed":
        raise ValueError(f"finding {finding_id!r} is not confirmed; PR drafts are for confirmed findings")
    if _corr_verdict(finding) == "design_accepted":
        raise ValueError(f"finding {finding_id!r} is documented as an accepted design risk")

    affected = finding.get("affected") or []
    affected_text = ", ".join(f"`{item}`" for item in affected) or "_Add affected files._"
    test_text = f"`{test_command}`" if test_command else "_Replace with the exact local test/build command you ran._"
    L: list[str] = []
    L.append(f"# Draft PR body - {finding.get('title')}")
    L.append("")
    L.append("> Human-edit before opening a PR: describe the final patch and paste real test output. ")
    L.append("> Argo generated this from a confirmed source-static finding; it did not submit anything.")
    L.append("")
    L.append("## What does this PR do?")
    L.append("")
    L.append(f"Addresses **{finding.get('title')}** in {affected_text}.")
    L.append("")
    L.append(f"Root cause: {finding.get('why_vulnerable', '')}")
    L.append("")
    L.append(f"Recommended fix direction: {finding.get('recommended_fix', '')}")
    L.append("")
    L.append("## Why is it important?")
    L.append("")
    L.append(f"Impact: {finding.get('impact', '')}")
    L.append("")
    L.append(f"Validated flow: {_validation_field(finding, 'surviving_data_flow') or finding.get('vulnerable_flow', '')}")
    L.append("")
    L.append("## How was this checked?")
    L.append("")
    L.append(f"- Argo run: `{ctx.run_id}` against `{scope.program_name}`")
    L.append(f"- Verdict: `{_verdict(finding)}`; severity: `{_eff_sev(finding)}`; confidence: `{_eff_conf(finding)}`")
    L.append(f"- Local validation command: {test_text}")
    L.append("- Regression expectation: the vulnerable flow above is rejected or safely handled after this patch.")
    L.append("")
    L.append("## Safety notes")
    L.append("")
    L.append("- Argo performed source-static analysis only; no live hosts were contacted.")
    L.append("- This draft is for a human-authored PR after implementing and testing a fix.")
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
