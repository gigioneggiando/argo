"""Stage — Corroborate (opt-out; networked; runs AFTER validate, BEFORE runtime/live).

For each surviving finding, cross-check it against the project's **own documentation** and the source
repository's **VCS history** (commits / PRs / releases / advisories) over public web OSINT, to CONFIRM
or DISCARD it. This closes two real false-positive modes seen in vendor replies:
  * a finding the docs describe as **intended** -> downgraded to ``design_accepted`` (kept, flagged);
  * a finding already **patched** in a newer commit -> moved to ``fixed_upstream`` (kept in an
    appendix, never silently deleted — see the downgrade-don't-delete principle).

Inputs: ``validated_findings.json`` (validate's survivors). Output: the same file, rewritten with a
``corroboration`` block attached to each finding and a new top-level ``fixed_upstream`` list.

Guardrails (defense in depth):
  * Split into isolated sessions: ``corroborate_docs`` mounts the repo and has no network tools;
    ``corroborate`` keeps OSINT tools but has no repo mount and receives no source excerpts
    (network OR repo, never both in one session).
  * It must NEVER contact the program's live in-scope hosts (passed as a forbidden list, like research).
  * Best-effort: a failure here never fails the run — the finding is simply left ``unknown``.
  * Self-consistency backstop: the model occasionally writes a ``rationale`` that itself asserts
    vendor-confirmed/documented intent while leaving ``verdict`` at ``corroborated`` — a real
    contradiction seen in production (2/27 gitea findings, 2026-07-22), not a hypothetical. A
    deterministic, high-precision phrase check (``_reconcile_verdict_with_rationale``) catches this
    and corrects the verdict, preserving the model's original call in
    ``verdict_overridden_from`` for transparency rather than silently substituting it.
"""

from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ..config import ARTIFACT_TOOLS, RESEARCH_TOOLS
from ..context import BudgetExceeded, RunContext, atomic_write_json, collect_output_files
from ..models import Corroboration, Finding
from ..rendering import design_context_block, fill_placeholders, with_artifact_contract
from ..runner import RunnerError
from .validate import _build_excerpts

_LIVE_ASSET_TYPES = {"web", "api", "mobile"}
_VALID_VERDICTS = {"corroborated", "design_accepted", "fixed_upstream", "unknown"}

#: A "verdict": "unknown" can mean two very different things for a reader of the report: the model
#: actually looked and could not tell (a real quality signal), or the session/backend never ran at
#: all (a pure tooling gap — e.g. a session-limit 429, every backend exhausted). Both paths above set
#: one of these exact rationale prefixes for the infra-failure case; this lets the run() summary below
#: report the split explicitly instead of collapsing them into one opaque "unknown" count.
_INFRA_FAILURE_RATIONALE_PREFIXES = (
    "corroboration session failed:",
    "corroboration docs session failed:",
    "corroboration osint session failed:",
    "corroboration session produced no verdict file",
    "corroboration verdict was not valid JSON",
    "no verdict returned for this finding in the batch",
)


def _is_infra_failure(corr: Corroboration) -> bool:
    return (corr.verdict == "unknown" and bool(corr.rationale)
            and any(prefix in corr.rationale for prefix in _INFRA_FAILURE_RATIONALE_PREFIXES))


# Self-consistency backstop for a real, observed LLM failure mode: the model's free-text ``rationale``
# correctly identifies and cites vendor documentation proving a behavior is intentional, but the
# structured ``verdict`` field it outputs alongside that same rationale still says "corroborated" — a
# contradiction between what the model wrote and what it clicked, not a code-plumbing bug. Found
# 2026-07-22 on gitea (CRYPTO-TOKEN-002, SSRF-001): both were about to ship as new vulnerabilities in
# a disclosure until a human re-read all 27 rationales by hand and caught the mismatch. The primary
# fix is prompting the model to keep verdict and rationale consistent (see 08_corroborate_prompt.md /
# 08b_corroborate_batch_prompt.md); this is the deterministic safety net for when that still slips
# through. Deliberately a SHORT, high-precision phrase list, not a broad keyword scan — a false
# positive here (wrongly downgrading a real vulnerability to design_accepted) is a worse outcome than
# the false negative it's meant to catch, so every phrase is one that essentially only appears when a
# rationale is actually asserting vendor-confirmed intent, not describing a design constraint the
# vulnerability violates.
_DESIGN_ACCEPTED_SIGNALS = (
    "documented as intended",
    "documented as intentional",
    "intended, documented behavior",
    "confirmed intentional",
    "vendor confirms this is intended",
    "vendor documentation confirms this is intended",
    "explicitly documented as intended",
    "is a documented design decision",
    "is an accepted design decision",
    "accepted risk per",
    "known, accepted limitation",
    "matches the vendor's documented threat model",
)


def _reconcile_verdict_with_rationale(corr: Corroboration) -> Corroboration:
    """If ``rationale`` strongly asserts vendor-confirmed/documented intent while ``verdict`` is
    anything other than ``design_accepted``, correct the verdict — but never silently: the model's
    own original verdict is preserved in ``verdict_overridden_from`` so a human reviewing the report
    can see exactly what happened and double-check the call (see the module-level note above)."""
    if corr.verdict == "design_accepted" or corr.verdict == "fixed_upstream" or not corr.rationale:
        return corr
    text = corr.rationale.lower()
    if any(sig in text for sig in _DESIGN_ACCEPTED_SIGNALS):
        return corr.model_copy(update={
            "verdict": "design_accepted",
            "verdict_overridden_from": corr.verdict,
        })
    return corr


def _log(msg: str) -> None:
    print(f"[corroborate] {msg}", file=sys.stderr)


def _repo_url(scope) -> str:
    for a in scope.source_repo_assets:
        return a.asset
    return "(unknown)"


def _repo_ref(ctx: RunContext, scope) -> str:
    """The exact revision the audit ran against (so the model corroborates against *newer* history)."""
    try:
        meta = json.loads(ctx.meta_path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        meta = {}
    sha = meta.get("repo_commit")
    src = meta.get("repo_source") or _repo_url(scope)
    return f"{src} @ {sha}" if sha else str(src)


def _bullets(items: list[str], empty: str) -> str:
    items = [i.strip() for i in items if i and i.strip()]
    return "\n".join(f"  - {i}" for i in items) if items else f"  {empty}"


def _public_finding(finding: Finding) -> dict:
    """The strict data boundary for the networked pass: no source-derived fields or excerpts."""
    return {
        "id": finding.id,
        "title": finding.title,
        "cwe": finding.cwe,
        "why_vulnerable": finding.why_vulnerable,
        "affected": finding.affected,
    }


def _build_docs_prompt(ctx: RunContext, scope, finding: Finding) -> str:
    template = (ctx.assets_dir / "08c_corroborate_docs_prompt.md").read_text(encoding="utf-8")
    excerpts = _build_excerpts(
        ctx.repo_dir, finding.affected,
        ctx.config.excerpt_context_lines, ctx.config.excerpt_max_bytes,
    )
    rendered = fill_placeholders(template, {
        "REPO_REF": _repo_ref(ctx, scope),
        "FINDING_JSON": json.dumps(finding.model_dump(exclude_none=True), indent=2),
        "CODE_EXCERPTS": excerpts,
        "FINDING_ID": finding.id,
    })
    if scope.accepted_risks and scope.accepted_risks.strip():
        rendered = rendered.rstrip() + "\n\n" + design_context_block(scope.accepted_risks)
    return with_artifact_contract(rendered, artifacts=[{
        "type": "corroboration", "filename": f"corroboration_{finding.id}.json", "schema": None,
        "desc": "the offline docs/VCS corroboration verdict for this finding",
    }])


def _build_osint_prompt(ctx: RunContext, scope, finding: Finding) -> str:
    template = (ctx.assets_dir / "08_corroborate_prompt.md").read_text(encoding="utf-8")
    live = [a.asset.strip() for a in scope.in_scope
            if a.type in _LIVE_ASSET_TYPES and a.asset.strip()]
    rendered = fill_placeholders(template, {
        "MAX_SEARCHES": str(ctx.config.corroborate_max_searches),
        "REPO_REF": _repo_ref(ctx, scope),
        "FINDING_JSON": json.dumps(_public_finding(finding), indent=2),
        "DOC_LINKS": _bullets(ctx.config.doc_links,
                              "(none provided — search the web for the official documentation)"),
        "REPO_URL": _repo_url(scope),
        "REFERENCE_LINKS": _bullets(scope.reference_links, "(none provided)"),
        "FORBIDDEN_HOSTS": _bullets(live, "(none listed in scope)"),
        "FINDING_ID": finding.id,
    })
    return with_artifact_contract(
        rendered,
        artifacts=[{
            "type": "corroboration", "filename": f"corroboration_{finding.id}.json", "schema": None,
            "desc": "the docs/history corroboration verdict for this single finding",
        }],
    )


def _build_docs_batch_prompt(ctx: RunContext, scope, batch: list[Finding]) -> str:
    template = (ctx.assets_dir / "08d_corroborate_docs_batch_prompt.md").read_text(encoding="utf-8")
    items = [{
        "finding_id": f.id,
        "finding": f.model_dump(exclude_none=True),
        "code_excerpts": _build_excerpts(
            ctx.repo_dir, f.affected,
            ctx.config.excerpt_context_lines, ctx.config.excerpt_max_bytes),
    } for f in batch]
    rendered = fill_placeholders(template, {
        "REPO_REF": _repo_ref(ctx, scope),
        "FINDINGS_BATCH": json.dumps(items, indent=2),
    })
    if scope.accepted_risks and scope.accepted_risks.strip():
        rendered = rendered.rstrip() + "\n\n" + design_context_block(scope.accepted_risks)
    return with_artifact_contract(rendered, artifacts=[{
        "type": "corroborations", "filename": "corroborations.json", "schema": None,
        "desc": "one offline docs/VCS verdict per finding_id",
    }])


def _build_osint_batch_prompt(ctx: RunContext, scope, batch: list[Finding]) -> str:
    template = (ctx.assets_dir / "08b_corroborate_batch_prompt.md").read_text(encoding="utf-8")
    items = [{"finding_id": f.id, "finding": _public_finding(f)} for f in batch]
    live = [a.asset.strip() for a in scope.in_scope
            if a.type in _LIVE_ASSET_TYPES and a.asset.strip()]
    rendered = fill_placeholders(template, {
        "MAX_SEARCHES": str(ctx.config.corroborate_max_searches),
        "REPO_REF": _repo_ref(ctx, scope),
        "FINDINGS_BATCH": json.dumps(items, indent=2),
        "DOC_LINKS": _bullets(ctx.config.doc_links,
                              "(none provided — search the web for the official documentation)"),
        "REPO_URL": _repo_url(scope),
        "REFERENCE_LINKS": _bullets(scope.reference_links, "(none provided)"),
        "FORBIDDEN_HOSTS": _bullets(live, "(none listed in scope)"),
    })
    return with_artifact_contract(rendered, artifacts=[{
        "type": "corroborations", "filename": "corroborations.json", "schema": None,
        "desc": "a JSON object {\"corroborations\": [...]} with ONE verdict per finding_id in the batch",
    }])


def _coerce_corroboration(row: dict) -> Corroboration:
    if row.get("verdict") not in _VALID_VERDICTS:
        row = {**row, "verdict": "unknown"}
    row = {k: v for k, v in row.items() if k != "finding_id"}   # not part of the model
    try:
        return Corroboration.model_validate(row)
    except Exception:  # noqa: BLE001 — a malformed row must never crash a best-effort stage
        return Corroboration(verdict="unknown", rationale="corroboration row failed schema validation")


def _run_batch_pass(ctx: RunContext, scope, batch: list[Finding], *, online: bool) -> dict[str, Corroboration]:
    """Run one isolated corroboration pass; repo access and network access never coexist."""
    ids = [f.id for f in batch]
    pass_name = "osint" if online else "docs"
    try:
        result = ctx.runner.run(
            prompt=(_build_osint_batch_prompt(ctx, scope, batch) if online
                    else _build_docs_batch_prompt(ctx, scope, batch)),
            run_dir=ctx.run_dir,
            work_dir=ctx.work_dir("corroborate", f"batch-{pass_name}-" + ids[0]),
            model=ctx.config.model_for("corroborate"),
            stage="corroborate" if online else "corroborate_docs", run_id=ctx.run_id,
            repo_dir=None if online else ctx.repo_dir,
            allowed_tools=RESEARCH_TOOLS if online else ARTIFACT_TOOLS,
            label=f"corroborate-{pass_name}-batch-" + ids[0])
        files = collect_output_files(result, "corroborations*.json")
    except RunnerError as exc:
        return {fid: Corroboration(verdict="unknown",
                                   rationale=f"corroboration {pass_name} session failed: {exc}") for fid in ids}
    out: dict[str, Corroboration] = {}
    for fp in files:
        try:
            doc = json.loads(fp.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            continue
        rows = doc.get("corroborations") if isinstance(doc, dict) else (doc if isinstance(doc, list) else [])
        for row in rows or []:
            fid = row.get("finding_id") if isinstance(row, dict) else None
            if fid in ids and fid not in out:
                out[fid] = _coerce_corroboration(row)
    for fid in ids:
        out.setdefault(fid, Corroboration(verdict="unknown",
                                          rationale="no verdict returned for this finding in the batch"))
    return out


def _run_one_pass(ctx: RunContext, scope, finding: Finding, *, online: bool) -> Corroboration:
    pass_name = "osint" if online else "docs"
    try:
        result = ctx.runner.run(
            prompt=(_build_osint_prompt(ctx, scope, finding) if online
                    else _build_docs_prompt(ctx, scope, finding)),
            run_dir=ctx.run_dir,
            work_dir=ctx.work_dir("corroborate", f"{pass_name}-{finding.id}"),
            model=ctx.config.model_for("corroborate"),
            stage="corroborate" if online else "corroborate_docs",
            run_id=ctx.run_id,
            repo_dir=None if online else ctx.repo_dir,
            allowed_tools=RESEARCH_TOOLS if online else ARTIFACT_TOOLS,
            label=finding.id,
        )
        files = collect_output_files(result, "corroboration_*.json")
    except RunnerError as exc:
        return Corroboration(verdict="unknown",
                             rationale=f"corroboration {pass_name} session failed: {exc}")
    if not files:
        return Corroboration(verdict="unknown",
                             rationale="corroboration session produced no verdict file")
    try:
        data = json.loads(files[0].read_text(encoding="utf-8-sig"))
    except ValueError:
        return Corroboration(verdict="unknown", rationale="corroboration verdict was not valid JSON")
    if data.get("verdict") not in _VALID_VERDICTS:
        data["verdict"] = "unknown"
    data.pop("finding_id", None)            # not part of the Corroboration model
    return Corroboration.model_validate(data)


_VERDICT_PRIORITY = {"unknown": 0, "corroborated": 1, "design_accepted": 2, "fixed_upstream": 3}


def _merge_corroborations(docs: Corroboration, osint: Corroboration) -> Corroboration:
    """Combine both independent checks into the existing single-result contract."""
    winner = max((docs, osint), key=lambda c: _VERDICT_PRIORITY[c.verdict])
    rationales = []
    if docs.rationale:
        rationales.append(f"Offline docs/VCS: {docs.rationale}")
    if osint.rationale:
        rationales.append(f"Public OSINT: {osint.rationale}")
    urls = list(dict.fromkeys([*docs.evidence_urls, *osint.evidence_urls]))
    return Corroboration(
        verdict=winner.verdict,
        rationale=" ".join(rationales) or None,
        evidence_urls=urls,
        fix_commit=winner.fix_commit or docs.fix_commit or osint.fix_commit,
        doc_url=winner.doc_url or docs.doc_url or osint.doc_url,
        adjusted_severity=winner.adjusted_severity,
    )


def _corroborate_batch(ctx: RunContext, scope, batch: list[Finding]) -> dict[str, Corroboration]:
    docs = _run_batch_pass(ctx, scope, batch, online=False)
    osint = _run_batch_pass(ctx, scope, batch, online=True)
    return {f.id: _merge_corroborations(docs[f.id], osint[f.id]) for f in batch}


def _corroborate_one(ctx: RunContext, scope, finding: Finding) -> Corroboration:
    docs = _run_one_pass(ctx, scope, finding, online=False)
    osint = _run_one_pass(ctx, scope, finding, online=True)
    return _merge_corroborations(docs, osint)


def run(ctx: RunContext) -> Path:
    scope = ctx.load_scope()
    doc = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8-sig"))
    survivors = [Finding.model_validate(f) for f in doc.get("findings", [])]
    if not survivors:
        _log("no surviving findings to corroborate")
        return ctx.validated_findings_path

    only = ctx.config.corroborate_only
    candidates = survivors if only is None else [f for f in survivors if f.id in only]

    # Budget-guarded launch set (parallel fan-out). Findings past the budget stay uncorroborated.
    launch: list[Finding] = []
    for f in candidates:
        try:
            ctx.assert_budget()
            launch.append(f)
        except BudgetExceeded as exc:
            _log(f"budget reached; {len(candidates) - len(launch)} finding(s) left uncorroborated ({exc})")
            break

    verdicts: dict[str, Corroboration] = {}
    if launch:
        bs = ctx.config.corroborate_batch_size
        batches = [launch[i:i + max(1, bs)] for i in range(0, len(launch), max(1, bs))]
        max_workers = max(1, min(ctx.config.max_parallel_audits, len(batches)))
        _log(f"corroborating {len(launch)} finding(s) in {len(batches) * 2} isolated sessions "
             f"(batch size {max(1, bs)})")
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            if bs <= 1:
                futs = {ex.submit(_corroborate_one, ctx, scope, b[0]): b for b in batches}
                for fut in as_completed(futs):
                    verdicts[futs[fut][0].id] = fut.result()
            else:
                futs = [ex.submit(_corroborate_batch, ctx, scope, b) for b in batches]
                for fut in as_completed(futs):
                    verdicts.update(fut.result())

    kept: list[Finding] = []
    fixed_upstream: list[dict] = []
    counts = {"corroborated": 0, "design_accepted": 0, "fixed_upstream": 0, "unknown": 0}
    infra_failure_unknown = 0
    overridden = 0
    for f in survivors:
        corr = verdicts.get(f.id)
        if corr is not None:
            corr = _reconcile_verdict_with_rationale(corr)
            if corr.verdict_overridden_from is not None:
                overridden += 1
                _log(f"{f.id}: verdict self-corrected "
                     f"{corr.verdict_overridden_from} -> design_accepted "
                     f"(rationale asserted vendor-confirmed intent)")
            f.corroboration = corr
            counts[corr.verdict] = counts.get(corr.verdict, 0) + 1
            if corr.verdict == "unknown" and _is_infra_failure(corr):
                infra_failure_unknown += 1
            if corr.verdict == "fixed_upstream":
                fixed_upstream.append(f.model_dump(exclude_none=True))
                _log(f"{f.id}: fixed_upstream ({corr.fix_commit or 'commit unspecified'}) -> appendix")
                continue
            _log(f"{f.id}: {corr.verdict}")
        kept.append(f)

    doc["findings"] = [f.model_dump(exclude_none=True) for f in kept]
    if fixed_upstream:
        doc["fixed_upstream"] = fixed_upstream
    stats = doc.setdefault("stats", {})
    stats["corroborated"] = counts
    stats["survivors"] = len(kept)
    stats["fixed_upstream"] = len(fixed_upstream)
    # Split "unknown" so a reader (or a paper-dataset script) can tell "the model looked and
    # couldn't tell" from "this was never actually examined" (session/backend failure) — collapsing
    # both into one opaque count is exactly what made a session-limit outage look, at a glance, like
    # a corroboration-quality problem in the gguf-tools run that first prompted this split.
    stats["unknown_due_to_infra_failure"] = infra_failure_unknown
    stats["unknown_genuine"] = counts["unknown"] - infra_failure_unknown
    stats["verdict_self_corrected"] = overridden
    atomic_write_json(ctx.validated_findings_path, doc)
    unknown_breakdown = (
        f"{counts['unknown']} unknown ({infra_failure_unknown} due to session/backend failure — "
        f"re-run `argo corroborate {ctx.run_id}` once the limit resets; "
        f"{counts['unknown'] - infra_failure_unknown} genuinely inconclusive)"
        if infra_failure_unknown else f"{counts['unknown']} unknown"
    )
    override_note = f" ({overridden} verdict-self-corrected)" if overridden else ""
    _log(f"{counts['corroborated']} corroborated, {counts['design_accepted']} design-accepted{override_note}, "
         f"{len(fixed_upstream)} fixed-upstream, {unknown_breakdown} "
         f"-> {len(kept)} active survivor(s)")
    return ctx.validated_findings_path
