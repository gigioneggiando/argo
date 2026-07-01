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
  * One of the only two networked stages (with ``research``): keeps the OSINT tools
    (``WebSearch``/``WebFetch``) but no shell, no sub-agents, no repo mount. The audited code is
    passed as excerpts in the prompt (network OR repo, never both in one session).
  * It must NEVER contact the program's live in-scope hosts (passed as a forbidden list, like research).
  * Best-effort: a failure here never fails the run — the finding is simply left ``unknown``.
"""

from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ..config import RESEARCH_TOOLS
from ..context import BudgetExceeded, RunContext, collect_output_files
from ..models import Corroboration, Finding
from ..rendering import design_context_block, fill_placeholders, with_artifact_contract
from ..runner import RunnerError
from .validate import _build_excerpts

_LIVE_ASSET_TYPES = {"web", "api", "mobile"}
_VALID_VERDICTS = {"corroborated", "design_accepted", "fixed_upstream", "unknown"}


def _log(msg: str) -> None:
    print(f"[corroborate] {msg}", file=sys.stderr)


def _repo_url(scope) -> str:
    for a in scope.source_repo_assets:
        return a.asset
    return "(unknown)"


def _repo_ref(ctx: RunContext, scope) -> str:
    """The exact revision the audit ran against (so the model corroborates against *newer* history)."""
    try:
        meta = json.loads(ctx.meta_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        meta = {}
    sha = meta.get("repo_commit")
    src = meta.get("repo_source") or _repo_url(scope)
    return f"{src} @ {sha}" if sha else str(src)


def _bullets(items: list[str], empty: str) -> str:
    items = [i.strip() for i in items if i and i.strip()]
    return "\n".join(f"  - {i}" for i in items) if items else f"  {empty}"


def _build_prompt(ctx: RunContext, scope, finding: Finding) -> str:
    template = (ctx.assets_dir / "08_corroborate_prompt.md").read_text(encoding="utf-8")
    excerpts = _build_excerpts(
        ctx.repo_dir, finding.affected,
        ctx.config.excerpt_context_lines, ctx.config.excerpt_max_bytes,
    )
    live = [a.asset.strip() for a in scope.in_scope
            if a.type in _LIVE_ASSET_TYPES and a.asset.strip()]
    rendered = fill_placeholders(template, {
        "MAX_SEARCHES": str(ctx.config.corroborate_max_searches),
        "REPO_REF": _repo_ref(ctx, scope),
        "FINDING_JSON": json.dumps(finding.model_dump(exclude_none=True), indent=2),
        "CODE_EXCERPTS": excerpts,
        "DOC_LINKS": _bullets(ctx.config.doc_links,
                              "(none provided — search the web for the official documentation)"),
        "REPO_URL": _repo_url(scope),
        "REFERENCE_LINKS": _bullets(scope.reference_links, "(none provided)"),
        "FORBIDDEN_HOSTS": _bullets(live, "(none listed in scope)"),
        "FINDING_ID": finding.id,
    })
    if scope.accepted_risks and scope.accepted_risks.strip():
        # If the maintainers' accepted-by-design list already covers this finding, that alone is
        # enough to return design_accepted (no doc search needed).
        rendered = rendered.rstrip() + "\n\n" + design_context_block(scope.accepted_risks)
    return with_artifact_contract(
        rendered,
        artifacts=[{
            "type": "corroboration", "filename": f"corroboration_{finding.id}.json", "schema": None,
            "desc": "the docs/history corroboration verdict for this single finding",
        }],
    )


def _corroborate_one(ctx: RunContext, scope, finding: Finding) -> Corroboration:
    try:
        result = ctx.runner.run(
            prompt=_build_prompt(ctx, scope, finding),
            run_dir=ctx.run_dir,
            work_dir=ctx.work_dir("corroborate", finding.id),   # fresh, isolated context
            model=ctx.config.model_for("corroborate"),
            stage="corroborate",
            run_id=ctx.run_id,
            repo_dir=None,                                       # networked session never mounts the repo
            allowed_tools=RESEARCH_TOOLS,                        # OSINT + Write (sanitized by the runner)
            label=finding.id,
        )
        files = collect_output_files(result, "corroboration_*.json")
    except RunnerError as exc:
        return Corroboration(verdict="unknown",
                             rationale=f"corroboration session failed: {exc}")
    if not files:
        return Corroboration(verdict="unknown",
                             rationale="corroboration session produced no verdict file")
    try:
        data = json.loads(files[0].read_text(encoding="utf-8"))
    except ValueError:
        return Corroboration(verdict="unknown", rationale="corroboration verdict was not valid JSON")
    if data.get("verdict") not in _VALID_VERDICTS:
        data["verdict"] = "unknown"
    data.pop("finding_id", None)            # not part of the Corroboration model
    return Corroboration.model_validate(data)


def run(ctx: RunContext) -> Path:
    scope = ctx.load_scope()
    doc = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))
    survivors = [Finding.model_validate(f) for f in doc.get("findings", [])]
    if not survivors:
        _log("no surviving findings to corroborate")
        return ctx.validated_findings_path

    # Budget-guarded launch set (parallel fan-out). Findings past the budget stay uncorroborated.
    launch: list[Finding] = []
    for f in survivors:
        try:
            ctx.assert_budget()
            launch.append(f)
        except BudgetExceeded as exc:
            _log(f"budget reached; {len(survivors) - len(launch)} finding(s) left uncorroborated ({exc})")
            break

    verdicts: dict[str, Corroboration] = {}
    if launch:
        max_workers = max(1, min(ctx.config.max_parallel_audits, len(launch)))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {ex.submit(_corroborate_one, ctx, scope, f): f for f in launch}
            for fut in as_completed(futs):
                verdicts[futs[fut].id] = fut.result()

    kept: list[Finding] = []
    fixed_upstream: list[dict] = []
    counts = {"corroborated": 0, "design_accepted": 0, "fixed_upstream": 0, "unknown": 0}
    for f in survivors:
        corr = verdicts.get(f.id)
        if corr is not None:
            f.corroboration = corr
            counts[corr.verdict] = counts.get(corr.verdict, 0) + 1
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
    ctx.validated_findings_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    _log(f"{counts['corroborated']} corroborated, {counts['design_accepted']} design-accepted, "
         f"{len(fixed_upstream)} fixed-upstream, {counts['unknown']} unknown "
         f"-> {len(kept)} active survivor(s)")
    return ctx.validated_findings_path
