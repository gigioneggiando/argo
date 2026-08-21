"""Stage 7 — Deep verify (opt-in; offline; runs AFTER corroborate, BEFORE runtime/live).

The final, deepest check on a surviving finding: independently RE-DERIVE it from the actual
source (full Read/Grep/Glob access, no excerpt budget, no batching — one full agentic session per
finding) and reason ACROSS the whole survivor set. Validate is adversarial but deliberately judges
each finding in ISOLATION (batched, excerpt-budgeted); corroborate cross-checks against external
docs/history but never opens the repo. Neither can notice that one finding is actually several
distinct bugs bundled together, that two findings share one root cause, or that a finding's
mechanism is real but a factual detail in it is wrong. This stage exists to catch exactly those
three things, to the standard of a human re-reading every cited line before a disclosure ships.

Inputs: ``validated_findings.json`` (validate's survivors, already annotated by corroborate if
that stage ran). Output: the same file, rewritten with a ``verification`` block attached to each
surviving finding, plus two new appendix lists (kept, never silently deleted):
  * ``split_originals`` — findings replaced by >=2 independently-verified sub-findings;
  * ``merged_findings`` — findings folded into another surviving finding by root cause.
Refuted findings move to the existing ``dropped`` list (same convention as validate/the code-side
scope filter).

Guardrails (defense in depth):
  * Offline, like validate: full repo mount (READ-ONLY) via ``ARTIFACT_TOOLS``, no network tools.
  * Best-effort per finding: a session failure never fails the run — the finding is kept
    (``inconclusive``, infra-failure rationale), never silently dropped.
"""

from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ..config import ARTIFACT_TOOLS
from ..context import BudgetExceeded, RunContext, atomic_write_json, collect_output_files
from ..guardrails import assert_prohibited_present
from ..models import Finding, Verification
from ..ranking import dedup_key, split_ref
from ..rendering import design_context_block, render_prompt_pair, with_artifact_contract
from ..runner import RunnerError
from .validate import _build_excerpts

_VALID_VERDICTS = {"reconfirmed", "corrected", "split", "merged", "refuted", "inconclusive"}

#: Mirrors validate.py / corroborate.py's infra-vs-genuine split: an "inconclusive" caused by a
#: session/backend failure or missing output is a tooling gap, not a real quality signal. These
#: exact rationale prefixes mark that case so the run summary can report the split honestly.
_INFRA_FAILURE_RATIONALE_PREFIXES = (
    "deep-verify session failed:",
    "deep-verify session produced no verdict file",
    "deep-verify verdict was not valid JSON",
    "not deep-verified: per-run budget reached",
    "not deep-verified: verify_max_findings cap reached",
)


def _is_infra_failure(v: Verification) -> bool:
    return (v.verdict == "inconclusive" and bool(v.rationale)
            and v.rationale.startswith(_INFRA_FAILURE_RATIONALE_PREFIXES))


def _log(msg: str) -> None:
    print(f"[verify] {msg}", file=sys.stderr)


def _summarize(f: Finding) -> dict:
    return {"id": f.id, "title": f.title, "cwe": f.cwe, "affected": f.affected,
            "summary": (f.why_vulnerable or "")[:200]}


def _prior_verdicts(f: Finding) -> dict:
    out: dict = {}
    if f.validation:
        out["validation"] = f.validation.model_dump(exclude_none=True)
    if f.corroboration:
        out["corroboration"] = f.corroboration.model_dump(exclude_none=True)
    return out


def _build_prompt(ctx: RunContext, scope, scope_json_text: str, finding: Finding,
                  siblings: list[Finding]) -> tuple[str, str | None]:
    excerpts = _build_excerpts(
        ctx.repo_dir, finding.affected,
        ctx.config.excerpt_context_lines, ctx.config.excerpt_max_bytes,
    )
    mapping = {
        "FINDING_JSON": json.dumps(finding.model_dump(exclude_none=True), indent=2),
        "PRIOR_VERDICTS_JSON": json.dumps(_prior_verdicts(finding), indent=2),
        "CODE_EXCERPTS": excerpts,
        "REPO_PATH": str(ctx.repo_dir.resolve()),
        "TARGET_TYPE": scope.target_type,
        "SCOPE_JSON": scope_json_text,
        "SIBLING_FINDINGS_JSON": json.dumps([_summarize(s) for s in siblings if s.id != finding.id],
                                            indent=2),
    }
    rendered, neutral_rendered = render_prompt_pair(ctx.assets_dir, "09_deep_verify_prompt.md", mapping)
    assert_prohibited_present(rendered, scope.prohibited_techniques)  # guardrail

    def _finish(text: str) -> str:
        text = (text.rstrip() + "\n\n" + design_context_block(scope.accepted_risks) + "\n\n"
                "If this finding matches an accepted-by-design behavior listed above, return verdict "
                "`refuted` with a rationale that names the accepted risk.")
        return with_artifact_contract(text, artifacts=[{
            "type": "deep_verify_verdict", "filename": f"deep_verify_{finding.id}.json", "schema": None,
            "desc": "the deep-verify verdict for this single finding",
        }])

    prompt = _finish(rendered)
    neutral_prompt = _finish(neutral_rendered) if neutral_rendered is not None else None
    if neutral_prompt is not None:
        assert_prohibited_present(neutral_prompt, scope.prohibited_techniques)
    return prompt, neutral_prompt


#: Fields the model sometimes echoes back as a placeholder-shaped STRING (copying the field's own
#: description from the prompt's JSON template) instead of leaving them null/omitted on a verdict
#: where they don't apply (e.g. `split_into` on a `reconfirmed` verdict). Seen for real on authentik:
#: a well-evidenced `reconfirmed` verdict was discarded to `inconclusive` over this alone. Dropped
#: rather than failing the whole verdict — the real, well-derived verdict/rationale must not be lost
#: over an irrelevant field's type.
_LIST_FIELDS = ("split_into", "related_finding_ids")


def _coerce(data: dict) -> Verification:
    if data.get("verdict") not in _VALID_VERDICTS:
        return Verification(verdict="inconclusive",
                            rationale=f"unrecognized verdict {data.get('verdict')!r}",
                            independent_derivation=data.get("independent_derivation") or "")
    data = dict(data)
    data.pop("finding_id", None)
    for key in _LIST_FIELDS:
        if key in data and not isinstance(data[key], list):
            data.pop(key)
    try:
        return Verification.model_validate(data)
    except Exception:  # noqa: BLE001 — a malformed verdict must never crash a best-effort stage
        return Verification(verdict="inconclusive", rationale="verdict failed schema validation")


def _verify_one(ctx: RunContext, scope, scope_json_text: str, finding: Finding,
                siblings: list[Finding]) -> Verification:
    """One finding, up to ``verify_max_attempts`` tries. Each attempt this expensive (one full
    Codex/Claude session, no excerpt budget - real sessions on real targets have run 1-3M+ input
    tokens) is worth retrying once on a transient infra failure before giving up, unlike validate/
    corroborate's cheaper per-session cost where a bare retry isn't worth the code. A recoverable
    CLI/sandbox crash (seen for real: Codex's Windows sandbox dying mid-session under heavy tool
    use) shouldn't cost a $1-4 session's verdict outright."""
    max_attempts = max(1, ctx.config.verify_max_attempts)
    last_rationale = "deep-verify session produced no verdict file"
    for attempt in range(max_attempts):
        retrying = attempt + 1 < max_attempts
        work_label = finding.id if attempt == 0 else f"{finding.id}-retry{attempt}"
        prompt, neutral_prompt = _build_prompt(ctx, scope, scope_json_text, finding, siblings)
        try:
            result = ctx.runner.run(
                prompt=prompt,
                neutral_prompt=neutral_prompt,
                run_dir=ctx.run_dir,
                work_dir=ctx.work_dir("verify", work_label),   # fresh, isolated context per attempt
                model=ctx.config.model_for("verify"),
                stage="verify",
                run_id=ctx.run_id,
                repo_dir=ctx.repo_dir,                       # READ-ONLY, full tree, no excerpt budget
                allowed_tools=ARTIFACT_TOOLS,
                label=finding.id,
            )
            files = collect_output_files(result, "deep_verify_*.json")
        except RunnerError as exc:
            last_rationale = f"deep-verify session failed: {exc}"
            _log(f"{finding.id}: attempt {attempt + 1}/{max_attempts} failed ({exc})"
                + (" — retrying" if retrying else "; keeping as-is"))
            continue
        if not files:
            last_rationale = "deep-verify session produced no verdict file"
            _log(f"{finding.id}: attempt {attempt + 1}/{max_attempts} produced no verdict file"
                + (" — retrying" if retrying else "; keeping as-is"))
            continue
        try:
            data = json.loads(files[0].read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            last_rationale = "deep-verify verdict was not valid JSON"
            _log(f"{finding.id}: attempt {attempt + 1}/{max_attempts} malformed JSON"
                + (" — retrying" if retrying else "; keeping as-is"))
            continue
        return _coerce(data)
    return Verification(verdict="inconclusive", rationale=last_rationale)


def _split_child(parent: Finding, idx: int, raw: dict) -> Finding:
    """Build one independent Finding from a ``split_into`` entry, id-derived from the parent so
    provenance is obvious (``NMQ-0013`` -> ``NMQ-0013-split-1``, ``-split-2``, ...)."""
    child = {**parent.model_dump(exclude_none=True), **raw}
    child["id"] = f"{parent.id}-split-{idx}"
    child.pop("validation", None)
    child.pop("corroboration", None)
    child.pop("verification", None)
    child.pop("grounding", None)
    f = Finding.model_validate(child)
    file, line = split_ref(f.affected[0]) if f.affected else ("", "")
    f.dedup_key = dedup_key(file, line, f.cwe)
    f.validation = parent.validation
    f.corroboration = parent.corroboration
    f.verification = Verification(
        verdict="reconfirmed",
        rationale=f"split out of {parent.id} at deep-verify; independently re-derived as its own bug",
        independent_derivation=raw.get("independent_derivation", "") or
                               (parent.verification.independent_derivation if parent.verification else ""),
    )
    return f


def run(ctx: RunContext) -> Path:
    scope = ctx.load_scope()
    scope_json_text = ctx.scope_path.read_text(encoding="utf-8")
    doc = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8-sig"))
    survivors = [Finding.model_validate(f) for f in doc.get("findings", [])]
    if not survivors:
        _log("no surviving findings to deep-verify")
        return ctx.validated_findings_path

    only = ctx.config.verify_only
    if only is not None:
        # Explicit scope: exactly these ids get a session; everyone else is untouched, whatever
        # their current state (verified, unverified, or infra-failure) — the caller has decided.
        candidates = [f for f in survivors if f.id in only]
        untouched = [f for f in survivors if f.id not in only]
    else:
        # Default resumable behavior: a finding that already carries a real verdict (anything but
        # an infra-failure inconclusive) from a prior invocation of this stage is done — re-running
        # `argo verify` on the same run after a partial failure (credits ran out, a rate limit, a
        # crash) should only re-spend on what didn't get a real answer last time, not everything.
        candidates = [f for f in survivors
                      if f.verification is None or _is_infra_failure(f.verification)]
        untouched = [f for f in survivors
                     if f.verification is not None and not _is_infra_failure(f.verification)]
        if untouched:
            _log(f"{len(untouched)} finding(s) already have a real deep-verify verdict, skipping "
                 f"(use --only to force a specific finding to re-verify)")

    cap = ctx.config.verify_max_findings
    eligible = candidates if cap is None else candidates[:cap]
    beyond_cap_ids = {f.id for f in candidates[len(eligible):]}

    launch: list[Finding] = []
    for f in eligible:
        try:
            ctx.assert_budget()
            launch.append(f)
        except BudgetExceeded as exc:
            _log(f"budget reached; {len(eligible) - len(launch)} finding(s) left un-deep-verified ({exc})")
            break
    launched_ids = {f.id for f in launch}
    skipped = [f for f in candidates if f.id not in launched_ids]

    verdicts: dict[str, Verification] = {}
    if launch:
        max_workers = max(1, min(ctx.config.max_parallel_audits, len(launch)))
        _log(f"deep-verifying {len(launch)} finding(s) in {len(launch)} session(s) "
             f"(one per finding, {max_workers} parallel)")
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {ex.submit(_verify_one, ctx, scope, scope_json_text, f, survivors): f for f in launch}
            for fut in as_completed(futs):
                verdicts[futs[fut].id] = fut.result()
    for f in skipped:
        reason = ("not deep-verified: verify_max_findings cap reached" if f.id in beyond_cap_ids
                  else "not deep-verified: per-run budget reached")
        verdicts[f.id] = Verification(verdict="inconclusive", rationale=reason)

    kept: list[Finding] = list(untouched)
    split_originals: list[dict] = []
    merged_findings: list[dict] = []
    newly_dropped: list[dict] = []
    counts = {k: 0 for k in _VALID_VERDICTS}
    infra_failure = 0
    split_children_total = 0

    for f in candidates:
        v = verdicts.get(f.id)
        if v is None:   # never launched and not in skipped (shouldn't happen, but never silently drop)
            kept.append(f)
            continue
        f.verification = v
        counts[v.verdict] = counts.get(v.verdict, 0) + 1
        if v.verdict == "inconclusive" and _is_infra_failure(v):
            infra_failure += 1

        if v.verdict == "refuted":
            newly_dropped.append({"id": f.id, "dedup_key": f.dedup_key, "title": f.title,
                                  "cwe": f.cwe, "severity": f.severity,
                                  "reason": f"refuted at deep-verify: {v.rationale or ''}".rstrip(),
                                  "verdict": "refuted"})
            _log(f"{f.id}: refuted at deep-verify")
            continue
        if v.verdict == "merged":
            merged_findings.append(f.model_dump(exclude_none=True))
            _log(f"{f.id}: merged into {v.merged_into or '?'}")
            continue
        if v.verdict == "split" and v.split_into:
            children = [_split_child(f, i + 1, raw) for i, raw in enumerate(v.split_into)]
            split_originals.append(f.model_dump(exclude_none=True))
            kept.extend(children)
            split_children_total += len(children)
            _log(f"{f.id}: split into {len(children)} independent finding(s) "
                f"({', '.join(c.id for c in children)})")
            continue
        kept.append(f)
        if v.verdict == "corrected":
            _log(f"{f.id}: corrected — {v.corrections or v.rationale or ''}".rstrip())
        elif v.verdict != "reconfirmed":
            _log(f"{f.id}: {v.verdict}")

    doc["findings"] = [f.model_dump(exclude_none=True) for f in kept]
    doc["dropped"] = list(doc.get("dropped", [])) + newly_dropped
    if split_originals:
        doc["split_originals"] = split_originals
    if merged_findings:
        doc["merged_findings"] = merged_findings
    stats = doc.setdefault("stats", {})
    stats["deep_verified"] = counts
    stats["survivors"] = len(kept)
    stats["deep_verify_inconclusive_due_to_infra_failure"] = infra_failure
    stats["deep_verify_inconclusive_genuine"] = counts.get("inconclusive", 0) - infra_failure
    atomic_write_json(ctx.validated_findings_path, doc)

    _log(f"{counts.get('reconfirmed', 0)} reconfirmed, {counts.get('corrected', 0)} corrected, "
        f"{len(split_originals)} split ({split_children_total} new finding(s)), "
        f"{len(merged_findings)} merged, {len(newly_dropped)} refuted, "
        f"{counts.get('inconclusive', 0)} inconclusive ({infra_failure} infra-failure) "
        f"-> {len(kept)} active survivor(s)")
    return ctx.validated_findings_path
