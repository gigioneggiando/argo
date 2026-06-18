"""Stage 4 — Validate.

Merge every focus's findings, compute ``dedup_key`` and collapse duplicates (keep highest
severity, union variants/affected), apply a code-side scope filter, then run the adversarial
validation prompt in a FRESH context per surviving finding. Attach the ``validation`` block and
drop ``out_of_scope`` / ``refuted``; keep ``confirmed`` and ``needs_runtime_verification``.
"""

from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ..config import ARTIFACT_TOOLS
from ..context import BudgetExceeded, RunContext, collect_output_files
from ..guardrails import assert_prohibited_present, out_of_scope_match
from ..models import Finding, Validation
from ..ranking import confidence_rank, dedup_key, severity_rank, split_ref
from ..rendering import fill_placeholders, with_artifact_contract
from ..runner import RunnerError

_KEEP_VERDICTS = {"confirmed", "needs_runtime_verification"}


def _log(msg: str) -> None:
    print(f"[validate] {msg}", file=sys.stderr)


# --------------------------------------------------------------------------- merge/dedup
def _load_all(ctx: RunContext) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(ctx.findings_dir.glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        focus = doc.get("audit_focus", path.stem)
        for raw in doc.get("findings", []):
            f = Finding.model_validate(raw)
            f.source_focus = focus
            findings.append(f)
    return findings


def _assign_keys(findings: list[Finding]) -> None:
    for f in findings:
        file, line = split_ref(f.affected[0]) if f.affected else ("", "")
        f.dedup_key = dedup_key(file, line, f.cwe)


def _merge(findings: list[Finding]) -> list[Finding]:
    """Group by dedup_key; keep highest severity (then highest confidence, then first seen);
    union affected + variants from the rest."""
    groups: dict[str, list[tuple[int, Finding]]] = {}
    for idx, f in enumerate(findings):
        groups.setdefault(f.dedup_key, []).append((idx, f))

    merged: list[Finding] = []
    for key, items in groups.items():
        items.sort(key=lambda it: (-severity_rank(it[1].severity),
                                   -confidence_rank(it[1].confidence), it[0]))
        keeper = items[0][1].model_copy(deep=True)
        affected = list(keeper.affected)
        variants = [keeper.variants] if keeper.variants else []
        for _idx, other in items[1:]:
            for a in other.affected:
                if a not in affected:
                    affected.append(a)
            if other.variants and other.variants not in variants:
                variants.append(other.variants)
        keeper.affected = affected
        if variants:
            keeper.variants = "\n".join(variants)
        merged.append(keeper)
    # Deterministic ordering for downstream sessions / output.
    merged.sort(key=lambda f: (-severity_rank(f.severity), -confidence_rank(f.confidence), f.id))
    return merged


# --------------------------------------------------------------------------- excerpts
def _build_excerpts(repo_dir: Path, affected: list[str], ctx_lines: int, max_bytes: int) -> str:
    chunks: list[str] = []
    total = 0
    for ref in affected:
        file, line = split_ref(ref)
        path = repo_dir / file
        if not path.is_file():
            chunks.append(f"--- {ref} (source not found in repo copy) ---")
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line:
            ln = int(line)
            start, end = max(1, ln - ctx_lines), min(len(lines), ln + ctx_lines)
        else:
            start, end = 1, min(len(lines), 2 * ctx_lines + 1)
        body = "\n".join(f"{i:6d}  {lines[i - 1]}" for i in range(start, end + 1))
        block = f"--- {file}:{line or ''} (lines {start}-{end}) ---\n{body}"
        if total + len(block) > max_bytes:
            chunks.append("... (excerpt budget exceeded; remaining refs omitted) ...")
            break
        total += len(block)
        chunks.append(block)
    return "\n\n".join(chunks) if chunks else "(no source excerpts available)"


# --------------------------------------------------------------------------- per-finding
def _validate_one(ctx: RunContext, scope, scope_json_text: str, finding: Finding) -> Validation:
    excerpts = _build_excerpts(
        ctx.repo_dir, finding.affected,
        ctx.config.excerpt_context_lines, ctx.config.excerpt_max_bytes,
    )
    template = (ctx.assets_dir / "02_adversarial_validation_prompt.md").read_text(encoding="utf-8")
    rendered = fill_placeholders(template, {
        "FINDING_JSON": json.dumps(finding.model_dump(exclude_none=True), indent=2),
        "CODE_EXCERPTS": excerpts,
        "REPO_PATH": str(ctx.repo_dir.resolve()),
        "TARGET_TYPE": scope.target_type,
        "SCOPE_JSON": scope_json_text,
    })
    assert_prohibited_present(rendered, scope.prohibited_techniques)  # guardrail

    prompt = with_artifact_contract(
        rendered,
        artifacts=[{
            "type": "verdict", "filename": f"verdict_{finding.id}.json", "schema": None,
            "desc": "the adversarial validation verdict for this single finding",
        }],
    )
    try:
        result = ctx.runner.run(
            prompt=prompt,
            run_dir=ctx.run_dir,
            work_dir=ctx.work_dir("validate", finding.id),   # fresh, isolated context
            model=ctx.config.model_for("validate"),
            stage="validate",
            run_id=ctx.run_id,
            repo_dir=ctx.repo_dir,                            # READ-ONLY
            allowed_tools=ARTIFACT_TOOLS,
            label=finding.id,
        )
    except RunnerError as exc:
        # Validation session failed hard: never auto-confirm and never silently drop a
        # candidate. Keep it, flagged for human runtime review.
        _log(f"{finding.id}: validation session failed ({exc}); flagging for human review")
        return Validation(verdict="needs_runtime_verification",
                          rationale=f"validation session failed: {exc}")
    files = collect_output_files(result, "verdict_*.json")
    if not files:
        # No verdict produced: do not auto-confirm. Flag for human runtime review.
        return Validation(verdict="needs_runtime_verification",
                          rationale="validation session produced no verdict file")
    data = json.loads(files[0].read_text(encoding="utf-8"))
    if data.get("verdict") not in {"confirmed", "refuted", "needs_runtime_verification",
                                   "out_of_scope"}:
        return Validation(verdict="needs_runtime_verification",
                          rationale=f"unrecognized verdict {data.get('verdict')!r}")
    return Validation.model_validate(data)


# --------------------------------------------------------------------------- entry
def run(ctx: RunContext) -> Path:
    scope = ctx.load_scope()
    scope_json_text = ctx.scope_path.read_text(encoding="utf-8")

    raw_findings = _load_all(ctx)
    _assign_keys(raw_findings)
    merged = _merge(raw_findings)
    _log(f"{len(raw_findings)} raw -> {len(merged)} after dedup")

    dropped: list[dict] = []
    to_validate: list[Finding] = []
    for f in merged:
        token = out_of_scope_match(f.affected, scope.out_of_scope)
        if token:
            f.validation = Validation(verdict="out_of_scope",
                                      rationale=f"affected asset matches out-of-scope '{token}'")
            dropped.append(_drop_record(f, "out_of_scope (code-side scope filter)"))
            _log(f"{f.id}: dropped pre-validation (out-of-scope '{token}')")
        else:
            to_validate.append(f)

    # Adversarial validation (parallel, budget-guarded). Skips are logged.
    survivors: list[Finding] = []
    launch: list[Finding] = []
    for f in to_validate:
        try:
            ctx.assert_budget()
            launch.append(f)
        except BudgetExceeded as exc:
            for skipped in to_validate[len(launch):]:
                skipped.validation = Validation(
                    verdict="needs_runtime_verification",
                    rationale="not adversarially validated: per-run budget reached")
                survivors.append(skipped)  # keep, flagged for human review (never auto-drop)
            _log(f"budget reached; {len(to_validate) - len(launch)} finding(s) left unvalidated ({exc})")
            break

    max_workers = max(1, min(ctx.config.max_parallel_audits, len(launch) or 1))
    verdicts: dict[str, Validation] = {}
    if launch:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {ex.submit(_validate_one, ctx, scope, scope_json_text, f): f for f in launch}
            for fut in as_completed(futs):
                f = futs[fut]
                verdicts[f.id] = fut.result()

    for f in launch:
        f.validation = verdicts[f.id]
        verdict = f.validation.verdict
        if verdict in _KEEP_VERDICTS:
            survivors.append(f)
            _log(f"{f.id}: {verdict}")
        else:
            dropped.append(_drop_record(f, verdict))
            _log(f"{f.id}: dropped ({verdict})")

    survivors.sort(key=lambda f: (
        -severity_rank(_eff_sev(f)), -confidence_rank(_eff_conf(f)), f.id))

    out_doc = {
        "program_name": scope.program_name,
        "run_id": ctx.run_id,
        "generated_at": ctx.timestamp(),
        "stats": {
            "raw": len(raw_findings),
            "after_dedup": len(merged),
            "validated": len(launch),
            "survivors": len(survivors),
            "dropped": len(dropped),
        },
        "findings": [f.model_dump(exclude_none=True) for f in survivors],
        "dropped": dropped,
    }
    ctx.validated_findings_path.write_text(json.dumps(out_doc, indent=2), encoding="utf-8")
    _log(f"{len(survivors)} survivor(s), {len(dropped)} dropped -> {ctx.validated_findings_path.name}")
    return ctx.validated_findings_path


def _drop_record(f: Finding, reason: str) -> dict:
    return {
        "id": f.id, "dedup_key": f.dedup_key, "title": f.title,
        "cwe": f.cwe, "severity": f.severity, "reason": reason,
        "verdict": f.validation.verdict if f.validation else None,
    }


def _eff_sev(f: Finding) -> str:
    if f.validation and f.validation.validated_severity:
        return f.validation.validated_severity
    return f.severity


def _eff_conf(f: Finding) -> str:
    if f.validation and f.validation.validated_confidence:
        return f.validation.validated_confidence
    return f.confidence
