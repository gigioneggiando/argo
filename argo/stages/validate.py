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
from ..rendering import design_context_block, fill_placeholders, with_artifact_contract
from ..runner import RunnerError

_KEEP_VERDICTS = {"confirmed", "needs_runtime_verification"}


def _log(msg: str) -> None:
    print(f"[validate] {msg}", file=sys.stderr)


# --------------------------------------------------------------------------- ground truth
def _load_ground_truth(ctx: RunContext) -> dict:
    """Recon's structured ground-truth pack (best-effort; empty dict if absent/malformed)."""
    try:
        return json.loads(ctx.ground_truth_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _format_ground_truth(gt: dict, focus: str | None) -> str:
    """The slice of ground truth relevant to one finding's focus: FP carve-outs (global + focus)
    and baseline-correct references — exactly what stops the validator over-refuting a real bug."""
    if not gt:
        return "(none captured by recon — judge from the code and scope only)"
    glob = gt.get("global", {}) if isinstance(gt.get("global"), dict) else {}
    foc = (gt.get("focuses", {}) or {}).get(focus or "", {}) if isinstance(gt.get("focuses"), dict) else {}
    carveouts = list(glob.get("fp_carveouts", []) or []) + list(foc.get("fp_carveouts", []) or [])
    baseline = list(foc.get("baseline_correct", []) or [])
    parts: list[str] = []
    if carveouts:
        parts.append("FALSE-POSITIVE CARVE-OUTS (a finding matching one of these IS a correct refute):\n"
                     + "\n".join(f"- {c}" for c in carveouts))
    if baseline:
        parts.append("BASELINE-CORRECT REFERENCES (deviation from these is evidence the bug is real):\n"
                     + "\n".join(f"- {b.get('pattern','?')}: known-correct `{b.get('reference_impl','?')}` "
                                 f"— {b.get('why_correct','')}" for b in baseline if isinstance(b, dict)))
    return "\n\n".join(parts) if parts else "(no focus-specific carve-outs; judge from code + scope)"


# --------------------------------------------------------------------------- merge/dedup
def _load_all(ctx: RunContext) -> list[Finding]:
    findings: list[Finding] = []
    # Each focus session numbers its findings independently (AUTHZ-001, AUTHZ-002, ...), so the same
    # id can collide across focuses. Disambiguate to a globally-unique id — otherwise downstream
    # id-keyed merges (e.g. the runtime stage attaching a verdict by id) mis-attach to the wrong one.
    seen: dict[str, int] = {}
    for path in sorted(ctx.findings_dir.glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        focus = doc.get("audit_focus", path.stem)
        for raw in doc.get("findings", []):
            f = Finding.model_validate(raw)
            f.source_focus = focus
            seen[f.id] = seen.get(f.id, 0) + 1
            if seen[f.id] > 1:
                f.id = f"{f.id}#{seen[f.id]}"
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
def _validate_one(ctx: RunContext, scope, scope_json_text: str, finding: Finding,
                  ground_truth: dict | None = None) -> Validation:
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
        "GROUND_TRUTH": _format_ground_truth(ground_truth, finding.source_focus),
    })
    assert_prohibited_present(rendered, scope.prohibited_techniques)  # guardrail

    # Impact discipline (no reflexive IMDS-style escalation) + accepted-by-design context: a finding
    # matching a stated accepted risk should be refuted-as-out-of-scope rather than confirmed.
    rendered = (rendered.rstrip() + "\n\n" + design_context_block(scope.accepted_risks) + "\n\n"
                "If this finding matches an accepted-by-design behavior listed above, return verdict "
                "`out_of_scope` with a rationale that names the accepted risk (it is intended, not a "
                "vulnerability).")

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


def _chunk(items: list, n: int) -> list[list]:
    n = max(1, n)
    return [items[i:i + n] for i in range(0, len(items), n)]


_VALID_VERDICTS = {"confirmed", "refuted", "needs_runtime_verification", "out_of_scope"}


def _validate_batch(ctx: RunContext, scope, scope_json_text: str, batch: list[Finding],
                    ground_truth: dict | None = None) -> dict[str, Validation]:
    """Adversarially validate a GROUP of findings in ONE session (each judged independently) —
    the efficiency path that collapses the per-finding fan-out. Returns {finding_id: Validation};
    any finding missing from the model's output or a failed session -> needs_runtime_verification
    (never silently dropped)."""
    items = []
    for f in batch:
        items.append({
            "finding_id": f.id,
            "finding": f.model_dump(exclude_none=True),
            "code_excerpts": _build_excerpts(
                ctx.repo_dir, f.affected,
                ctx.config.excerpt_context_lines, ctx.config.excerpt_max_bytes),
            "ground_truth": _format_ground_truth(ground_truth, f.source_focus),
        })
    template = (ctx.assets_dir / "02b_adversarial_validation_batch_prompt.md").read_text(encoding="utf-8")
    rendered = fill_placeholders(template, {
        "FINDINGS_BATCH": json.dumps(items, indent=2),
        "REPO_PATH": str(ctx.repo_dir.resolve()),
        "TARGET_TYPE": scope.target_type,
        "SCOPE_JSON": scope_json_text,
    })
    assert_prohibited_present(rendered, scope.prohibited_techniques)  # guardrail
    rendered = (rendered.rstrip() + "\n\n" + design_context_block(scope.accepted_risks) + "\n\n"
                "If a finding matches an accepted-by-design behavior listed above, return verdict "
                "`out_of_scope` for it with a rationale that names the accepted risk.")
    prompt = with_artifact_contract(rendered, artifacts=[{
        "type": "verdicts", "filename": "verdicts.json", "schema": None,
        "desc": "a JSON object {\"verdicts\": [...]} with ONE adversarial verdict per finding_id in the batch",
    }])
    ids = [f.id for f in batch]
    try:
        result = ctx.runner.run(
            prompt=prompt, run_dir=ctx.run_dir,
            work_dir=ctx.work_dir("validate", "batch-" + ids[0]),   # fresh, isolated context
            model=ctx.config.model_for("validate"), stage="validate",
            run_id=ctx.run_id, repo_dir=ctx.repo_dir,               # READ-ONLY
            allowed_tools=ARTIFACT_TOOLS, label="validate-batch-" + ids[0])
    except RunnerError as exc:
        _log(f"batch {ids[0]}+{len(ids) - 1}: validation session failed ({exc}); "
             f"flagging {len(ids)} finding(s) for human review")
        return {fid: Validation(verdict="needs_runtime_verification",
                                rationale=f"validation session failed: {exc}") for fid in ids}
    out: dict[str, Validation] = {}
    for fp in collect_output_files(result, "verdicts*.json"):
        try:
            doc = json.loads(fp.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        rows = doc.get("verdicts") if isinstance(doc, dict) else (doc if isinstance(doc, list) else [])
        for row in rows or []:
            fid = row.get("finding_id") if isinstance(row, dict) else None
            if fid not in ids or fid in out:
                continue
            if row.get("verdict") not in _VALID_VERDICTS:
                out[fid] = Validation(verdict="needs_runtime_verification",
                                      rationale=f"unrecognized verdict {row.get('verdict')!r}")
                continue
            try:
                out[fid] = Validation.model_validate(row)
            except Exception:  # noqa: BLE001 — a malformed row must never crash the stage
                out[fid] = Validation(verdict="needs_runtime_verification",
                                      rationale="verdict row failed schema validation")
    for fid in ids:  # any finding the model omitted: keep for a human, never auto-drop
        out.setdefault(fid, Validation(verdict="needs_runtime_verification",
                                       rationale="no verdict returned for this finding in the batch"))
    return out


# --------------------------------------------------------------------------- entry
def run(ctx: RunContext) -> Path:
    scope = ctx.load_scope()
    scope_json_text = ctx.scope_path.read_text(encoding="utf-8")

    ground_truth = _load_ground_truth(ctx)
    raw_findings = _load_all(ctx)
    _assign_keys(raw_findings)
    merged = _merge(raw_findings)
    _log(f"{len(raw_findings)} raw -> {len(merged)} after dedup")

    dropped: list[dict] = []
    to_validate: list[Finding] = []
    survivors: list[Finding] = []
    for f in merged:
        token = out_of_scope_match(f.affected, scope.out_of_scope)
        if token:
            f.validation = Validation(verdict="out_of_scope",
                                      rationale=f"affected asset matches out-of-scope '{token}'")
            dropped.append(_drop_record(f, "out_of_scope (code-side scope filter)"))
            _log(f"{f.id}: dropped pre-validation (out-of-scope '{token}')")
        elif f.source_focus == "dependencies":
            # SCA advisory findings: the adversarial validator is offline and cannot re-check a CVE,
            # so it would refute real ones for "unverifiable". Keep them on their own confidence.
            verdict = "confirmed" if f.confidence == "Confirmed" else "needs_runtime_verification"
            f.validation = Validation(
                verdict=verdict, validated_severity=f.severity, validated_confidence=f.confidence,
                rationale="software-composition finding; advisory not re-checkable offline — kept "
                          "on the SCA stage's own confidence for human confirmation")
            survivors.append(f)
            _log(f"{f.id}: kept ({verdict}) — SCA dependency finding")
        elif getattr(f, "schema_repair_failed", False):
            # A drift-repaired finding has placeholder fields; the adversarial validator would just
            # refute it for thin evidence. Keep it for a human (never auto-drop salvaged coverage).
            f.validation = Validation(
                verdict="needs_runtime_verification",
                rationale="schema-repaired audit finding (fields were backfilled); kept for human "
                          "review rather than adversarially validated against placeholder content")
            survivors.append(f)
            _log(f"{f.id}: kept unvalidated (schema-repaired finding, flagged for human review)")
        else:
            to_validate.append(f)

    # Adversarial validation (parallel, budget-guarded). Skips are logged.
    # NB: `survivors` already holds any schema-repaired findings kept above — do not reset it.
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

    verdicts: dict[str, Validation] = {}
    if launch:
        bs = ctx.config.validate_batch_size
        batches = _chunk(launch, bs)
        max_workers = max(1, min(ctx.config.max_parallel_audits, len(batches)))
        _log(f"validating {len(launch)} finding(s) in {len(batches)} session(s) "
             f"(batch size {max(1, bs)}, {max_workers} parallel)")
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            if bs <= 1:                       # legacy per-finding path (single-finding prompt)
                futs = {ex.submit(_validate_one, ctx, scope, scope_json_text, b[0], ground_truth): b
                        for b in batches}
                for fut in as_completed(futs):
                    verdicts[futs[fut][0].id] = fut.result()
            else:
                futs = [ex.submit(_validate_batch, ctx, scope, scope_json_text, b, ground_truth)
                        for b in batches]
                for fut in as_completed(futs):
                    verdicts.update(fut.result())

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
