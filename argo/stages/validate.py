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
from ..context import BudgetExceeded, RunContext, atomic_write_json, collect_output_files
from ..grounding import build_index, ground_finding
from ..guardrails import assert_prohibited_present, out_of_scope_match
from ..models import Finding, Grounding, Validation
from ..ranking import confidence_rank, dedup_key, severity_rank, split_ref
from ..rendering import design_context_block, fill_placeholders, render_prompt_pair, with_artifact_contract
from ..runner import RunnerError

_KEEP_VERDICTS = {"confirmed", "needs_runtime_verification"}

#: A survivor kept as "needs_runtime_verification" can mean the model made a genuine judgment call
#: (a real, useful signal) or that it was never actually adversarially examined — a session/backend
#: failure, a missing verdict, or the per-run budget being reached. These exact rationale prefixes
#: mark the latter, letting the final summary report the split instead of one opaque survivor count.
_INFRA_UNVALIDATED_RATIONALE_PREFIXES = (
    "validation session failed:",
    "validation session produced no verdict file",
    "no verdict returned for this finding in the batch",
    "not adversarially validated: per-run budget reached",
    "unrecognized verdict ",
)


def _is_infra_unvalidated(f: Finding) -> bool:
    v = f.validation
    return bool(v and v.verdict == "needs_runtime_verification" and v.rationale
                and v.rationale.startswith(_INFRA_UNVALIDATED_RATIONALE_PREFIXES))


def _log(msg: str) -> None:
    print(f"[validate] {msg}", file=sys.stderr)


# --------------------------------------------------------------------------- ground truth
def _load_ground_truth(ctx: RunContext) -> dict:
    """Recon's structured ground-truth pack (best-effort; empty dict if absent/malformed)."""
    try:
        return json.loads(ctx.ground_truth_path.read_text(encoding="utf-8-sig"))
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
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
        focus = doc.get("audit_focus", path.stem)
        pass_id = doc.get("source_pass")  # None = the primary pass; else "second-opinion-N"
        for raw in doc.get("findings", []):
            f = Finding.model_validate(raw)
            f.source_focus = focus
            f.source_pass = pass_id
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
        passes = {keeper.source_pass or "primary"}
        for _idx, other in items[1:]:
            for a in other.affected:
                if a not in affected:
                    affected.append(a)
            if other.variants and other.variants not in variants:
                variants.append(other.variants)
            passes.add(other.source_pass or "primary")
        keeper.affected = affected
        if variants:
            keeper.variants = "\n".join(variants)
        # A dedup_key collision across >1 distinct blind passes means an independent audit pass
        # rediscovered the exact same file:line:cwe — the strongest possible corroboration signal.
        if len(passes) > 1:
            keeper.corroborating_passes = sorted(passes)
        merged.append(keeper)
    # Deterministic ordering for downstream sessions / output.
    merged.sort(key=lambda f: (-severity_rank(f.severity), -confidence_rank(f.confidence), f.id))
    return merged


# --------------------------------------------------------------------------- semantic dedup
def _summarize_for_dedup(f: Finding) -> dict:
    return {"finding_id": f.id, "title": f.title, "cwe": f.cwe, "affected": f.affected,
            "summary": (f.why_vulnerable or "")[:200]}


def _semantic_dedup(ctx: RunContext, findings: list[Finding]) -> tuple[list[Finding], list[dict]]:
    """Cluster near-duplicate findings (same root cause, different call site / audit focus) that
    the structural ``dedup_key`` merge above cannot see — it only collapses EXACT (file, line, CWE)
    matches, so the same bug reported by two foci at two different lines survives as two findings.
    One extra cheap batched session (summaries only, no source excerpts) before the much more
    expensive per-finding validate/corroborate fan-out. Fails open on any error: returns ``findings``
    unchanged. Returns ``(deduped_findings, drop_records)``."""
    if not ctx.config.semantic_dedup_enabled or len(findings) < ctx.config.semantic_dedup_min_findings:
        return findings, []

    by_id = {f.id: f for f in findings}
    template = (ctx.assets_dir / "02c_semantic_dedup_prompt.md").read_text(encoding="utf-8")
    rendered = fill_placeholders(template, {
        "FINDINGS_SUMMARY": json.dumps([_summarize_for_dedup(f) for f in findings], indent=2),
    })
    prompt = with_artifact_contract(rendered, artifacts=[{
        "type": "dedup_clusters", "filename": "dedup_clusters.json", "schema": None,
        "desc": "clusters of finding_ids that describe the same underlying bug",
    }])
    try:
        result = ctx.runner.run(
            prompt=prompt, run_dir=ctx.run_dir,
            work_dir=ctx.work_dir("validate", "semantic-dedup"),
            model=ctx.config.model_for("validate"), stage="validate",
            run_id=ctx.run_id, repo_dir=None,            # summaries only; no repo access needed
            allowed_tools=ARTIFACT_TOOLS, label="validate-semantic-dedup")
        files = collect_output_files(result, "dedup_clusters*.json")
    except RunnerError as exc:
        _log(f"semantic dedup skipped (session failed: {exc}); keeping all {len(findings)} finding(s) separate")
        return findings, []
    if not files:
        _log("semantic dedup skipped (no output produced); keeping all findings separate")
        return findings, []
    try:
        clusters = json.loads(files[0].read_text(encoding="utf-8-sig")).get("clusters") or []
    except (OSError, ValueError):
        _log("semantic dedup skipped (malformed output); keeping all findings separate")
        return findings, []

    drop_of: dict[str, str] = {}         # duplicate_id -> primary_id
    affected_files = {
        f.id: {split_ref(ref)[0].replace("\\", "/").lower() for ref in f.affected}
        for f in findings
    }
    for cluster in clusters:
        if not isinstance(cluster, dict):
            continue
        primary_id = cluster.get("primary_id")
        if primary_id not in by_id or primary_id in drop_of:
            continue                     # unknown, or already merged into someone else: skip cluster
        for d in cluster.get("duplicate_ids") or []:
            if (d in by_id and d != primary_id and d not in drop_of
                    and (by_id[d].cwe.lower() == by_id[primary_id].cwe.lower()
                         or affected_files[d] & affected_files[primary_id])
                    and severity_rank(by_id[primary_id].severity)
                    >= severity_rank(by_id[d].severity)):
                drop_of[d] = primary_id

    if not drop_of:
        return findings, []

    dropped: list[dict] = []
    kept: list[Finding] = []
    for f in findings:
        primary_id = drop_of.get(f.id)
        if primary_id is None:
            kept.append(f)
            continue
        primary = by_id[primary_id]
        for a in f.affected:
            if a not in primary.affected:
                primary.affected.append(a)
        # Same corroboration signal as _merge(), for near-duplicates the LLM clustered rather than
        # an exact dedup_key match: if the collapsed finding came from a DIFFERENT blind pass, that's
        # an independent rediscovery, not just a different audit focus in the same pass.
        this_pass = f.source_pass or "primary"
        primary_pass = primary.source_pass or "primary"
        if this_pass != primary_pass:
            passes = set(primary.corroborating_passes) | {primary_pass, this_pass}
            primary.corroborating_passes = sorted(passes)
        dropped.append({"id": f.id, "dedup_key": f.dedup_key, "title": f.title, "cwe": f.cwe,
                        "severity": f.severity,
                        "reason": f"duplicate_of:{primary_id} (semantic dedup)", "verdict": None})
    _log(f"{len(findings)} finding(s) -> {len(kept)} after semantic dedup "
         f"({len(dropped)} near-duplicate(s) collapsed)")
    return kept, dropped


# --------------------------------------------------------------------------- citation grounding
_CONF_ORDER = ["Low", "Medium", "High", "Confirmed"]


def _downgrade_confidence(c: str) -> str:
    try:
        i = _CONF_ORDER.index(c)
    except ValueError:
        return c
    return _CONF_ORDER[max(0, i - 1)]


def _ground_citations(ctx: RunContext, findings: list[Finding]) -> tuple[list[Finding], list[dict]]:
    """Deterministic citation grounding (no LLM call). DROP a finding whose PRIMARY ``affected``
    file exists nowhere in the repo (a hallucinated location — e.g. a bug carried over from a
    different target); for a finding citing project-specific code SYMBOLS that appear nowhere in
    the repo, attach a grounding note and downgrade confidence one notch (the adversarial validator
    makes the final call, with the note surfaced in its excerpts). Fails open: on any error every
    finding passes through unchanged. Returns ``(kept, drop_records)``."""
    if not findings:
        return findings, []
    try:
        index = build_index(ctx.repo_dir, findings)
    except Exception as exc:  # noqa: BLE001 — grounding must never crash the stage
        _log(f"citation grounding skipped ({exc}); keeping all findings")
        return findings, []

    kept: list[Finding] = []
    dropped: list[dict] = []
    n_downgraded = 0
    for f in findings:
        try:
            res = ground_finding(index, f)
        except Exception:  # noqa: BLE001 — never let one malformed finding crash the stage
            f.grounding = Grounding(status="grounded")
            kept.append(f)
            continue
        missing_files, missing_symbols = res["missing_files"], res["missing_symbols"]
        out_of_range_lines = res["out_of_range_lines"]
        grounding_kwargs = dict(missing_files=missing_files, missing_symbols=missing_symbols,
                                out_of_range_lines=out_of_range_lines,
                                composite_suspect=res["composite_suspect"],
                                composite_reason=res["composite_reason"])
        if res["composite_suspect"]:
            _log(f"{f.id}: possible composite finding ({res['composite_reason']}); informational only")
        primary = f.affected[0] if f.affected else ""
        if primary and primary in missing_files:
            f.grounding = Grounding(status="ungrounded", **grounding_kwargs)
            f.validation = Validation(
                verdict="out_of_scope",
                rationale=f"ungrounded citation: primary affected file '{primary}' does not exist "
                          "in the repo under audit (likely mis-attributed from another target)")
            dropped.append(_drop_record(f, "ungrounded_citation (primary file not in repo)"))
            _log(f"{f.id}: dropped pre-validation (ungrounded citation: {primary} not in repo)")
            continue
        if missing_files or missing_symbols or out_of_range_lines:
            f.grounding = Grounding(status="ungrounded", **grounding_kwargs)
            f.confidence = _downgrade_confidence(f.confidence)
            n_downgraded += 1
            _log(f"{f.id}: ungrounded citation {missing_symbols or missing_files or out_of_range_lines}; confidence "
                 f"downgraded to {f.confidence}, flagged for the validator")
        else:
            f.grounding = Grounding(status="grounded", **grounding_kwargs)
        kept.append(f)
    if dropped or n_downgraded:
        _log(f"citation grounding: {len(dropped)} dropped, {n_downgraded} downgraded")
    return kept, dropped


def _grounding_note(f: Finding) -> str:
    """A prominent warning block, prepended to a finding's validation excerpts, when the
    deterministic grounding pass found cited files/symbols that do not exist in this repo."""
    g = f.grounding
    if not g or g.status == "grounded":
        return ""
    parts: list[str] = []
    if g.missing_symbols:
        parts.append("code symbol(s) cited but NOT FOUND anywhere in this repo: "
                     + ", ".join(g.missing_symbols))
    if g.missing_files:
        parts.append("file(s) cited but NOT FOUND in this repo: " + ", ".join(g.missing_files))
    if g.out_of_range_lines:
        parts.append("line citation(s) exceed the actual file length: "
                     + ", ".join(g.out_of_range_lines))
    if not parts:
        return ""
    return ("!!! CITATION GROUNDING WARNING (deterministic pre-check) !!!\n"
            + "\n".join(f"- {p}" for p in parts)
            + "\nA citation that does not exist in THIS repo is strong evidence the finding was "
              "mis-attributed (e.g. carried over from a different project). Weigh this heavily: "
              "unless you can point to the real code here, refute it.\n\n")


# --------------------------------------------------------------------------- excerpts
def _build_excerpts(repo_dir: Path, affected: list[str], ctx_lines: int, max_bytes: int) -> str:
    chunks: list[str] = []
    total = 0
    for ref in affected:
        file, line = split_ref(ref)
        root = repo_dir.resolve()
        path = (repo_dir / file).resolve()
        if not path.is_relative_to(root):
            chunks.append(f"--- {ref} (source not found in repo copy) ---")
            continue
        try:
            if not path.is_file():
                chunks.append(f"--- {ref} (source not found in repo copy) ---")
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            # A malformed/garbage citation must never crash the whole batch (validate/corroborate
            # cover many OTHER unrelated findings in the same call) -- e.g. a colon-bearing `file`
            # can pass is_file() yet fail read_text() on Windows (NTFS alternate-data-stream path
            # semantics treat "name:suffix" as a stream reference on the base file).
            chunks.append(f"--- {ref} (unreadable in repo copy: {exc.__class__.__name__}) ---")
            continue
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
    excerpts = _grounding_note(finding) + _build_excerpts(
        ctx.repo_dir, finding.affected,
        ctx.config.excerpt_context_lines, ctx.config.excerpt_max_bytes,
    )
    mapping = {
        "FINDING_JSON": json.dumps(finding.model_dump(exclude_none=True), indent=2),
        "CODE_EXCERPTS": excerpts,
        "REPO_PATH": str(ctx.repo_dir.resolve()),
        "TARGET_TYPE": scope.target_type,
        "SCOPE_JSON": scope_json_text,
        "GROUND_TRUTH": _format_ground_truth(ground_truth, finding.source_focus),
    }
    rendered, neutral_rendered = render_prompt_pair(
        ctx.assets_dir, "02_adversarial_validation_prompt.md", mapping)
    assert_prohibited_present(rendered, scope.prohibited_techniques)  # guardrail

    # Impact discipline (no reflexive IMDS-style escalation) + accepted-by-design context: a finding
    # matching a stated accepted risk should be refuted-as-out-of-scope rather than confirmed.
    def _finish(text: str) -> str:
        text = (text.rstrip() + "\n\n" + design_context_block(scope.accepted_risks) + "\n\n"
                "If this finding matches an accepted-by-design behavior listed above, return verdict "
                "`out_of_scope` with a rationale that names the accepted risk (it is intended, not a "
                "vulnerability).")
        return with_artifact_contract(
            text,
            artifacts=[{
                "type": "verdict", "filename": f"verdict_{finding.id}.json", "schema": None,
                "desc": "the adversarial validation verdict for this single finding",
            }],
        )

    prompt = _finish(rendered)
    neutral_prompt = _finish(neutral_rendered) if neutral_rendered is not None else None
    if neutral_prompt is not None:
        assert_prohibited_present(neutral_prompt, scope.prohibited_techniques)
    try:
        result = ctx.runner.run(
            prompt=prompt,
            neutral_prompt=neutral_prompt,
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
                          rationale="validation session failed; see the local LLM log for diagnostics")
    files = collect_output_files(result, "verdict_*.json")
    if not files:
        # No verdict produced: do not auto-confirm. Flag for human runtime review.
        return Validation(verdict="needs_runtime_verification",
                          rationale="validation session produced no verdict file")
    data = json.loads(files[0].read_text(encoding="utf-8-sig"))
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
            "code_excerpts": _grounding_note(f) + _build_excerpts(
                ctx.repo_dir, f.affected,
                ctx.config.excerpt_context_lines, ctx.config.excerpt_max_bytes),
            "ground_truth": _format_ground_truth(ground_truth, f.source_focus),
        })
    mapping = {
        "FINDINGS_BATCH": json.dumps(items, indent=2),
        "REPO_PATH": str(ctx.repo_dir.resolve()),
        "TARGET_TYPE": scope.target_type,
        "SCOPE_JSON": scope_json_text,
    }
    rendered, neutral_rendered = render_prompt_pair(
        ctx.assets_dir, "02b_adversarial_validation_batch_prompt.md", mapping)
    assert_prohibited_present(rendered, scope.prohibited_techniques)  # guardrail

    def _finish(text: str) -> str:
        text = (text.rstrip() + "\n\n" + design_context_block(scope.accepted_risks) + "\n\n"
                "If a finding matches an accepted-by-design behavior listed above, return verdict "
                "`out_of_scope` for it with a rationale that names the accepted risk.")
        return with_artifact_contract(text, artifacts=[{
            "type": "verdicts", "filename": "verdicts.json", "schema": None,
            "desc": "a JSON object {\"verdicts\": [...]} with ONE adversarial verdict per finding_id in the batch",
        }])

    prompt = _finish(rendered)
    neutral_prompt = _finish(neutral_rendered) if neutral_rendered is not None else None
    if neutral_prompt is not None:
        assert_prohibited_present(neutral_prompt, scope.prohibited_techniques)
    ids = [f.id for f in batch]
    try:
        result = ctx.runner.run(
            prompt=prompt, neutral_prompt=neutral_prompt, run_dir=ctx.run_dir,
            work_dir=ctx.work_dir("validate", "batch-" + ids[0]),   # fresh, isolated context
            model=ctx.config.model_for("validate"), stage="validate",
            run_id=ctx.run_id, repo_dir=ctx.repo_dir,               # READ-ONLY
            allowed_tools=ARTIFACT_TOOLS, label="validate-batch-" + ids[0])
    except RunnerError as exc:
        _log(f"batch {ids[0]}+{len(ids) - 1}: validation session failed ({exc}); "
             f"flagging {len(ids)} finding(s) for human review")
        return {fid: Validation(
            verdict="needs_runtime_verification",
            rationale="validation session failed; see the local LLM log for diagnostics",
        ) for fid in ids}
    out: dict[str, Validation] = {}
    for fp in collect_output_files(result, "verdicts*.json"):
        try:
            doc = json.loads(fp.read_text(encoding="utf-8-sig"))
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
    merged, semantic_dedup_dropped = _semantic_dedup(ctx, merged)
    merged, grounding_dropped = _ground_citations(ctx, merged)

    dropped: list[dict] = list(semantic_dedup_dropped) + list(grounding_dropped)
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

    infra_unvalidated = sum(1 for f in survivors if _is_infra_unvalidated(f))

    out_doc = {
        "program_name": scope.program_name,
        "run_id": ctx.run_id,
        "generated_at": ctx.timestamp(),
        "stats": {
            "raw": len(raw_findings),
            "after_dedup": len(merged) + len(semantic_dedup_dropped) + len(grounding_dropped),
            "after_semantic_dedup": len(merged) + len(grounding_dropped),
            "grounding_dropped": len(grounding_dropped),
            "after_grounding": len(merged),
            "validated": len(launch),
            "survivors": len(survivors),
            "dropped": len(dropped),
            "survivors_not_actually_validated": infra_unvalidated,
        },
        "findings": [f.model_dump(exclude_none=True) for f in survivors],
        "dropped": dropped,
    }
    atomic_write_json(ctx.validated_findings_path, out_doc)
    survivor_note = (
        f"{len(survivors)} survivor(s) ({infra_unvalidated} not actually adversarially validated — "
        f"session/backend failure or budget reached; re-run validate later if desired)"
        if infra_unvalidated else f"{len(survivors)} survivor(s)"
    )
    _log(f"{survivor_note}, {len(dropped)} dropped -> {ctx.validated_findings_path.name}")
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
