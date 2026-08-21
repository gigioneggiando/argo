"""Stage — Second opinion (opt-in; runs AFTER audit/[sca], BEFORE validate).

Runs N additional, fully independent ("blind") recon+audit passes over the SAME scope/repo the
primary pass already ingested, then merges their raw findings into the primary run's
``findings_dir`` before validate ever runs. This is the tool encoding a manual methodology used
repeatedly in real disclosures (fastjson2, open62541): an LLM audit is a single noisy sample of
what a careful reader would find; a second, genuinely independent pass over the same code — ideally
on a different backend for real diversity, not just a re-roll of the same model — surfaces both
findings the first pass missed (recall) and, when the two passes independently converge on the same
bug, a real corroboration signal no single pass can produce on its own.

Each blind pass gets its own run_id (``"{primary_run_id}-so{N}"``) and therefore its own isolated
``run_dir`` — it never reads the primary's ``findings/`` and the primary never reads its foci mid-
flight, so the two audits cannot contaminate each other. What IS deliberately reused (to avoid
wasted spend and keep the comparison apples-to-apples): the already-parsed ``scope.json``, the
already-fetched read-only repo copy, and the primary's Stage-0 research brief if research ran. What
is NOT reused: recon's own synthesis (a fresh recon session naturally produces different audit foci
from sampling variance alone) and the audit itself.

Findings copied back into the primary's ``findings_dir`` carry a document-level ``source_pass``
field (``"second-opinion-1"``, ``"second-opinion-2"``, ...); the primary's own findings implicitly
carry no such field (read back as ``"primary"`` by validate.py). validate's existing structural
(``_merge``) and semantic (``_semantic_dedup``) dedup already collapse duplicates across audit
foci — collapsing across PASSES needs no new matching logic, only the bookkeeping addition (see
``Finding.corroborating_passes``) that notices when a collapsed group spans more than one distinct
pass. That is the reuse this stage was designed around: the second-opinion methodology was mostly
already implicit in stages that exist for an unrelated reason.

Guardrails:
  * Offline, like audit: full repo mount (READ-ONLY), no network tools (unless research/SCA were
    already run for the primary — this stage never re-runs either).
  * Best-effort per pass: a failed blind pass (session/backend outage) is logged and skipped, never
    aborts the run — the primary's own findings are never held hostage by a second opinion failing.
  * Never touches the program's live in-scope hosts (inherits the same guarantee every offline stage
    has; no stage in this module ever requests a networked tool).
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
from pathlib import Path

from ..config import PipelineConfig
from ..context import RunContext, atomic_write_json
from ..guardrails import GuardrailError
from ..runner import build_runner
from . import audit, ingest, recon


def _log(msg: str) -> None:
    print(f"[second-opinion] {msg}", file=sys.stderr)


def _rmtree_readonly_safe(path: Path) -> None:
    """A sub-run's repo copy is deliberately made read-only by ingest._make_readonly (defense in
    depth), so a plain shutil.rmtree fails on it. Clear the write bit and retry on error."""
    def _onerror(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    shutil.rmtree(path, onerror=_onerror)


def _build_sub_context(ctx: RunContext, pass_index: int) -> RunContext:
    """A fresh, isolated RunContext for one blind pass: its own run_id (-> its own run_dir), but the
    SAME ledger as the primary (one SQLite file records every pass's cost, queryable together) and,
    unless overridden, the same runner/config. ``second_opinion_backend`` swaps the runner for real
    cross-engine diversity (e.g. primary=codex, second opinion=headless/Claude)."""
    sub_run_id = f"{ctx.run_id}-so{pass_index}"
    sub_config: PipelineConfig = ctx.config
    if ctx.config.second_opinion_backend and ctx.config.second_opinion_backend != ctx.config.runner:
        sub_config = ctx.config.with_overrides(runner=ctx.config.second_opinion_backend)
    runner = ctx.runner if sub_config is ctx.config else build_runner(sub_config, ctx.ledger)
    return RunContext(run_id=sub_run_id, config=sub_config, runner=runner, ledger=ctx.ledger, now=ctx.now)


def _seed_sub_context(ctx: RunContext, sub_ctx: RunContext) -> None:
    """Cheaply reuse the primary's already-parsed scope + already-fetched repo (and research brief,
    if present) instead of re-parsing the brief or re-cloning/copying the repo N times. No LLM call,
    no network fetch — this is the only "shared" state between passes; everything downstream
    (recon's synthesis, audit's findings) runs fresh and independent."""
    sub_ctx.run_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ctx.scope_path, sub_ctx.scope_path)
    if ctx.meta_path.exists():
        shutil.copy2(ctx.meta_path, sub_ctx.meta_path)
    if ctx.research_brief_path.exists():
        shutil.copy2(ctx.research_brief_path, sub_ctx.research_brief_path)
    if ctx.threat_intel_path.exists():
        shutil.copy2(ctx.threat_intel_path, sub_ctx.threat_intel_path)
    if ctx.ground_truth_path.exists():
        shutil.copy2(ctx.ground_truth_path, sub_ctx.ground_truth_path)
    # Reuses ingest's own repo-copy helper (local source -> read-only copy), so the second-opinion
    # repo gets the exact same write-bit-stripped treatment the primary's did, without re-cloning
    # from the original URL/path.
    ingest.acquire_repo(str(ctx.repo_dir), sub_ctx.repo_dir, is_url=False)


def _merge_findings_back(ctx: RunContext, sub_ctx: RunContext, pass_label: str) -> int:
    """Copy one blind pass's raw findings/*.json into the primary's findings_dir, tagging each
    document with source_pass and renaming to avoid any filename collision with the primary's own
    foci. Returns the number of findings copied over (for logging only)."""
    ctx.findings_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for path in sorted(sub_ctx.findings_dir.glob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            _log(f"{pass_label}: skipping unreadable findings file {path.name}")
            continue
        doc["source_pass"] = pass_label
        doc["audit_focus"] = f"{pass_label}-{doc.get('audit_focus', path.stem)}"
        count += len(doc.get("findings", []))
        out_path = ctx.findings_dir / f"{pass_label}-{path.name}"
        atomic_write_json(out_path, doc)
    return count


def _run_one_pass(ctx: RunContext, pass_index: int) -> int:
    # SCA is deliberately never re-run per pass: it's deterministic-ish (manifest matching + LLM
    # long-tail), so repeating it would just re-report the same dependency findings, not add real
    # audit diversity. Only the code-reading recon+audit cycle benefits from a second opinion.
    pass_label = f"second-opinion-{pass_index}"
    sub_ctx = _build_sub_context(ctx, pass_index)
    if sub_ctx.run_dir.exists():
        # A previous invocation (e.g. a failed pass retried via the standalone `argo second-opinion`
        # command) may have left a partial sub-run dir behind — ingest.acquire_repo refuses to copy
        # into an existing target, so without this every retry after any failure would fail again on
        # the SAME collision. Wipe it so each attempt starts from a clean, reproducible seed.
        _rmtree_readonly_safe(sub_ctx.run_dir)
    try:
        _seed_sub_context(ctx, sub_ctx)
        recon.run(sub_ctx)
        audit.run(sub_ctx)
        return _merge_findings_back(ctx, sub_ctx, pass_label)
    except GuardrailError:
        raise  # safety controls are run-level hard stops, including inside optional blind passes
    except Exception as exc:  # noqa: BLE001 — one failed blind pass must never abort the run
        _log(f"{pass_label}: failed ({type(exc).__name__}: {exc}); skipping this pass, "
            f"primary findings are unaffected")
        return 0


def run(ctx: RunContext) -> None:
    n = ctx.config.second_opinion_passes
    if n <= 0:
        return
    backend_note = f" on {ctx.config.second_opinion_backend}" if ctx.config.second_opinion_backend else ""
    _log(f"running {n} independent blind pass(es){backend_note} over the same scope/repo")
    total_new = 0
    for i in range(1, n + 1):
        found = _run_one_pass(ctx, i)
        total_new += found
        _log(f"second-opinion-{i}: {found} finding(s) merged into the primary findings_dir")
    _log(f"{total_new} total finding(s) from {n} blind pass(es) added; validate will dedup/reconcile "
        f"them against the primary's own findings next")
