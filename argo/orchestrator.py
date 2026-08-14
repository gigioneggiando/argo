"""Wiring: build a config + run context, generate run IDs, and drive the five stages.
Kept separate from the CLI so tests can drive the pipeline programmatically."""

from __future__ import annotations

import json
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from .config import PipelineConfig
from .context import RunContext
from .estimate import estimate_cost, format_estimate
from .ledger import Ledger
from .progress import ProgressReporter, read_status
from .runner import RunnerCancelled, _is_retryable, build_runner, parse_retry_after
from .stages import (asan_poc, audit, corroborate, deep_verify, freshness, ingest, live, recon,
                     report, research, runtime, sca, second_opinion, validate)


class PipelineCancelled(RuntimeError):
    """Raised when a run is cancelled between stages."""


#: A stage exception that reaches _run_stage_sequence already represents every backend a
#: FallbackRunner had configured failing (or a single-backend config's only option failing) -- so
#: an auto-retry here means "give whatever just failed a little real TIME, then try the exact same
#: stage call again," relying on FallbackRunner's own internal cooldown bookkeeping (which persists
#: on ctx.runner across the whole run) to skip anything still disabled. Bounded so a genuinely
#: broken stage can't loop forever.
_MAX_STAGE_AUTO_RETRIES = 2

#: Cap on how long an auto-retry will sleep waiting for a failure's own reset hint. Beyond this,
#: auto-retrying blindly would silently hang an unattended run for a long, indeterminate stretch --
#: give up on auto-retry and surface the failure normally instead (cli.py's resume-hint then tells
#: a human exactly how to continue manually, e.g. `argo resume --wait --max-wait 12h` for a hint
#: further out than this).
_AUTO_RETRY_MAX_SLEEP = timedelta(minutes=10)

#: Failure kinds an automatic in-process stage retry must NOT attempt. Credits exhaustion will not
#: resolve itself no matter how long the process waits short of a human topping the account up --
#: see runner._COOLDOWN_BY_FAILURE_KIND's own reasoning for the same judgment call applied to
#: FallbackRunner's backend-level cooldown. Retrying here would just burn the bounded retry budget
#: on something that structurally cannot succeed, delaying the (still necessary) surfaced failure.
_NO_AUTO_RETRY_FAILURE_KINDS = {"credits_exhausted"}


def _auto_retry_wait_seconds(exc: Exception) -> float | None:
    """How long to sleep before an automatic in-process stage retry, or ``None`` if either the
    failure isn't retryable at all, is a kind that auto-retry should never attempt, or its own
    reset hint points further out than ``_AUTO_RETRY_MAX_SLEEP`` (too long to wait unattended)."""
    if not _is_retryable(exc):
        return None
    if getattr(exc, "failure_kind", None) in _NO_AUTO_RETRY_FAILURE_KINDS:
        return None
    target = parse_retry_after(getattr(exc, "retry_after", None))
    if target is None:
        return 20.0  # no specific hint -- still worth one short, cheap pause before retrying
    now = datetime.now(timezone.utc).astimezone(target.tzinfo)
    wait = (target - now).total_seconds()
    if wait <= 0:
        return 1.0
    if wait > _AUTO_RETRY_MAX_SLEEP.total_seconds():
        return None
    return wait


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]


def build_context(config: PipelineConfig, run_id: str, *, now: str | None = None) -> RunContext:
    ledger = Ledger(config.ledger_path)
    runner = build_runner(config, ledger)
    return RunContext(run_id=run_id, config=config, runner=runner, ledger=ledger, now=now)


# --- individual stages (thin wrappers so the CLI and tests share one entry point) ----
def do_ingest(ctx: RunContext, brief: Path | None, repo: str, repo_is_url: bool | None = None,
              links_path: Path | None = None, accepted_risks_path: Path | None = None,
              commit: str | None = None):
    return ingest.run(ctx, brief_path=brief, repo=repo, repo_is_url=repo_is_url,
                      links_path=links_path, accepted_risks_path=accepted_risks_path,
                      commit=commit)


def do_research(ctx: RunContext):
    return research.run(ctx)


def do_recon(ctx: RunContext):
    return recon.run(ctx)


def do_audit(ctx: RunContext):
    return audit.run(ctx)


def do_sca(ctx: RunContext):
    return sca.run(ctx)


def do_second_opinion(ctx: RunContext):
    return second_opinion.run(ctx)


def do_validate(ctx: RunContext):
    return validate.run(ctx)


def do_corroborate(ctx: RunContext):
    return corroborate.run(ctx)


def do_verify(ctx: RunContext):
    return deep_verify.run(ctx)


def do_asan_poc(ctx: RunContext):
    return asan_poc.run(ctx)


def do_freshness_check(ctx: RunContext):
    return freshness.run(ctx)


def do_runtime(ctx: RunContext):
    return runtime.run(ctx)


def do_live(ctx: RunContext):
    return live.run(ctx)


def do_report(ctx: RunContext):
    return report.run(ctx)


def pipeline_stages(ctx: RunContext, *, dry_run: bool = False,
                    research_enabled: bool | None = None) -> list[str]:
    """Compute the effective stage sequence from the run config."""
    research_on = ctx.config.research_enabled if research_enabled is None else research_enabled
    stages = ["ingest"] + (["research"] if research_on else []) + ["recon"]
    if dry_run:
        return stages
    stages += ["audit"]
    if ctx.config.sca_enabled:
        stages.append("sca")
    if ctx.config.second_opinion_passes > 0:
        stages.append("second_opinion")
    stages.append("validate")
    if ctx.config.corroborate_enabled:
        stages.append("corroborate")
    if ctx.config.verify_enabled:
        stages.append("verify")
    if ctx.config.asan_poc_enabled:
        stages.append("asan_poc")
    if ctx.config.freshness_check_enabled:
        stages.append("freshness_check")
    if ctx.config.runtime_enabled:
        stages.append("runtime")
    stages.append("report")
    return stages


def _stage_functions(
    ctx: RunContext,
    stages: list[str],
    *,
    brief: Path | None = None,
    repo: str | None = None,
    repo_is_url: bool | None = None,
    links_path: Path | None = None,
    accepted_risks_path: Path | None = None,
    commit: str | None = None,
    resume: bool = False,
) -> list[tuple[str, object]]:
    funcs = {
        "research": lambda: do_research(ctx),
        "recon": lambda: do_recon(ctx),
        "audit": lambda: do_audit(ctx),
        "sca": lambda: do_sca(ctx),
        "second_opinion": lambda: do_second_opinion(ctx),
        "validate": lambda: do_validate(ctx),
        "corroborate": lambda: do_corroborate(ctx),
        "verify": lambda: do_verify(ctx),
        "asan_poc": lambda: do_asan_poc(ctx),
        "freshness_check": lambda: do_freshness_check(ctx),
        "runtime": lambda: do_runtime(ctx),
        "live": lambda: do_live(ctx),
        "report": lambda: do_report(ctx),
    }
    if not resume:
        if repo is None:
            raise ValueError("repo is required for ingest")
        funcs["ingest"] = lambda: do_ingest(
            ctx, brief, repo, repo_is_url=repo_is_url, links_path=links_path,
            accepted_risks_path=accepted_risks_path, commit=commit)
    return [(name, funcs[name]) for name in stages if name in funcs]


def _run_stage_sequence(ctx: RunContext, stage_fns: list[tuple[str, object]],
                        reporter: ProgressReporter, cancel_event=None,
                        *, start_from: str | None = None,
                        done_stages: set[str] | None = None) -> dict[str, object]:
    names = [name for name, _fn in stage_fns]
    if start_from is not None and start_from not in names:
        raise ValueError(f"unknown or non-resumable stage {start_from!r}")
    start_idx = names.index(start_from) if start_from else 0
    done_stages = done_stages or set()
    results: dict[str, object] = {}

    # Wire cancellation into the runner so a long session is killed on Cancel, not just checked
    # between stages.
    ctx.runner.cancel_event = cancel_event

    def _check_cancel() -> None:
        if cancel_event is not None and cancel_event.is_set():
            reporter.cancelled()
            raise PipelineCancelled(f"run {ctx.run_id} cancelled")

    for idx, (name, fn) in enumerate(stage_fns):
        if idx < start_idx:
            continue
        if name in done_stages:
            continue
        _check_cancel()
        reporter.start_stage(name)
        attempt = 0
        while True:
            try:
                result = fn()
                break
            except PipelineCancelled:
                raise
            except RunnerCancelled as exc:
                reporter.cancelled()
                raise PipelineCancelled(f"run {ctx.run_id} cancelled mid-stage ({name})") from exc
            except Exception as exc:
                wait_s = _auto_retry_wait_seconds(exc) if attempt < _MAX_STAGE_AUTO_RETRIES else None
                if wait_s is None:
                    reporter.fail_stage(
                        name,
                        f"{type(exc).__name__}: {exc}",
                        retry_after=getattr(exc, "retry_after", None),
                    )
                    raise
                attempt += 1
                print(f"[orchestrator] stage {name!r} failed "
                      f"({getattr(exc, 'failure_kind', None) or 'retryable'}); auto-retry "
                      f"{attempt}/{_MAX_STAGE_AUTO_RETRIES} in {wait_s:.0f}s: {exc}",
                      file=sys.stderr)
                time.sleep(wait_s)
        reporter.finish_stage(name)
        results[name] = result
    return results


def _completed_summary(ctx: RunContext) -> dict:
    report_path = ctx.run_dir / "REPORT.md"
    return {
        "run_id": ctx.run_id,
        "report": str(report_path) if report_path.exists() else None,
        "drafts_dir": str(ctx.drafts_dir),
        "cost_usd": ctx.ledger.run_cost(ctx.run_id),
    }


def run_pipeline(ctx: RunContext, brief: Path | None, repo: str, *, dry_run: bool = False,
                 research_enabled: bool | None = None, repo_is_url: bool | None = None,
                 links_path: Path | None = None, accepted_risks_path: Path | None = None,
                 reporter: ProgressReporter | None = None,
                 cancel_event=None, commit: str | None = None,
                 estimate_before_audit: bool = False,
                 estimate_output: Callable[[str], None] | None = None,
                 estimate_confirm: Callable[[dict], bool] | None = None) -> dict:
    """Run the pipeline and emit status.json progress. Never submits."""
    if research_enabled is not None and research_enabled != ctx.config.research_enabled:
        ctx.config = ctx.config.with_overrides(research_enabled=research_enabled)
    stages = pipeline_stages(ctx, dry_run=dry_run)
    own = reporter is None
    reporter = reporter or ProgressReporter(ctx, stages)
    if own:
        reporter.begin()

    stage_fns = _stage_functions(
        ctx, stages, brief=brief, repo=repo, repo_is_url=repo_is_url,
        links_path=links_path, accepted_risks_path=accepted_risks_path, commit=commit)
    results: dict[str, object] = {}
    estimate: dict | None = None
    if estimate_before_audit and not dry_run and "audit" in stages:
        audit_idx = next(i for i, (name, _fn) in enumerate(stage_fns) if name == "audit")
        results.update(_run_stage_sequence(ctx, stage_fns[:audit_idx], reporter, cancel_event))
        estimate = _estimate_after_recon(ctx)
        if estimate_output is not None:
            estimate_output(format_estimate(estimate))
        proceed = estimate_confirm(estimate) if estimate_confirm is not None else True
        if not proceed:
            reporter.complete()
            prompts = results.get("recon") or []
            return {
                "run_id": ctx.run_id,
                "stopped_after": "recon (estimate declined)",
                "estimate": estimate,
                "prompts": [str(p) for p in prompts],
                "scope": str(ctx.scope_path),
            }
        results.update(_run_stage_sequence(ctx, stage_fns[audit_idx:], reporter, cancel_event))
    else:
        results = _run_stage_sequence(ctx, stage_fns, reporter, cancel_event)
    reporter.complete()
    if dry_run:
        prompts = results.get("recon") or []
        return {
            "run_id": ctx.run_id,
            "stopped_after": "recon (dry-run)",
            "prompts": [str(p) for p in prompts],
            "scope": str(ctx.scope_path),
        }
    report_path = results.get("report") or (ctx.run_dir / "REPORT.md")
    summary = {
        "run_id": ctx.run_id,
        "report": str(report_path),
        "drafts_dir": str(ctx.drafts_dir),
        "cost_usd": ctx.ledger.run_cost(ctx.run_id),
    }
    if estimate is not None:
        summary["estimate"] = estimate
    return summary


def _estimate_after_recon(ctx: RunContext) -> dict:
    meta = {}
    try:
        meta = json.loads(ctx.meta_path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        pass
    archetype = meta.get("archetype") if isinstance(meta, dict) else None
    return estimate_cost(ctx.ledger, Path(ctx.config.runs_dir), archetype or "other",
                         ctx.config, run_id=ctx.run_id)


def resume_pipeline(ctx: RunContext, from_stage: str | None = None,
                    reporter: ProgressReporter | None = None,
                    cancel_event=None) -> dict:
    """Resume an existing run from the first stage not marked done in status.json."""
    status = read_status(ctx.run_dir)
    if not status:
        raise FileNotFoundError(f"cannot resume run {ctx.run_id}: missing or unreadable status.json")
    stages = pipeline_stages(ctx)
    state_by_stage = {
        st.get("name"): st.get("state")
        for st in (status.get("stages") or [])
        if isinstance(st, dict)
    }
    if from_stage is not None:
        if from_stage not in stages:
            raise ValueError(f"stage {from_stage!r} is not in this run's configured stage sequence")
        start = from_stage
    else:
        start = next((s for s in stages if state_by_stage.get(s) != "done"), None)
    if start is None:
        return _completed_summary(ctx)
    if start == "ingest":
        raise RuntimeError(
            "cannot resume from ingest: the original --brief/--repo inputs are not replayed by "
            "argo resume. Re-run argo pipeline/ingest with the original inputs.")

    done = {s for s, state in state_by_stage.items() if state == "done"}
    own = reporter is None
    reporter = reporter or ProgressReporter(ctx, stages, initial_status=status)
    if own:
        reporter.begin()
    results = _run_stage_sequence(
        ctx,
        _stage_functions(ctx, stages, resume=True),
        reporter,
        cancel_event,
        start_from=start,
        done_stages=done,
    )
    reporter.complete()
    report_path = results.get("report") or (ctx.run_dir / "REPORT.md")
    return {
        "run_id": ctx.run_id,
        "resumed_from": start,
        "report": str(report_path) if Path(report_path).exists() else str(report_path),
        "drafts_dir": str(ctx.drafts_dir),
        "cost_usd": ctx.ledger.run_cost(ctx.run_id),
    }
