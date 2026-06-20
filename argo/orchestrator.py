"""Wiring: build a config + run context, generate run IDs, and drive the five stages.
Kept separate from the CLI so tests can drive the pipeline programmatically."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from .config import PipelineConfig
from .context import RunContext
from .ledger import Ledger
from .progress import ProgressReporter
from .runner import RunnerCancelled, build_runner
from .stages import audit, ingest, recon, report, research, runtime, sca, validate


class PipelineCancelled(RuntimeError):
    """Raised when a run is cancelled between stages."""


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]


def build_context(config: PipelineConfig, run_id: str, *, now: str | None = None) -> RunContext:
    ledger = Ledger(config.ledger_path)
    runner = build_runner(config, ledger)
    return RunContext(run_id=run_id, config=config, runner=runner, ledger=ledger, now=now)


# --- individual stages (thin wrappers so the CLI and tests share one entry point) ----
def do_ingest(ctx: RunContext, brief: Path | None, repo: str, repo_is_url: bool | None = None,
              links_path: Path | None = None):
    return ingest.run(ctx, brief_path=brief, repo=repo, repo_is_url=repo_is_url,
                      links_path=links_path)


def do_research(ctx: RunContext):
    return research.run(ctx)


def do_recon(ctx: RunContext):
    return recon.run(ctx)


def do_audit(ctx: RunContext):
    return audit.run(ctx)


def do_sca(ctx: RunContext):
    return sca.run(ctx)


def do_validate(ctx: RunContext):
    return validate.run(ctx)


def do_runtime(ctx: RunContext):
    return runtime.run(ctx)


def do_report(ctx: RunContext):
    return report.run(ctx)


def run_pipeline(ctx: RunContext, brief: Path | None, repo: str, *, dry_run: bool = False,
                 research_enabled: bool = True, repo_is_url: bool | None = None,
                 links_path: Path | None = None, reporter: ProgressReporter | None = None,
                 cancel_event=None) -> dict:
    """Run the pipeline (ingest → [research] → recon → audit → validate → report). Never submits.

    ``research_enabled`` (default on) inserts the Stage-0 web-OSINT step before recon; it is the
    only networked session and is best-effort (a failure never aborts the run). Optional
    ``reporter`` records per-stage progress to ``status.json``; ``cancel_event`` aborts at the next
    stage boundary AND mid-stage — it is wired into the runner so an in-flight CLI session is killed.
    """
    do_sca_stage = (not dry_run) and ctx.config.sca_enabled
    do_runtime_stage = (not dry_run) and ctx.config.runtime_enabled
    stages = (["ingest"] + (["research"] if research_enabled else []) + ["recon"]
              + ([] if dry_run else ["audit"] + (["sca"] if do_sca_stage else [])
                 + ["validate"] + (["runtime"] if do_runtime_stage else []) + ["report"]))
    own = reporter is None
    reporter = reporter or ProgressReporter(ctx, stages)
    if own:
        reporter.begin()

    # Wire cancellation into the runner so a long session (e.g. a 20-min audit) is killed on Cancel,
    # not just checked between stages.
    ctx.runner.cancel_event = cancel_event

    def _check_cancel() -> None:
        if cancel_event is not None and cancel_event.is_set():
            reporter.cancelled()
            raise PipelineCancelled(f"run {ctx.run_id} cancelled")

    def _stage(name: str, fn):
        _check_cancel()
        reporter.start_stage(name)
        try:
            result = fn()
        except PipelineCancelled:
            raise
        except RunnerCancelled as exc:                 # killed mid-stage -> a cancellation, not a failure
            reporter.cancelled()
            raise PipelineCancelled(f"run {ctx.run_id} cancelled mid-stage ({name})") from exc
        except Exception as exc:
            reporter.fail_stage(name, f"{type(exc).__name__}: {exc}")
            raise
        reporter.finish_stage(name)
        return result

    _stage("ingest", lambda: do_ingest(ctx, brief, repo, repo_is_url=repo_is_url,
                                       links_path=links_path))
    if research_enabled:
        _stage("research", lambda: do_research(ctx))
    prompts = _stage("recon", lambda: do_recon(ctx))
    if dry_run:
        reporter.complete()
        return {
            "run_id": ctx.run_id,
            "stopped_after": "recon (dry-run)",
            "prompts": [str(p) for p in prompts],
            "scope": str(ctx.scope_path),
        }
    _stage("audit", lambda: do_audit(ctx))
    if do_sca_stage:
        _stage("sca", lambda: do_sca(ctx))
    _stage("validate", lambda: do_validate(ctx))
    if do_runtime_stage:
        _stage("runtime", lambda: do_runtime(ctx))
    report_path = _stage("report", lambda: do_report(ctx))
    reporter.complete()
    return {
        "run_id": ctx.run_id,
        "report": str(report_path),
        "drafts_dir": str(ctx.drafts_dir),
        "cost_usd": ctx.ledger.run_cost(ctx.run_id),
    }
