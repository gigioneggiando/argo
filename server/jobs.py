"""Background job manager: launches a pipeline run in a daemon thread, tracks it, and supports
cancellation at stage boundaries. For a local single-user tool, in-process threads are enough;
the pipeline is I/O-bound (it shells out to ``claude``). Isolating runs into subprocesses is a
future hardening step (noted in the roadmap)."""

from __future__ import annotations

import threading
from pathlib import Path

from argo.config import PipelineConfig
from argo.orchestrator import (PipelineCancelled, build_context, new_run_id, pipeline_stages,
                               run_pipeline)
from argo.progress import ProgressReporter

from .schemas import RunRequest


class JobManager:
    def __init__(self, base_config: PipelineConfig):
        self.base = base_config
        self._jobs: dict[str, dict] = {}
        self._lock = threading.Lock()

    _STAGES = ("ingest", "research", "recon", "audit", "sca", "validate", "corroborate",
               "verify", "asan_poc", "runtime", "live", "remediate", "chat", "report")

    def _config_for(self, req: RunRequest) -> PipelineConfig:
        cfg = self.base.with_overrides(
            runner=req.config.runner,
            budget_usd=req.config.budget_usd,
            max_parallel_audits=req.config.parallel,
            codex_model=req.config.codex_model,
            codex_oss=req.config.codex_oss,
            codex_local_provider=req.config.codex_local_provider,
            gemini_api_key=req.config.gemini_api_key,
            claude_api_key=req.config.claude_api_key,
            codex_api_key=req.config.codex_api_key,
            stage_runners=dict(req.config.stage_runners),
            allow_model_substitution=req.config.allow_model_substitution,
        )
        if req.config.profile:
            from argo.profiles import apply_profile
            cfg = apply_profile(cfg, req.config.profile)
            cfg = cfg.with_overrides(stage_runners={**cfg.stage_runners, **req.config.stage_runners})
        if req.config.gemini_model:
            # Flat override across every stage, applied BEFORE calibration/audit_model below so
            # those can still bump individual stages on top -- mirrors the CLI's _build_config.
            cfg = cfg.with_overrides(
                gemini_stage_models={k: req.config.gemini_model for k in cfg.gemini_stage_models})
        if req.config.calibration:
            cfg = cfg.calibrated()
        if req.config.audit_model:
            cfg = cfg.with_stage_model("audit", req.config.audit_model)
        for stage, model in (req.config.models or {}).items():
            if model and stage in self._STAGES:  # ignore unknown stage keys
                cfg = cfg.with_stage_model(stage, model)
        if req.config.stage_effort:
            effort = dict(cfg.stage_effort)
            allowed_effort = {"low", "medium", "high", "xhigh", "max"}
            for stage, value in req.config.stage_effort.items():
                backend = cfg.stage_runners.get(stage, cfg.runner)
                if backend != "headless":
                    raise ValueError(f"stage_effort is currently supported only for headless/Claude: {stage}")
                if value not in allowed_effort:
                    raise ValueError(f"invalid stage_effort for {stage}: {value}")
                effort[stage] = value
            cfg = cfg.with_overrides(stage_effort=effort)
        from argo.model_catalog import validate_selection
        stages = set(cfg.stage_models) | set(cfg.codex_stage_models) | set(cfg.gemini_stage_models) | set(cfg.stage_runners)
        for stage in stages:
            backend = cfg.stage_runners.get(stage, cfg.runner)
            check = validate_selection(cfg.model_for(stage), backend)
            if check.get("selectable") is False:
                raise ValueError(f"invalid effective routing for {stage}: {check.get('reason')}")
        return cfg

    def start(self, req: RunRequest) -> str:
        run_id = new_run_id()
        ctx = build_context(self._config_for(req), run_id)
        ctx.run_dir.mkdir(parents=True, exist_ok=True)
        # No brief -> local/personal source-only review (scope synthesized from the repo; offline).
        local_mode = not (req.brief and req.brief.strip())
        if not local_mode:
            (ctx.run_dir / "brief.txt").write_text(req.brief, encoding="utf-8")
        research = bool(req.research) and not local_mode
        links_path: Path | None = None
        if req.links and req.links.strip():
            links_path = ctx.run_dir / "links.txt"
            links_path.write_text(req.links, encoding="utf-8")

        stages = pipeline_stages(ctx, dry_run=req.dry_run, research_enabled=research)
        reporter = ProgressReporter(ctx, stages)
        reporter.begin()  # status.json exists before this call returns

        cancel = threading.Event()
        thread = threading.Thread(
            target=self._run, args=(ctx, req, links_path, reporter, cancel, local_mode, research),
            daemon=True)
        with self._lock:
            self._jobs[run_id] = {"thread": thread, "cancel": cancel, "ctx": ctx}
        thread.start()
        return run_id

    def _run(self, ctx, req: RunRequest, links_path, reporter, cancel,
             local_mode=False, research=True) -> None:
        try:
            brief_path = None if local_mode else (ctx.run_dir / "brief.txt")
            run_pipeline(ctx, brief_path, req.repo, dry_run=req.dry_run,
                         research_enabled=research, links_path=links_path,
                         reporter=reporter, cancel_event=cancel)
        except PipelineCancelled:
            reporter.cancelled()
        except Exception as exc:  # surface ANY failure as a terminal status, never a silent hang
            reporter.fail(f"{type(exc).__name__}: {exc}")
        finally:
            try:
                ctx.ledger.close()
            except Exception:
                pass

    def cancel(self, run_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(run_id)
        if not job:
            return False
        job["cancel"].set()
        return True

    def is_active(self, run_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(run_id)
        return bool(job and job["thread"].is_alive())
