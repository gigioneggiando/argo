"""FastAPI application exposing the pipeline.

Endpoints (all JSON unless noted):
  GET  /health
  POST /runs                      start a run (defaults to the free mock runner)
  GET  /runs                      list runs (newest first)
  GET  /runs/{id}                 live status (stage timeline + cost + ready artifacts)
  GET  /runs/{id}/events          Server-Sent Events stream of status until terminal
  POST /runs/{id}/cancel          request cancellation (takes effect at the next stage boundary)
  GET  /runs/{id}/report          REPORT.md (text/markdown)
  GET  /runs/{id}/artifacts/{name}  a whitelisted single-file artifact
  GET  /runs/{id}/prompts|findings|drafts   the multi-file artifacts

Security: only whitelisted artifact names are served — the repo copy and arbitrary paths are
never exposed. Intended for localhost; do not expose unauthenticated (it runs an agent over
arbitrary repos).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from argo import __version__
from argo import chat as chat_engine
from argo.chat import ChatStore
from argo.costs import cost_report
from argo.fixes import generate_fixes
from argo.knowledge import load_vuln_index
from argo.config import PipelineConfig
from argo.ledger import Ledger
from argo.orchestrator import build_context
from argo.progress import read_status

from .jobs import JobManager
from .recommend import recommend
from .schemas import (ChatMessage, FixRequest, RecommendRequest, RunCreated, RunRequest,
                      Settings)
from .settings import SettingsStore

# Single-file artifacts a client may fetch by name (prevents path traversal — name is a key).
_SINGLE_ARTIFACTS = {
    "scope": "scope.json",
    "repo_profile": "repo_profile.json",
    "research_brief": "research_brief.md",
    "threat_intel": "threat_intel.json",
    "synthesis_notes": "synthesis_notes.md",
    "validated_findings": "validated_findings.json",
    "report": "REPORT.md",
    "meta": "meta.json",
    "status": "status.json",
    "brief": "brief.txt",
    "fixes_report": "fixes_report.json",
}
_TERMINAL = {"completed", "failed", "cancelled"}


def create_app(base_config: PipelineConfig | None = None) -> FastAPI:
    cfg = base_config or PipelineConfig()
    runs_dir = Path(cfg.runs_dir)
    jobs = JobManager(cfg)
    ledger = Ledger(cfg.ledger_path)  # read-side: live per-run cost
    settings = SettingsStore(Path(cfg.ledger_path).with_name("app_settings.json"))

    app = FastAPI(title="Argo — source-static bug-bounty audits", version=__version__)
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
    )

    # -- helpers -------------------------------------------------------------------
    def _run_dir(run_id: str) -> Path:
        rd = runs_dir / run_id
        if not rd.exists():
            raise HTTPException(status_code=404, detail=f"run {run_id} not found")
        return rd

    def _status(run_id: str) -> dict:
        rd = _run_dir(run_id)
        st = read_status(rd) or {"run_id": run_id, "state": "unknown",
                                 "stages": [], "artifacts": {}, "cost_usd": 0.0}
        try:
            st["cost_usd"] = round(ledger.run_cost(run_id), 6)  # live cost, even mid-stage
        except Exception:
            pass
        return st

    def _read_json(path: Path):
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    def _chat_ctx(run_id: str):
        """Build a RunContext for chat that matches how the run was executed (same runner +
        per-stage models, from meta.json) so a mock run chats for free and a real run on the
        real CLI."""
        rd = _run_dir(run_id)
        meta = _read_json(rd / "meta.json") or {}
        chat_cfg = cfg.with_overrides(runner=meta.get("runner", cfg.runner))
        for stage, model in (meta.get("stage_models") or {}).items():
            if model:
                chat_cfg = chat_cfg.with_stage_model(stage, model)
        return build_context(chat_cfg, run_id)

    # -- endpoints -----------------------------------------------------------------
    @app.get("/health")
    def health():
        return {"ok": True, "version": __version__}

    @app.get("/knowledge")
    def knowledge():
        """The curated vulnerability-class index by archetype (Phase 4)."""
        return load_vuln_index()

    @app.post("/runs", response_model=RunCreated, status_code=202)
    def create_run(req: RunRequest):
        run_id = jobs.start(req)
        return RunCreated(run_id=run_id, state="running",
                          status_url=f"/runs/{run_id}", events_url=f"/runs/{run_id}/events")

    @app.get("/settings")
    def get_settings():
        return settings.load()

    @app.put("/settings")
    def put_settings(s: Settings):
        return settings.save(s.model_dump())

    @app.post("/recommend")
    def recommend_config(req: RecommendRequest):
        rec = recommend(req.repo, req.target)
        avg = cost_report(ledger)["totals"]["avg_cost_per_run"]   # tie-in to real spend
        if avg and avg > 0:
            rec["rationale"] += f" (Your real runs so far average ${avg:.2f}.)"
        return rec

    @app.get("/models")
    def models():
        """Available backends, their selectable models, and the token-cost price table — so the UI
        can offer model pickers and show cost estimates instead of free-text guessing."""
        from argo.config import (DEFAULT_STAGE_MODELS, HAIKU, MODEL_PRICING, OPUS, SONNET,
                                 _codex_default_model)
        return {
            "backends": [
                {"id": "mock", "label": "Mock (free)", "cost": "free", "models": []},
                {"id": "headless", "label": "Claude Code", "cost": "authoritative (USD per call)",
                 "models": [{"id": OPUS, "label": "Opus 4.8"}, {"id": SONNET, "label": "Sonnet 4.6"},
                            {"id": HAIKU, "label": "Haiku 4.5"}]},
                {"id": "codex", "label": "Codex CLI (OpenAI / open-source)",
                 "cost": "estimated (token-based)", "default": _codex_default_model(),
                 "oss_providers": ["ollama", "lmstudio"],
                 "models": [{"id": "gpt-5.5"}, {"id": "gpt-5-codex"}, {"id": "o4-mini"}, {"id": "o3"}]},
            ],
            "default_stage_models": DEFAULT_STAGE_MODELS,
            "pricing": [{"model": k, "input_per_mtok": v[0], "output_per_mtok": v[1]}
                        for k, v in sorted(MODEL_PRICING.items())],
        }

    @app.get("/benchmark")
    def benchmark():
        """The latest benchmark report (Phase 7), or null. Benchmarks are run from the CLI
        (`argo bench`) — real runs cost money — and surfaced here read-only."""
        return _read_json(runs_dir / "benchmark_report.json")

    @app.get("/benchmark/ab")
    def benchmark_ab():
        return _read_json(runs_dir / "benchmark_ab_report.json")

    @app.get("/costs")
    def costs():
        """Observed cost analytics from the ledger (Phase 8), grouped by archetype when known."""
        return cost_report(ledger, run_archetypes=_run_archetypes())

    def _run_archetypes() -> dict:
        """Map run_id -> canonical archetype, read from each run's meta.json."""
        mapping = {}
        if runs_dir.exists():
            for rd in runs_dir.iterdir():
                if not rd.is_dir():
                    continue
                arch = (_read_json(rd / "meta.json") or {}).get("archetype")
                if arch:
                    mapping[rd.name] = arch
        return mapping

    @app.get("/runs")
    def list_runs():
        out = []
        if runs_dir.exists():
            for rd in runs_dir.iterdir():
                if not rd.is_dir():
                    continue
                st = read_status(rd)
                meta = _read_json(rd / "meta.json") or {}
                if st is None and not meta:
                    continue
                out.append({
                    "run_id": rd.name,
                    "state": (st or {}).get("state", "unknown"),
                    "program_name": meta.get("program_name"),
                    "target_type": meta.get("target_type"),
                    "archetype": meta.get("archetype"),
                    "cost_usd": round(_safe_cost(rd.name), 6),
                    "started_at": (st or {}).get("started_at"),
                })
        out.sort(key=lambda r: (r.get("started_at") or ""), reverse=True)
        return out

    def _safe_cost(run_id: str) -> float:
        try:
            return ledger.run_cost(run_id)
        except Exception:
            return 0.0

    @app.get("/runs/{run_id}")
    def get_run(run_id: str):
        return _status(run_id)

    @app.post("/runs/{run_id}/cancel")
    def cancel_run(run_id: str):
        _run_dir(run_id)
        ok = jobs.cancel(run_id)
        return {"run_id": run_id, "cancel_requested": ok}

    @app.get("/runs/{run_id}/events")
    async def events(run_id: str):
        _run_dir(run_id)

        async def gen():
            last = None
            ticks = 0
            while ticks < 7200:  # ~1h safety cap at 0.5s/tick
                st = _status(run_id)
                payload = json.dumps(st)
                if payload != last:
                    yield f"data: {payload}\n\n"
                    last = payload
                if st.get("state") in _TERMINAL:
                    break
                ticks += 1
                await asyncio.sleep(0.5)

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.get("/runs/{run_id}/report", response_class=PlainTextResponse)
    def get_report(run_id: str):
        rd = _run_dir(run_id)
        report = rd / "REPORT.md"
        if not report.exists():
            raise HTTPException(status_code=404, detail="REPORT.md not ready")
        return PlainTextResponse(report.read_text(encoding="utf-8"), media_type="text/markdown")

    @app.get("/runs/{run_id}/artifacts/{name}")
    def get_artifact(run_id: str, name: str):
        rd = _run_dir(run_id)
        rel = _SINGLE_ARTIFACTS.get(name)
        if rel is None:
            raise HTTPException(status_code=404, detail=f"unknown artifact '{name}'")
        path = rd / rel
        if not path.exists():
            raise HTTPException(status_code=404, detail=f"{rel} not ready")
        if path.suffix == ".json":
            return _read_json(path)
        return PlainTextResponse(path.read_text(encoding="utf-8"))

    @app.get("/runs/{run_id}/prompts")
    def get_prompts(run_id: str):
        rd = _run_dir(run_id)
        pd = rd / "prompts"
        if not pd.exists():
            return []
        return [{"name": p.name, "content": p.read_text(encoding="utf-8")}
                for p in sorted(pd.glob("audit_*.md"))]

    @app.get("/runs/{run_id}/findings")
    def get_findings(run_id: str):
        """Per-focus raw findings (Stage 3). For the canonical merged+validated set use the
        ``validated_findings`` artifact."""
        rd = _run_dir(run_id)
        fd = rd / "findings"
        if not fd.exists():
            return []
        return [{"focus_file": p.name, **(_read_json(p) or {})} for p in sorted(fd.glob("*.json"))]

    @app.get("/runs/{run_id}/drafts")
    def get_drafts(run_id: str):
        rd = _run_dir(run_id)
        dd = rd / "submission_drafts"
        if not dd.exists():
            return []
        return [{"name": p.name, "content": p.read_text(encoding="utf-8")}
                for p in sorted(dd.glob("*.md"))]

    @app.get("/runs/{run_id}/generated")
    def get_generated(run_id: str):
        """Files the chat analyst generated (e.g. test suites). Written to runs/<id>/generated/,
        never into the target repo."""
        rd = _run_dir(run_id)
        gd = rd / "generated"
        if not gd.exists():
            return []
        return [{"name": p.name, "content": p.read_text(encoding="utf-8", errors="replace")}
                for p in sorted(gd.glob("*")) if p.is_file()]

    # -- chat (Phase 3) ---------------------------------------------------------------
    @app.get("/runs/{run_id}/chat")
    def get_chat(run_id: str):
        rd = _run_dir(run_id)
        return ChatStore(rd / "chat.jsonl").messages()

    @app.post("/runs/{run_id}/chat")
    def post_chat(run_id: str, body: ChatMessage):
        rd = _run_dir(run_id)
        if not (rd / "scope.json").exists():
            raise HTTPException(status_code=409, detail="run has no scope yet — wait for ingest")
        ctx = _chat_ctx(run_id)
        try:
            return chat_engine.ask(ctx, body.message)
        finally:
            try:
                ctx.ledger.close()
            except Exception:
                pass

    # -- fixes / remediation (Phase 6) ------------------------------------------------
    @app.get("/runs/{run_id}/fixes")
    def get_fixes(run_id: str):
        """The fixes report (fixes_report.json), or null if no fixes were generated yet."""
        rd = _run_dir(run_id)
        return _read_json(rd / "fixes_report.json")

    @app.get("/runs/{run_id}/patches")
    def get_patches(run_id: str):
        """Proposed fix patches (unified diffs) under runs/<id>/patches/."""
        rd = _run_dir(run_id)
        pd = rd / "patches"
        if not pd.exists():
            return []
        return [{"name": p.name, "content": p.read_text(encoding="utf-8", errors="replace")}
                for p in sorted(pd.glob("*.diff"))]

    @app.post("/runs/{run_id}/fixes")
    def post_fixes(run_id: str, body: FixRequest):
        """Generate + verify a proposed patch per confirmed finding. The target repo stays
        read-only; verification runs on an isolated copy."""
        rd = _run_dir(run_id)
        if not (rd / "validated_findings.json").exists():
            raise HTTPException(status_code=409,
                                detail="no validated findings yet — finish the audit pipeline first")
        ctx = _chat_ctx(run_id)   # same runner/model resolution as the original run
        try:
            return generate_fixes(ctx, verify=body.verify, docker=body.docker,
                                  build_cmd=body.build_cmd,
                                  only=set(body.only) if body.only else None,
                                  re_audit=body.re_audit)
        finally:
            try:
                ctx.ledger.close()
            except Exception:
                pass

    # -- web UI (Phase 1): serve the no-build SPA from webapp/ -----------------------
    webapp_dir = Path(__file__).resolve().parent.parent / "webapp"
    if (webapp_dir / "index.html").exists():
        @app.get("/", include_in_schema=False)
        def _index():
            return RedirectResponse("/app/")
        app.mount("/app", StaticFiles(directory=str(webapp_dir), html=True), name="webapp")

    app.state.jobs = jobs
    app.state.ledger = ledger
    app.state.config = cfg
    return app


# Run with the CLI (`python -m argo.cli serve`, or `argo serve` after `pip install -e .`) or:
#   uvicorn --factory server.app:create_app
# We deliberately do NOT create a module-level app() here, to avoid opening the default ledger
# as an import side effect (which would pollute tests).
