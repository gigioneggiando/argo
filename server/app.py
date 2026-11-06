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
never exposed. Intended for localhost. Every API route needs the per-process access token (the
`argo_token` cookie set by opening the URL `argo serve` prints, or an `X-Argo-Token` header), the
Host header must name a loopback address (DNS-rebinding guard), and there is no CORS: a web page
on another origin can neither read responses nor send the cookie (SameSite=Strict).
"""

from __future__ import annotations

import asyncio
import hmac
import re
import secrets
import json
import queue
import shutil
import threading
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi import Request
from fastapi.responses import (JSONResponse, PlainTextResponse, RedirectResponse,
                               StreamingResponse)
from fastapi.staticfiles import StaticFiles

from argo import __version__
from argo import chat as chat_engine
from argo.archetype import run_archetypes
from argo.chat import ChatStore
from argo.costs import cost_report
from argo.fixes import generate_fixes
from argo.knowledge import load_vuln_index
from argo.config import PipelineConfig, load_pipeline_config
from argo.ledger import Ledger
from argo.orchestrator import (build_context, do_context_revalidation, do_evidence, do_report,
                               do_review_questions, new_run_id)
from argo.progress import read_status
from argo.stages import review_questions as review_questions_stage

from .jobs import JobManager
from .recommend import recommend
from .uploads import UnsafeZip, extract_zip
from .schemas import (ChatMessage, ContextRevalidationRequest, FixRequest, PlanRequest,
                      QuestionAnswer, RecommendRequest, RunCreated, RunRequest, ScreenRequest,
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
    "incremental_review": "incremental_review.json",
    "attack_paths": "attack_paths.json",
    "report": "REPORT.md",
    "meta": "meta.json",
    "status": "status.json",
    "brief": "brief.txt",
    "fixes_report": "fixes_report.json",
}
_TERMINAL = {"completed", "failed", "cancelled"}
#: Same shape RunContext accepts: a single path component, never "." / ".." / a separator / drive.
_RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")  # == RunContext.__post_init__
#: Hostnames a browser may use to reach the local server (anything else = DNS rebinding / proxy).
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
#: Reachable without the token: the login redirect, liveness and the static SPA shell (no data).
_PUBLIC_PREFIXES = ("/app", "/health")
TOKEN_COOKIE = "argo_token"
TOKEN_HEADER = "x-argo-token"


def _host_name(host_header: str) -> str:
    host = (host_header or "").strip().lower()
    if host.startswith("["):                       # [::1]:8000
        return host[1:].split("]", 1)[0]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def create_app(base_config: PipelineConfig | None = None, *, token: str | None = None,
               allowed_hosts: set[str] | None = None) -> FastAPI:
    """Build the app. ``token`` is the per-process secret every API call must present (a random
    one is generated when omitted; ``argo serve`` prints it inside the URL it opens).
    ``allowed_hosts`` extends the loopback names accepted in the Host header (e.g. a non-default
    ``--host`` the operator chose deliberately)."""
    cfg = base_config or PipelineConfig()
    access_token = token or secrets.token_urlsafe(32)
    hosts = _LOOPBACK_HOSTS | {h.lower() for h in (allowed_hosts or set())}
    runs_dir = Path(cfg.runs_dir)
    jobs = JobManager(cfg)
    ledger = Ledger(cfg.ledger_path)  # read-side: live per-run cost
    settings = SettingsStore(Path(cfg.ledger_path).with_name("app_settings.json"))

    app = FastAPI(title="Argo — source-static bug-bounty audits", version=__version__)

    @app.middleware("http")
    async def _guard(request: Request, call_next):
        # 1) DNS rebinding: a foreign hostname that resolves to 127.0.0.1 is still a foreign origin.
        if _host_name(request.headers.get("host", "")) not in hosts:
            return JSONResponse({"detail": "forbidden host"}, status_code=403)
        path = request.url.path
        # 2) Token login: GET /?token=... sets the cookie and lands on the UI.
        if path == "/" and request.query_params.get("token"):
            if not hmac.compare_digest(request.query_params["token"], access_token):
                return JSONResponse({"detail": "invalid token"}, status_code=401)
            resp = RedirectResponse("/app/", status_code=303)
            resp.set_cookie(TOKEN_COOKIE, access_token, httponly=True, samesite="strict",
                            path="/")
            return resp
        public = path == "/" or any(path == p or path.startswith(p + "/") for p in _PUBLIC_PREFIXES)
        if not public:
            presented = request.headers.get(TOKEN_HEADER) or request.cookies.get(TOKEN_COOKIE) or ""
            if not hmac.compare_digest(presented, access_token):
                return JSONResponse(
                    {"detail": "missing or invalid access token: open the URL printed by "
                               "`argo serve`, or send the X-Argo-Token header"},
                    status_code=401)
        response = await call_next(request)
        if path.startswith("/app"):
            # Defence in depth for model/repo-controlled text rendered in the UI: no inline or
            # foreign scripts, no plugins, no framing.
            response.headers["Content-Security-Policy"] = (
                "script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
            response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    # -- helpers -------------------------------------------------------------------
    def _run_dir(run_id: str) -> Path:
        # run_id comes from the URL: accept only a single safe path component, then make sure the
        # resolved directory really is a child of runs_dir (no "..", separators or drive letters).
        if not _RUN_ID_RE.fullmatch(run_id or "") or run_id in {".", ".."}:
            raise HTTPException(status_code=404, detail="run not found")
        rd = runs_dir / run_id
        try:
            inside = rd.resolve().parent == runs_dir.resolve()
        except OSError:
            inside = False
        if not inside or not rd.exists():
            raise HTTPException(status_code=404, detail=f"run {run_id} not found")
        return rd

    def _status(run_id: str) -> dict:
        rd = _run_dir(run_id)
        st = read_status(rd) or {"run_id": run_id, "state": "unknown",
                                 "stages": [], "artifacts": {}, "cost_usd": 0.0}
        meta = _read_json(rd / "meta.json") or {}
        st["runner"] = meta.get("runner")
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
        try:
            run_id = jobs.start(req)
        except ValueError as exc:                # invalid routing/config: the client's fault
            raise HTTPException(status_code=400, detail=str(exc))
        return RunCreated(run_id=run_id, state="running",
                          status_url=f"/runs/{run_id}", events_url=f"/runs/{run_id}/events")

    @app.post("/uploads")
    def upload_repo(file: UploadFile = File(...)):
        """C3: upload a `.zip` of a repo instead of typing a path. It is safely extracted to a
        staging dir under runs_dir; the returned `repo` path is then used in a normal `POST /runs`
        (ingest copies it read-only, like any local folder). The target stays read-only; nothing
        here executes the uploaded code."""
        if not (file.filename or "").lower().endswith(".zip"):
            raise HTTPException(status_code=400, detail="only .zip uploads are supported")
        staging = runs_dir / "_uploads" / new_run_id()
        try:
            info = extract_zip(file.file, staging)
        except UnsafeZip as exc:
            shutil.rmtree(staging, ignore_errors=True)
            raise HTTPException(status_code=400, detail=f"rejected upload: {exc}")
        except Exception as exc:                       # pragma: no cover - defensive
            shutil.rmtree(staging, ignore_errors=True)
            raise HTTPException(status_code=400, detail=f"could not read upload: {exc}")
        return {"repo": info["path"], "files": info["files"],
                "name": Path(file.filename).stem}

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

    @app.post("/screen")
    def screen(req: ScreenRequest):
        from argo.screening import screen_target
        try:
            return screen_target(req.target, cache_dir=runs_dir / ".screen-cache", rescreen=req.rescreen)
        except (ValueError, OSError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/plan")
    def plan(req: PlanRequest):
        from argo.planner import make_plan
        from argo.screening import screen_target
        try:
            fp = screen_target(req.target, cache_dir=runs_dir / ".screen-cache", rescreen=req.rescreen)
            return make_plan(fp, cfg, objective=req.objective, max_cost=req.max_cost,
                             max_duration_minutes=req.max_duration_minutes)
        except (ValueError, OSError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/models")
    def models():
        """Available backends, their selectable models, and the token-cost price table — so the UI
        can offer model pickers and show cost estimates instead of free-text guessing."""
        import shutil
        from argo.config import (DEFAULT_CODEX_STAGE_MODELS, DEFAULT_GEMINI_STAGE_MODELS,
                                 DEFAULT_STAGE_MODELS, MISTRAL_API_BALANCED, MISTRAL_VIBE_DEFAULT,
                                 MODEL_PRICING)
        from argo.model_catalog import catalog_by_provider, catalog_snapshot
        return {
            "backends": [
                {"id": "mock", "label": "Demo (synthetic)", "cost": "free", "models": []},
                {"id": "headless", "label": "Claude Code", "cost": "authoritative (USD per call)",
                 "models": [{**s.__dict__, "id": s.model_id} for s in catalog_by_provider("anthropic")]},
                {"id": "codex", "label": "Codex CLI (OpenAI / open-source)",
                 "cost": "estimated (token-based)", "default_stage_models": DEFAULT_CODEX_STAGE_MODELS,
                 "oss_providers": ["ollama", "lmstudio"],
                 "models": [{**s.__dict__, "id": s.model_id} for s in catalog_by_provider("openai")]},
                {"id": "gemini", "label": "Gemini CLI", "cost": "estimated (token-based)",
                 "models": [{**s.__dict__, "id": s.model_id} for s in catalog_by_provider("gemini")]},
                {"id": "mistral-api", "label": "Mistral API",
                 "cost": "estimated (token-based; unknown for unpriced models)",
                 "default_model": MISTRAL_API_BALANCED, "offline_only": True,
                 "key_env": ["ARGO_MISTRAL_API_KEY", "MISTRAL_API_KEY"],
                 "models": [{**s.__dict__, "id": s.model_id} for s in catalog_by_provider("mistral")]},
                {"id": "mistral-vibe", "label": "Mistral Vibe CLI",
                 "cost": "Vibe estimate (provider_estimated)",
                 "default_model": MISTRAL_VIBE_DEFAULT, "offline_only": True,
                 "installed": shutil.which("vibe") is not None,
                 "key_env": ["ARGO_MISTRAL_VIBE_API_KEY", "ARGO_MISTRAL_API_KEY", "MISTRAL_API_KEY"],
                 "models": [{**s.__dict__, "id": s.model_id} for s in catalog_by_provider("mistral")
                            if s.cli_available]},
            ],
            "default_stage_models": DEFAULT_STAGE_MODELS,
            "default_gemini_stage_models": DEFAULT_GEMINI_STAGE_MODELS,
            "default_codex_stage_models": DEFAULT_CODEX_STAGE_MODELS,
            "catalog": catalog_snapshot(),
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

    @app.get("/benchmark/cross")
    def benchmark_cross():
        """The latest cross-backend comparison (`argo bench-cross`), or null. Read-only, same
        pattern as /benchmark and /benchmark/ab — the real run is a CLI-only, cost-bearing action."""
        return _read_json(runs_dir / "benchmark_crossbackend_report.json")

    @app.get("/refusal-probe")
    def refusal_probe_report():
        """The latest refusal-rate comparison (`argo refusal-probe`), or null."""
        return _read_json(runs_dir / "refusal_probe_report.json")

    @app.get("/costs")
    def costs():
        """Observed cost analytics from the ledger (Phase 8), grouped by archetype when known."""
        return cost_report(ledger, run_archetypes=run_archetypes(runs_dir))

    @app.get("/quality")
    def quality():
        """A2: real-world triager accept-rate (precision proxy) paired with benchmark recall.
        Fields are null/empty until feedback is recorded (via `argo feedback`) and a benchmark
        has been run."""
        from argo.quality import quality_report
        bench = runs_dir / "benchmark_report.json"
        return quality_report(ledger, benchmark_report_path=bench if bench.exists() else None)

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
                    "runner": meta.get("runner"),
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

    @app.post("/runs/{run_id}/chat/stream")
    def post_chat_stream(run_id: str, body: ChatMessage):
        """One chat turn as NDJSON: ``{"type":"activity","text":...}`` lines while the analyst
        works (tool calls / interim messages, on backends that expose them), then one
        ``{"type":"done", ...}`` line with the same payload as ``POST /runs/{id}/chat`` (or
        ``{"type":"error","detail":...}``). Same guardrails and ledger logging as the plain call."""
        rd = _run_dir(run_id)
        if not (rd / "scope.json").exists():
            raise HTTPException(status_code=409, detail="run has no scope yet — wait for ingest")
        events: queue.Queue = queue.Queue()

        def turn() -> None:
            ctx = _chat_ctx(run_id)
            try:
                result = chat_engine.ask(
                    ctx, body.message, on_activity=lambda t: events.put({"type": "activity", "text": t}))
                events.put({"type": "done", **result})
            except Exception as exc:  # noqa: BLE001 -- surfaced to the client, not swallowed
                events.put({"type": "error", "detail": str(exc)[:500]})
            finally:
                try:
                    ctx.ledger.close()
                except Exception:
                    pass
                events.put(None)

        threading.Thread(target=turn, name=f"chat-{run_id}", daemon=True).start()

        def lines():
            while (ev := events.get()) is not None:
                yield json.dumps(ev) + "\n"

        return StreamingResponse(lines(), media_type="application/x-ndjson",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

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
            # build_cmd / docker are CLI-only (`argo fix`): an HTTP caller must never choose a
            # shell command or image to run on the host.
            return generate_fixes(ctx, verify=body.verify, docker=None, build_cmd=None,
                                  only=set(body.only) if body.only else None,
                                  re_audit=body.re_audit)
        finally:
            try:
                ctx.ledger.close()
            except Exception:
                pass

    # -- private review questions (F5) -----------------------------------------------
    def _saved_ctx(run_id: str):
        """RunContext from the run's persisted config.json (same as ``argo resume``), so answers
        and re-validation use the backend/models the run was executed with."""
        rd = _run_dir(run_id)
        config_path = rd / "config.json"
        if not config_path.is_file():
            raise HTTPException(status_code=409, detail="run predates config persistence")
        run_cfg = load_pipeline_config(config_path)
        if Path(run_cfg.runs_dir).resolve() != runs_dir.resolve():
            run_cfg = run_cfg.with_overrides(runs_dir=runs_dir)
        return build_context(run_cfg, run_id)

    def _require_finished(run_id: str) -> None:
        if _status(run_id).get("state") not in _TERMINAL:
            raise HTTPException(status_code=409, detail="run is still active; wait for it to finish")

    def _close(ctx) -> None:
        try:
            ctx.ledger.close()
        except Exception:
            pass

    @app.get("/runs/{run_id}/questions")
    def get_questions(run_id: str):
        """The private review-question queue (review_questions.json), or null if none."""
        return _read_json(_run_dir(run_id) / "review_questions.json")

    @app.post("/runs/{run_id}/questions")
    def post_questions(run_id: str):
        """(Re)build the question queue for a finished run, like ``argo questions``. Deterministic,
        no model call; existing answers are preserved."""
        _require_finished(run_id)
        if not (_run_dir(run_id) / "validated_findings.json").is_file():
            raise HTTPException(status_code=409, detail="no validated findings yet")
        ctx = _saved_ctx(run_id)
        _close(ctx)
        ctx = build_context(ctx.config.with_overrides(review_questions_enabled=True), run_id)
        try:
            do_review_questions(ctx)
            if (ctx.run_dir / "REPORT.md").is_file():
                do_report(ctx)
        finally:
            _close(ctx)
        return _read_json(ctx.review_questions_path)

    @app.post("/runs/{run_id}/questions/{question_id}/answer")
    def post_question_answer(run_id: str, question_id: str, body: QuestionAnswer):
        """Record a provenance-bearing answer (no model call). Affected verdicts become stale and
        their drafts are withheld until ``POST /runs/{id}/revalidate-context``."""
        _require_finished(run_id)
        if not (_run_dir(run_id) / "review_questions.json").is_file():
            raise HTTPException(status_code=404, detail="this run has no review questions")
        ctx = _saved_ctx(run_id)
        try:
            review_questions_stage.answer(ctx, question_id, body.answer, body.provenance)
            if (ctx.run_dir / "REPORT.md").is_file():
                do_report(ctx)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            _close(ctx)
        return _read_json(ctx.review_questions_path)

    @app.post("/runs/{run_id}/revalidate-context")
    def post_revalidate_context(run_id: str, body: ContextRevalidationRequest):
        """Re-validate only the findings made stale by answered questions (spends model calls on
        the run's backend; a mock run is free). Unrelated findings are untouched."""
        _require_finished(run_id)
        ctx = _saved_ctx(run_id)
        if body.budget_usd is not None:
            _close(ctx)
            ctx = build_context(ctx.config.with_overrides(budget_usd=body.budget_usd), run_id)
        try:
            summary = do_context_revalidation(ctx, question_id=body.question)
            do_evidence(ctx)
            if ctx.review_questions_path.is_file():
                do_review_questions(ctx)
            if (ctx.run_dir / "REPORT.md").is_file():
                do_report(ctx)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            _close(ctx)
        return {**summary, "questions": _read_json(ctx.review_questions_path)}

    # -- web UI (Phase 1): serve the no-build SPA from webapp/ -----------------------
    webapp_dir = Path(__file__).resolve().parent.parent / "webapp"
    if (webapp_dir / "index.html").exists():
        @app.get("/", include_in_schema=False)
        def _index():
            return RedirectResponse("/app/")
        app.mount("/app", StaticFiles(directory=str(webapp_dir), html=True), name="webapp")

    app.state.jobs = jobs
    app.state.access_token = access_token
    app.state.ledger = ledger
    app.state.config = cfg
    return app


# Run with the CLI (`python -m argo.cli serve`, or `argo serve` after `pip install -e .`) or:
#   uvicorn --factory server.app:create_app
# We deliberately do NOT create a module-level app() here, to avoid opening the default ledger
# as an import side effect (which would pollute tests).
