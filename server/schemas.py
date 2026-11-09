"""Request/response models for the HTTP API."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class RunConfig(BaseModel):
    """The subset of PipelineConfig a client may set per run. Defaults are deliberately safe:
    ``runner="mock"`` means a request spends **zero tokens** unless the client opts into
    ``headless``."""
    runner: str = Field("mock", description='"mock" (free) · "headless" (Claude Code) · "codex" (Codex CLI / OpenAI / OSS) · "gemini" (Gemini CLI) · "mistral-api" (Mistral API, Argo tool loop) · "mistral-vibe" (Mistral Vibe CLI)')
    budget_usd: Optional[float] = Field(None, description="per-run USD ceiling: no new session launches once spend reaches it")
    audit_model: Optional[str] = Field(None, description="override the Stage-3 audit model")
    calibration: bool = Field(False, description="run audit on Opus (all-Opus)")
    parallel: int = Field(3, ge=1, le=16, description="max concurrent audit/validate sessions")
    models: dict[str, str] = Field(default_factory=dict,
                                   description="per-stage model overrides {ingest,recon,audit,validate,report}")
    stage_runners: dict[str, str] = Field(default_factory=dict,
                                         description="per-stage backend overrides")
    stage_effort: dict[str, str] = Field(default_factory=dict,
                                         description="Claude-only per-stage effort settings")
    profile: Optional[str] = Field(None, description="credential-free routing profile")
    allow_model_substitution: bool = Field(False, description="allow requested/served model mismatch")
    codex_model: Optional[str] = Field(None, description="(runner=codex) model id; omit for the Codex CLI default")
    codex_oss: bool = Field(False, description="(runner=codex) use the open-source provider")
    codex_local_provider: Optional[str] = Field(None, description="(runner=codex+oss) ollama | lmstudio")
    gemini_model: Optional[str] = Field(
        None, description="(runner=gemini) flat model override across every stage, e.g. "
                          "gemini-3.1-pro; omit to use the built-in per-stage tiering")
    gemini_api_key: Optional[str] = Field(
        None, description="(runner=gemini) GEMINI_API_KEY for this run; omit to use the ambient "
                          "env var / existing gemini CLI login. Never echoed back or persisted in "
                          "the clear (see PipelineConfig._SECRET_FIELDS redaction).")
    claude_api_key: Optional[str] = Field(
        None, description="(runner=headless) ANTHROPIC_API_KEY for this run; omit to use the "
                          "ambient env var / existing Claude Code subscription login. Never "
                          "echoed back or persisted in the clear (see "
                          "PipelineConfig._SECRET_FIELDS redaction).")
    codex_api_key: Optional[str] = Field(
        None, description="(runner=codex) OpenAI API key for this run; Argo bootstraps a "
                          "dedicated cached CODEX_HOME for it via `codex login --with-api-key` on "
                          "first use (a bare env var alone does not authenticate codex exec). "
                          "Never echoed back or persisted in the clear (see "
                          "PipelineConfig._SECRET_FIELDS redaction).")
    mistral_api_model: Optional[str] = Field(
        None, description="(runner=mistral-api) model id for every stage; default mistral-large-4")
    mistral_vibe_model: Optional[str] = Field(
        None, description="(runner=mistral-vibe) Vibe model alias; default mistral-medium-3.5")
    mistral_vibe_auth: Literal["key", "stored"] = Field(
        "key", description="Vibe authentication: key (legacy API-key sources) or stored "
                           "(Vibe credentials for the server process's OS account; billing unknown)")
    mistral_api_key: Optional[str] = Field(
        None, description="(runner=mistral-api) Mistral API key for this run; omit to use "
                          "ARGO_MISTRAL_API_KEY / MISTRAL_API_KEY. Never echoed back or persisted "
                          "in the clear (see PipelineConfig._SECRET_FIELDS redaction).")
    mistral_vibe_api_key: Optional[str] = Field(
        None, description="(runner=mistral-vibe) key for the Vibe CLI; omit to use "
                          "ARGO_MISTRAL_VIBE_API_KEY / the mistral-api key. Never echoed back or "
                          "persisted in the clear.")
    research_enabled: Optional[bool] = Field(
        None, description="override the Stage-1 web research default (Mistral runners need false)")
    corroborate_enabled: Optional[bool] = Field(
        None, description="override the networked corroboration default (Mistral runners need false)")
    review_questions_enabled: Optional[bool] = Field(
        None, description="emit the private, non-blocking architecture review-question queue (F5); "
                          "answer it later via POST /runs/{id}/questions/{qid}/answer")
    # NOTE: no claude_api_keys/codex_api_keys here, deliberately -- mirrors gemini_accounts' own
    # absence from RunConfig. Multi-account fallback chains are a CLI concept (one process, many
    # accounts); one HTTP request = one run = one identity.


class Settings(BaseModel):
    """Persisted UI defaults (Phase 2)."""
    runner: str = "mock"
    budget_usd: Optional[float] = None
    parallel: int = Field(3, ge=1, le=16)
    audit_model: Optional[str] = None
    calibration: bool = False
    models: dict[str, str] = Field(default_factory=dict)


class RecommendRequest(BaseModel):
    repo: Optional[str] = None
    target: str = Field("standard", description="quick | standard | thorough")


class ScreenRequest(BaseModel):
    target: str = Field(..., min_length=1, description="local repository directory")
    rescreen: bool = False


class PlanRequest(ScreenRequest):
    objective: str = "balanced"
    max_cost: Optional[float] = Field(None, ge=0)
    max_duration_minutes: Optional[int] = Field(None, ge=1)


class ChatMessage(BaseModel):
    message: str = Field(..., min_length=1)


class FixRequest(BaseModel):
    """Phase 6 — propose + verify fixes for a run's confirmed findings."""
    model_config = {"extra": "forbid"}
    verify: bool = Field(True, description="apply each patch to an isolated copy and check it "
                                           "compiles + introduces no new errors")
    # docker / build_cmd are deliberately absent: choosing a shell command or image to run on the
    # host is CLI-only (`argo fix --docker/--build-cmd`), never an HTTP parameter.
    only: Optional[list[str]] = Field(None, description="finding ids to fix (default: all confirmed)")
    re_audit: bool = Field(False, description="also re-audit each patched copy to check the vuln is "
                                              "gone (one extra model session per patch; needs verify)")


class RunRequest(BaseModel):
    brief: Optional[str] = Field(None, description="program description / brief text. OMIT (or empty) "
                                                  "for a local/personal source-only review of --repo.")
    repo: str = Field(..., min_length=1, description="codebase to analyze: a local folder path or a git URL")
    links: Optional[str] = Field(None, description="curated reference links, one http(s) URL per line")
    dry_run: bool = Field(False, description="ingest + recon only, then stop before any audit")
    research: bool = Field(True, description="Stage-1 web OSINT before recon (the only networked "
                                            "stage; never the live in-scope hosts). Set false to "
                                            "keep the run fully offline.")
    config: RunConfig = Field(default_factory=RunConfig)


class RunCreated(BaseModel):
    run_id: str
    state: str
    status_url: str
    events_url: str


class StageStatus(BaseModel):
    model_config = {"extra": "allow"}
    name: str
    state: str


class RunStatus(BaseModel):
    model_config = {"extra": "allow"}
    run_id: str
    state: str
    current_stage: Optional[str] = None
    stages: list[StageStatus] = Field(default_factory=list)
    artifacts: dict = Field(default_factory=dict)
    cost_usd: float = 0.0
    error: Optional[str] = None


class RunSummary(BaseModel):
    run_id: str
    state: str
    program_name: Optional[str] = None
    target_type: Optional[str] = None
    cost_usd: float = 0.0
    started_at: Optional[str] = None


class QuestionAnswer(BaseModel):
    """F5: a provenance-bearing answer to one private review question (no model call)."""
    answer: str = Field(..., min_length=1, max_length=2000,
                        description="concise architecture/business answer")
    provenance: str = Field(..., min_length=1, max_length=500,
                            description="where the answer came from (owner, document, ticket, ...)")


class ContextRevalidationRequest(BaseModel):
    """F5: re-validate only findings made stale by answered review questions (model calls)."""
    question: Optional[str] = Field(None, pattern=r"^rq:[0-9a-f]{16}$",
                                    description="only findings affected by this answered question")
    budget_usd: Optional[float] = Field(None, gt=0, description="spend cap for this re-validation")
