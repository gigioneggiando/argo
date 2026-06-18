"""Request/response models for the HTTP API."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class RunConfig(BaseModel):
    """The subset of PipelineConfig a client may set per run. Defaults are deliberately safe:
    ``runner="mock"`` means a request spends **zero tokens** unless the client opts into
    ``headless``."""
    runner: str = Field("mock", description='"mock" (free) · "headless" (Claude Code) · "codex" (Codex CLI / OpenAI / OSS)')
    budget_usd: Optional[float] = Field(None, description="hard per-run USD ceiling")
    audit_model: Optional[str] = Field(None, description="override the Stage-3 audit model")
    calibration: bool = Field(False, description="run audit on Opus (all-Opus)")
    parallel: int = Field(3, ge=1, le=16, description="max concurrent audit/validate sessions")
    models: dict[str, str] = Field(default_factory=dict,
                                   description="per-stage model overrides {ingest,recon,audit,validate,report}")
    codex_model: Optional[str] = Field(None, description="(runner=codex) model id; omit for the Codex CLI default")
    codex_oss: bool = Field(False, description="(runner=codex) use the open-source provider")
    codex_local_provider: Optional[str] = Field(None, description="(runner=codex+oss) ollama | lmstudio")


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


class ChatMessage(BaseModel):
    message: str = Field(..., min_length=1)


class FixRequest(BaseModel):
    """Phase 6 — propose + verify fixes for a run's confirmed findings."""
    verify: bool = Field(True, description="apply each patch to an isolated copy and check it "
                                           "compiles + introduces no new errors")
    docker: Optional[str] = Field(None, description="run the build/compile check in this Docker "
                                                    "image (offline)")
    build_cmd: Optional[str] = Field(None, description="explicit build command for verification")
    only: Optional[list[str]] = Field(None, description="finding ids to fix (default: all confirmed)")


class RunRequest(BaseModel):
    brief: Optional[str] = Field(None, description="program description / brief text. OMIT (or empty) "
                                                  "for a local/personal source-only review of --repo.")
    repo: str = Field(..., min_length=1, description="codebase to analyze: a local folder path or a git URL")
    links: Optional[str] = Field(None, description="curated reference links, one http(s) URL per line")
    dry_run: bool = Field(False, description="ingest + recon only, then stop before any audit")
    research: bool = Field(True, description="Stage-0 web OSINT before recon (the only networked "
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
