"""Portable routing profiles.  Profiles contain no credentials and expand to PipelineConfig data."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import (CODEX_BALANCED, CODEX_CHEAP, CODEX_TOP, DEFAULT_CODEX_STAGE_MODELS,
                     DEFAULT_GEMINI_STAGE_MODELS, DEFAULT_STAGE_MODELS, GEMINI_ARGON, GEMINI_CHEAP,
                     HAIKU, OPUS, SONNET, PipelineConfig)

_PROFILE_NAMES = ("balanced", "maximum-quality", "cost-saver", "diverse-validation", "smoke")


def profile_data(name: str) -> dict[str, Any]:
    name = name.lower()
    base = {"name": name, "version": 1, "routing_basis": {"status": "provisional",
            "sample_count": 0, "note": "built-in defaults until labeled benchmark evidence is sufficient"},
            "stage_runners": {}, "stage_models": {},
            "codex_stage_models": {}, "gemini_stage_models": {}, "flags": {}}
    if name == "balanced":
        return base
    if name == "maximum-quality":
        base["codex_stage_models"] = {k: CODEX_TOP for k in DEFAULT_CODEX_STAGE_MODELS}
        base["stage_models"] = {k: OPUS for k in DEFAULT_STAGE_MODELS}
        base["gemini_stage_models"] = {k: GEMINI_ARGON for k in DEFAULT_GEMINI_STAGE_MODELS}
        base["flags"] = {"verify_enabled": True, "corroborate_enabled": True}
        return base
    if name == "cost-saver":
        base["codex_stage_models"] = {k: CODEX_CHEAP for k in DEFAULT_CODEX_STAGE_MODELS}
        base["stage_models"] = {k: HAIKU for k in DEFAULT_STAGE_MODELS}
        base["stage_models"]["recon"] = SONNET
        base["gemini_stage_models"] = {k: GEMINI_CHEAP for k in DEFAULT_GEMINI_STAGE_MODELS}
        base["flags"] = {"research_enabled": False, "corroborate_enabled": False}
        return base
    if name == "diverse-validation":
        base["stage_runners"] = {"audit": "codex", "validate": "headless", "verify": "gemini"}
        base["codex_stage_models"] = {"audit": CODEX_BALANCED}
        base["flags"] = {"verify_enabled": True}
        return base
    if name == "smoke":
        base["codex_stage_models"] = {k: CODEX_CHEAP for k in DEFAULT_CODEX_STAGE_MODELS}
        base["stage_models"] = {k: HAIKU for k in DEFAULT_STAGE_MODELS}
        base["stage_models"]["recon"] = SONNET
        base["gemini_stage_models"] = {k: GEMINI_CHEAP for k in DEFAULT_GEMINI_STAGE_MODELS}
        base["gemini_stage_models"]["recon"] = "gemini-3.8-flash"
        base["flags"] = {"max_focuses": 1, "research_enabled": False, "corroborate_enabled": False}
        return base
    raise ValueError(f"unknown profile {name!r}; choose from {', '.join(_PROFILE_NAMES)}")


def apply_profile_data(config: PipelineConfig, data: dict[str, Any]) -> PipelineConfig:
    if not isinstance(data, dict):
        raise ValueError("profile must be a JSON object")
    flags = data.get("flags", {})
    if not isinstance(flags, dict):
        raise ValueError("profile flags must be an object")
    allowed = {"stage_runners", "stage_models", "codex_stage_models", "gemini_stage_models", "flags", "runner", "name", "version", "routing_basis"}
    unknown = set(data) - allowed
    if unknown:
        raise ValueError(f"profile contains unsupported fields: {', '.join(sorted(unknown))}")
    return config.with_overrides(
        runner=data.get("runner", config.runner),
        stage_runners={**config.stage_runners, **(data.get("stage_runners") or {})},
        stage_models={**config.stage_models, **(data.get("stage_models") or {})},
        codex_stage_models={**config.codex_stage_models, **(data.get("codex_stage_models") or {})},
        gemini_stage_models={**config.gemini_stage_models, **(data.get("gemini_stage_models") or {})},
        **flags,
    )


def apply_profile(config: PipelineConfig, name: str) -> PipelineConfig:
    path = Path(name).expanduser()
    data = load_profile(path) if path.exists() else profile_data(name)
    return apply_profile_data(config, data)


def save_profile(path: str | Path, config: PipelineConfig, name: str) -> None:
    """Save only routing/behavior fields; secret fields are intentionally not copied."""
    data = profile_data(name) if name in _PROFILE_NAMES else {"name": name, "version": 1}
    data.update({"stage_runners": dict(config.stage_runners), "stage_models": dict(config.stage_models),
                 "codex_stage_models": dict(config.codex_stage_models),
                 "gemini_stage_models": dict(config.gemini_stage_models),
                 "runner": config.runner})
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_profile(path: str | Path) -> dict[str, Any]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or any(k in raw for k in ("gemini_api_key", "claude_api_key", "codex_api_key")):
        raise ValueError("profile must be a JSON object containing routing only, never credentials")
    return raw


def profile_names() -> tuple[str, ...]:
    return _PROFILE_NAMES
