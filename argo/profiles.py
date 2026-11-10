"""Portable routing profiles.  Profiles contain no credentials and expand to PipelineConfig data."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import (CODEX_BALANCED, CODEX_CHEAP, CODEX_TOP, DEFAULT_CODEX_STAGE_MODELS,
                     DEFAULT_GEMINI_STAGE_MODELS, DEFAULT_STAGE_MODELS, GEMINI_ARGON, GEMINI_CHEAP,
                     HAIKU, OPUS, SONNET, PipelineConfig, DEEPSEEK_FLASH, DEEPSEEK_PRO,
                     _SECRET_FIELDS)

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
        base['deepseek_api_stage_models'] = {k: DEEPSEEK_PRO for k in DEFAULT_STAGE_MODELS}
        base["codex_stage_models"] = {k: CODEX_TOP for k in DEFAULT_CODEX_STAGE_MODELS}
        base["stage_models"] = {k: OPUS for k in DEFAULT_STAGE_MODELS}
        base["gemini_stage_models"] = {k: GEMINI_ARGON for k in DEFAULT_GEMINI_STAGE_MODELS}
        base["flags"] = {"verify_enabled": True, "corroborate_enabled": True}
        return base
    if name == "cost-saver":
        base['deepseek_api_stage_models'] = {k: DEEPSEEK_FLASH for k in DEFAULT_STAGE_MODELS}
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
        base['deepseek_api_stage_models'] = {k: DEEPSEEK_FLASH for k in DEFAULT_STAGE_MODELS}
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
    if _SECRET_FIELDS.intersection(flags):
        raise ValueError('profile flags must never contain credentials')
    allowed = {"stage_runners", "stage_models", "codex_stage_models", "gemini_stage_models", "flags", "runner", "name", "version", "routing_basis"}
    allowed.add('deepseek_api_stage_models')
    unknown = set(data) - allowed
    if unknown:
        raise ValueError(f"profile contains unsupported fields: {', '.join(sorted(unknown))}")
    return config.with_overrides(
        runner=data.get("runner", config.runner),
        stage_runners={**config.stage_runners, **(data.get("stage_runners") or {})},
        stage_models={**config.stage_models, **(data.get("stage_models") or {})},
        codex_stage_models={**config.codex_stage_models, **(data.get("codex_stage_models") or {})},
        gemini_stage_models={**config.gemini_stage_models, **(data.get("gemini_stage_models") or {})},
        deepseek_api_stage_models={**config.deepseek_api_stage_models,
                                   **(data.get('deepseek_api_stage_models') or {})},
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
                 "deepseek_api_stage_models": {
                     **({k: config.deepseek_api_model for k in DEFAULT_STAGE_MODELS}
                        if config.deepseek_api_model else {}), **config.deepseek_api_stage_models},
                 "runner": config.runner})
    data['flags'] = {**data.get('flags', {}), **{name: getattr(config, name) for name in (
        'deepseek_thinking', 'deepseek_reasoning_effort', 'deepseek_api_max_tokens',
        'deepseek_api_context_window', 'deepseek_api_max_requests')}}
    Path(path).write_bytes(json.dumps(data, indent=2).encode('utf-8'))


def load_profile(path: str | Path) -> dict[str, Any]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or _SECRET_FIELDS.intersection(raw):
        raise ValueError("profile must be a JSON object containing routing only, never credentials")
    return raw


def profile_names() -> tuple[str, ...]:
    return _PROFILE_NAMES
