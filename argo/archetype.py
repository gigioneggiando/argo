"""Canonical software archetypes + a normalizer.

Used to capture the archetype the recon stage classified for each run (persisted in meta.json),
so cost analytics and future benchmarks (Phase 7) can group/calibrate by archetype.
"""

from __future__ import annotations

import json
from pathlib import Path

ARCHETYPES = {
    "web_api_cms": "Web / API / CMS",
    "plugin_extension": "Plugin / Extension / Mod",
    "library_sdk": "Library / SDK / Framework",
    "cli_desktop": "CLI / Desktop",
    "agent_llm_mcp": "Agent / LLM / MCP",
    "mobile": "Mobile",
    "data_ml": "Data / ML pipeline",
    "smart_contract": "Smart contract",
    "firmware": "Firmware / Embedded",
    "iac": "Infrastructure-as-code",
    "other": "Other",
}

# keyword → canonical key (checked in order; first match wins)
_KEYWORDS = [
    ("plugin_extension", ("plugin", "extension", " mod ", "add-on", "addon", "mixin", "bukkit", "spigot")),
    ("agent_llm_mcp", ("agent", " llm", "mcp", "prompt-")),
    ("library_sdk", ("library", " sdk", "framework")),
    ("cli_desktop", ("cli", "desktop", "command-line", "command line")),
    ("mobile", ("mobile", "android", "ios ", "react native", "flutter", "swiftui")),
    ("data_ml", ("data pipeline", "ml pipeline", "machine learning", "notebook", " etl", "dataset", "model training")),
    ("smart_contract", ("smart contract", "solidity", "on-chain", "blockchain", "evm")),
    ("firmware", ("firmware", "embedded", "rtos", "microcontroller")),
    ("iac", ("infrastructure-as-code", "infrastructure as code", "terraform", " iac", "helm", "k8s manifest")),
    ("web_api_cms", ("cms", "web app", "web application", " api", "graphql", "rest ", "backend")),
]


def canonicalize(text: str | None) -> str:
    """Map a free-text or already-canonical archetype label to a canonical key."""
    if not text:
        return "other"
    t = text.strip().lower()
    if t in ARCHETYPES:
        return t
    for key, kws in _KEYWORDS:
        if any(k in t for k in kws):
            return key
    return "other"


def label(key: str) -> str:
    return ARCHETYPES.get(key, key)


def run_archetypes(runs_dir: Path) -> dict[str, str]:
    """Map run_id -> canonical archetype from each run's meta.json.

    This is shared by the API cost endpoint and the CLI estimator. Missing, malformed, or
    pre-archetype meta files are ignored so one bad run directory never breaks analytics.
    """
    mapping: dict[str, str] = {}
    root = Path(runs_dir)
    if not root.exists():
        return mapping
    for rd in root.iterdir():
        if not rd.is_dir():
            continue
        try:
            meta = json.loads((rd / "meta.json").read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            continue
        arch = meta.get("archetype") if isinstance(meta, dict) else None
        if arch:
            mapping[rd.name] = canonicalize(str(arch))
    return mapping
