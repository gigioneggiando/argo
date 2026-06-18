"""Vulnerability-class knowledge base (Phase 4 — context enrichment).

Loads ``pipeline/data/vuln_index.yaml`` and formats it for two consumers: the recon stage (injected
as REFERENCE context — "use the relevant classes, do not limit yourself to them") and the UI.
It augments the model's own discovery; it never constrains it.
"""

from __future__ import annotations

import functools
from pathlib import Path

import yaml

_DEFAULT_PATH = Path(__file__).resolve().parent / "data" / "vuln_index.yaml"


@functools.lru_cache(maxsize=4)
def load_vuln_index(path: str | Path | None = None) -> dict:
    return yaml.safe_load(Path(path or _DEFAULT_PATH).read_text(encoding="utf-8")) or {}


def format_for_prompt(index: dict | None = None) -> str:
    """Compact markdown reference for injection into the recon prompt."""
    index = index if index is not None else load_vuln_index()
    lines = [
        "## VULNERABILITY-CLASS REFERENCE INDEX (by archetype)",
        "Curated reference of bug classes that commonly hide real findings per archetype. After "
        "you classify the target's archetype, treat the matching section (plus `general`) as an "
        "**additional checklist** — apply the relevant classes, but do NOT limit yourself to them "
        "or report a class that does not fit the code.",
    ]
    for archetype, items in index.items():
        lines.append(f"\n### {archetype}")
        for it in items or []:
            cwe = it.get("cwe", "")
            name = it.get("name", "")
            note = it.get("note", "")
            lines.append(f"- {cwe} {name}" + (f" — {note}" if note else ""))
    return "\n".join(lines)
