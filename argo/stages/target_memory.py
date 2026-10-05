"""Revision-bound private target-memory stage and deterministic recon fact capture."""

from __future__ import annotations

import json
from pathlib import Path

from ..context import RunContext, atomic_write_json
from ..target_memory import TargetMemoryStore, canonical_target, fresh_facts


def _meta(ctx: RunContext) -> dict:
    try:
        raw = json.loads(ctx.meta_path.read_text(encoding="utf-8-sig"))
        return raw if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        return {}


def _store(ctx: RunContext) -> TargetMemoryStore:
    return TargetMemoryStore(ctx.target_memory_dir)


def _identity(ctx: RunContext):
    meta = _meta(ctx)
    return canonical_target(str(meta.get("repo_source") or ""), bool(meta.get("repo_is_url"))), meta


def _snapshot(ctx: RunContext, memory, *, captured_ids: list[str] | None = None) -> None:
    facts = fresh_facts(memory)
    payload = {
        "schema_version": 1,
        "target": memory.target.model_dump(mode="json"),
        "commit": _meta(ctx).get("repo_commit"),
        "seed_facts": [fact.model_dump(mode="json") for fact in facts],
        "captured_fact_ids": captured_ids or [],
        "note": "Private local target memory. Facts are hypotheses to re-check against this run.",
    }
    atomic_write_json(ctx.target_memory_path, payload)


def run(ctx: RunContext) -> Path:
    """Load only same-commit facts before modelled stages begin."""
    identity, meta = _identity(ctx)
    memory = _store(ctx).load(identity, meta.get("repo_commit"))
    _snapshot(ctx, memory)
    return ctx.target_memory_path


def _as_strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    return [item for item in value or [] if isinstance(item, str)]


def capture_recon(ctx: RunContext) -> None:
    """Persist concise, structured recon conclusions without copying source text."""
    identity, meta = _identity(ctx)
    entries: list[tuple[str, str, str, list[str]]] = []
    try:
        profile = json.loads(ctx.repo_profile_path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        profile = {}
    if isinstance(profile, dict):
        for entry in _as_strings(profile.get("entry_points")):
            entries.append(("entry_point", entry, "recon:repo_profile", ["repo_profile.json"]))
        for boundary in _as_strings(profile.get("trust_boundaries")):
            entries.append(("trust_boundary", boundary, "recon:repo_profile", ["repo_profile.json"]))
        for unknown in _as_strings(profile.get("residual_unknowns")):
            entries.append(("question", unknown, "recon:repo_profile", ["repo_profile.json"]))
    try:
        ground_truth = json.loads(ctx.ground_truth_path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        ground_truth = {}
    if isinstance(ground_truth, dict):
        global_data = ground_truth.get("global") if isinstance(ground_truth.get("global"), dict) else {}
        for item in _as_strings(global_data.get("fp_carveouts")):
            entries.append(("false_lead", item, "recon:ground_truth", ["ground_truth.json"]))
        for focus in (ground_truth.get("focuses") or {}).values():
            if not isinstance(focus, dict):
                continue
            for item in focus.get("invariants") or []:
                if isinstance(item, dict) and isinstance(item.get("expected"), str):
                    summary = f"{item.get('location', 'unspecified location')}: {item['expected']}"
                    entries.append(("invariant", summary, "recon:ground_truth", ["ground_truth.json"]))
            for item in focus.get("baseline_correct") or []:
                if isinstance(item, dict) and isinstance(item.get("why_correct"), str):
                    summary = f"{item.get('pattern', 'baseline')}: {item['why_correct']}"
                    entries.append(("baseline", summary, "recon:ground_truth", ["ground_truth.json"]))
            for item in _as_strings(focus.get("fp_carveouts")):
                entries.append(("false_lead", item, "recon:ground_truth", ["ground_truth.json"]))
    memory = _store(ctx).upsert(identity, meta.get("repo_commit"), entries)
    captured = [fact.id for fact in fresh_facts(memory) if fact.provenance.startswith("recon:")]
    _snapshot(ctx, memory, captured_ids=captured)
