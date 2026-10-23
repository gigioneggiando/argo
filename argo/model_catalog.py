"""Versioned, provider-aware model catalog used by routing and cost estimation.

The catalog is intentionally static.  Refreshing provider metadata is an explicit maintenance
operation; a run never reaches the network to decide which model or price it used.  Unknown models
remain distinguishable from a known model whose price happens to be zero.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Literal

Availability = Literal["general", "preview", "trusted_access", "legacy"]
Lifecycle = Literal["current", "preview", "deprecated", "retired", "legacy"]


@dataclass(frozen=True)
class ModelSpec:
    provider: str
    model_id: str
    input_per_million: float | None = None
    output_per_million: float | None = None
    aliases: tuple[str, ...] = ()
    availability: Availability = "general"
    lifecycle: Lifecycle = "current"
    supports_reasoning: bool = False
    supports_thinking: bool = False
    api_product: str = "api"
    cli_product: str | None = None
    notes: str = ""
    effective_until: str | None = None
    # Optional effective-dated prices.  ``input_per_million``/``output_per_million`` remain the
    # current fallback so old callers keep working; a schedule is selected explicitly by
    # ``resolve_pricing(..., as_of=...)`` and is never fetched at runtime.
    pricing_periods: tuple[dict, ...] = ()
    source_url: str = ""
    verified_at: str = "2026-10-21"
    product_surface: str = "api"
    api_available: bool = True
    cli_available: bool = False
    exact_pinning: bool = True
    approval_required: bool = False
    minimum_cli_version: str | None = None

    @property
    def pricing_known(self) -> bool:
        return self.input_per_million is not None and self.output_per_million is not None


MODEL_CATALOG: tuple[ModelSpec, ...] = (
    # OpenAI / Codex.  GPT-5.6 entries remain readable for old run directories, but are never
    # selected by a new built-in profile.
    ModelSpec("openai", "gpt-6-astra", 10.0, 50.0, supports_reasoning=True,
              cli_product="codex", cli_available=True),
    ModelSpec("openai", "gpt-6.1-sol", 2.0, 10.0, supports_reasoning=True,
              cli_product="codex", cli_available=True),
    ModelSpec("openai", "gpt-6-luna", 0.1, 0.5, supports_reasoning=True,
              cli_product="codex", cli_available=True),
    ModelSpec("openai", "gpt-6-sol", 2.0, 10.0, supports_reasoning=True,
              notes=("Current, exact model ID (not an alias for gpt-6.1-sol). Supports Daybreak Blue; "
                     "account/project access is still required."),
              cli_product="codex", cli_available=True,
              source_url="https://developers.openai.com/api/docs/models/gpt-6-sol",
              verified_at="2026-10-23", product_surface="api+codex-cli"),
    ModelSpec("openai", "gpt-5.6-cyber", 12.5, 75.0, availability="trusted_access",
              notes="Daybreak Red; authorized security research only.", cli_product="codex",
              cli_available=False, approval_required=True),
    ModelSpec("openai", "gpt-5.6-sol", 4.0, 20.0, availability="legacy", lifecycle="legacy"),
    ModelSpec("openai", "gpt-5.6-terra", 2.5, 15.0, availability="legacy", lifecycle="legacy"),
    ModelSpec("openai", "gpt-5.6-luna", 1.0, 6.0, availability="legacy", lifecycle="legacy"),
    ModelSpec("openai", "gpt-5-codex", 1.25, 10.0, availability="legacy", lifecycle="legacy"),
    ModelSpec("openai", "gpt-5.5", 1.25, 10.0, availability="legacy", lifecycle="legacy"),
    ModelSpec("openai", "gpt-5", 1.25, 10.0, availability="legacy", lifecycle="legacy"),
    ModelSpec("openai", "o4-mini", 1.1, 4.4, availability="legacy", lifecycle="legacy"),
    ModelSpec("openai", "o3", 2.0, 8.0, availability="legacy", lifecycle="legacy"),
    ModelSpec("openai", "gpt-4o", 2.5, 10.0, availability="legacy", lifecycle="legacy"),
    ModelSpec("openai", "gpt-4.1", 2.0, 8.0, availability="legacy", lifecycle="legacy"),
    # Gemini.  Prices are standard API rates; promotional windows are represented in notes and
    # should be modeled as separate effective-dated records when the budget planner needs them.
    ModelSpec("gemini", "gemini-4-argon", 2.0, 10.0, supports_thinking=True,
              pricing_periods=({"until": "2026-11-30", "input": 2.0, "output": 10.0},
                               {"from": "2026-12-01", "input": 4.0, "output": 20.0}),
              notes="Introductory rate through 2026-11-30; $4/$20 thereafter.",
              cli_product="gemini", cli_available=True),
    ModelSpec("gemini", "gemini-3.8-flash", 0.75, 3.75, supports_thinking=True,
              pricing_periods=({"until": "2026-12-31", "input": 0.75, "output": 3.75},
                               {"from": "2027-01-01", "input": 1.5, "output": 7.5}),
              notes="Introductory $0.75/$3.75 through 2026-12-31.",
              cli_product="gemini", cli_available=True),
    ModelSpec("gemini", "gemini-3.6-flash", 0.75, 3.75, supports_thinking=True,
              pricing_periods=({"until": "2026-12-31", "input": 0.75, "output": 3.75},
                               {"from": "2027-01-01", "input": 1.5, "output": 7.5}),
              notes="Introductory $0.75/$3.75 through 2026-12-31.",
              cli_product="gemini", cli_available=True),
    ModelSpec("gemini", "gemini-3.5-flash-lite", 0.3, 2.5, supports_thinking=True,
              cli_product="gemini", cli_available=True),
    ModelSpec("gemini", "gemini-3.1-flash-lite", 0.25, 1.5, supports_thinking=True,
              cli_product="gemini", cli_available=True),
    ModelSpec("gemini", "gemini-3.1-pro-preview", 2.0, 12.0, availability="preview",
              lifecycle="preview", supports_thinking=True, cli_product="gemini",
              cli_available=True, exact_pinning=False),
    ModelSpec("gemini", "gemini-3-flash-preview", 0.5, 3.0, availability="preview",
              lifecycle="preview", supports_thinking=True, cli_product="gemini",
              cli_available=True, exact_pinning=False),
    ModelSpec("gemini", "gemini-3.7-flash", 1.5, 7.5, availability="legacy", lifecycle="deprecated",
              notes="Provider automatically routes to 3.8; exact trials must use 3.8."),
    ModelSpec("gemini", "gemini-3.5-flash", 1.5, 9.0, availability="legacy", lifecycle="deprecated",
              notes="Provider automatically routes to 3.6; exact trials must use 3.6."),
    # Anthropic.  New exact IDs have no date suffix; Haiku 4.5 remains a compatibility model.
    ModelSpec("anthropic", "claude-fable-5-1", 10.0, 50.0, supports_thinking=True,
              cli_product="claude", cli_available=True),
    ModelSpec("anthropic", "claude-mythos-5-1", 10.0, 50.0, availability="trusted_access",
              supports_thinking=True, cli_product="claude", cli_available=True,
              approval_required=True),
    ModelSpec("anthropic", "claude-opus-5-5", 4.0, 20.0, supports_thinking=True,
              cli_product="claude", cli_available=True),
    ModelSpec("anthropic", "claude-sonnet-5-5", 2.0, 10.0, supports_thinking=True,
              cli_product="claude", cli_available=True),
    ModelSpec("anthropic", "claude-haiku-5-5", 0.1, 0.5, supports_thinking=True,
              cli_product="claude", cli_available=True),
    ModelSpec("anthropic", "claude-haiku-4-5-20251001", 1.0, 5.0, availability="legacy",
              lifecycle="legacy"),
    ModelSpec("anthropic", "claude-opus-5", 5.0, 25.0, availability="legacy", lifecycle="legacy"),
    ModelSpec("anthropic", "claude-sonnet-5", 2.0, 10.0, availability="legacy", lifecycle="legacy"),
)


_BY_ID = {spec.model_id.lower(): spec for spec in MODEL_CATALOG}
_ALIASES: dict[str, ModelSpec] = {}
for _spec in MODEL_CATALOG:
    for _alias in _spec.aliases:
        _ALIASES[_alias.lower()] = _spec


def get_model_spec(model_id: str | None) -> ModelSpec | None:
    """Resolve only exact IDs and explicit aliases; return ``None`` for unknown models."""
    if not model_id:
        return None
    key = str(model_id).strip().lower()
    return _BY_ID.get(key) or _ALIASES.get(key)


def resolve_pricing(model_id: str | None, *, as_of: str | None = None) -> tuple[float, float] | None:
    """Return input/output rates or ``None`` when the model is unknown/unpriced.

    ``as_of`` is an ISO date.  If omitted, the current catalog fallback is used; callers that
    need reproducible historical cost attribution should pass the run/report date.
    """
    spec = get_model_spec(model_id)
    if spec is None or not spec.pricing_known:
        return None
    if as_of and spec.pricing_periods:
        for period in spec.pricing_periods:
            until = period.get("until")
            starts = period.get("from")
            if (not starts or as_of >= starts) and (not until or as_of <= until):
                return float(period["input"]), float(period["output"])
    return spec.input_per_million or 0.0, spec.output_per_million or 0.0


def catalog_snapshot() -> dict:
    """JSON-safe catalog metadata persisted in run provenance."""
    payload = {
        "version": "2026-10-23",
        "models": [
            {
                "provider": s.provider,
                "model_id": s.model_id,
                "aliases": list(s.aliases),
                "availability": s.availability,
                "lifecycle": s.lifecycle,
                "pricing_known": s.pricing_known,
                "input_per_million": s.input_per_million,
                "output_per_million": s.output_per_million,
                "supports_reasoning": s.supports_reasoning,
                "supports_thinking": s.supports_thinking,
                "source_url": s.source_url or {
                    "openai": "https://developers.openai.com/api/docs/models",
                    "gemini": "https://ai.google.dev/gemini-api/docs/models",
                    "anthropic": "https://platform.claude.com/docs/en/models",
                }.get(s.provider, ""),
                "verified_at": s.verified_at,
                "product_surface": s.product_surface,
                "effective_until": s.effective_until,
                "pricing_periods": [dict(p) for p in s.pricing_periods],
                "notes": s.notes,
                "api_available": s.api_available,
                "cli_available": s.cli_available,
                "cli_product": s.cli_product,
                "exact_pinning": s.exact_pinning,
                "approval_required": s.approval_required,
                "minimum_cli_version": s.minimum_cli_version,
            }
            for s in MODEL_CATALOG
        ],
    }
    payload["snapshot_hash"] = hashlib.sha256(
        json.dumps(payload["models"], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return payload


def selection_status(model_id: str | None, *, allow_preview: bool = False,
                     allow_trusted: bool = False) -> dict:
    """Explain whether an ID is a safe built-in selection without rejecting custom IDs."""
    spec = get_model_spec(model_id)
    if spec is None:
        return {"model_id": model_id, "status": "custom/unverified", "pricing": "unknown",
                "selectable": True, "exact_pinning": False}
    if spec.lifecycle in {"deprecated", "retired", "legacy"}:
        return {"model_id": model_id, "status": spec.lifecycle, "selectable": False,
                "reason": "compatibility only; use an exact current ID"}
    if spec.availability == "preview" and not allow_preview:
        return {"model_id": model_id, "status": "preview", "selectable": False,
                "reason": "preview models require explicit opt-in"}
    if spec.availability == "trusted_access" and not allow_trusted:
        return {"model_id": model_id, "status": "trusted_access", "selectable": False,
                "reason": "limited-access models require explicit access"}
    return {"model_id": model_id, "status": "current", "selectable": True,
            "pricing": "known" if spec.pricing_known else "unknown",
            "provider": spec.provider, "api_available": spec.api_available,
            "cli_available": spec.cli_available, "exact_pinning": spec.exact_pinning,
            "approval_required": spec.approval_required}


def validate_selection(model_id: str | None, backend: str, *, exact: bool = False,
                       allow_preview: bool = False, allow_trusted: bool = False) -> dict:
    """Return an actionable, side-effect-free preflight result for a backend/model pair.

    Unknown IDs remain valid custom selections (the adapters accept arbitrary provider IDs), but
    are explicitly marked unverified and cannot be considered exact benchmark evidence.  Known
    legacy/preview/trusted IDs are rejected only for exact selection; normal best-effort routing
    receives a warning so migration of old run directories remains possible.
    """
    spec = get_model_spec(model_id)
    result = selection_status(model_id, allow_preview=allow_preview, allow_trusted=allow_trusted)
    result["backend"] = backend
    if spec is None:
        result["warnings"] = ["custom/unverified model ID; pricing and served-model support are unknown"]
        return result
    expected = {"headless": "anthropic", "gemini": "gemini", "codex": "openai"}.get(backend)
    if expected and spec.provider != expected:
        result.update(selectable=False, reason=f"model belongs to {spec.provider}, not {backend}")
        return result
    if not exact and result.get("selectable") is False:
        # Historical IDs remain usable for migration/compatibility runs; only exact benchmark
        # preflight rejects them.  Keep the warning visible in routing/provenance output.
        result["selectable"] = True
        result["warnings"] = ["compatibility/limited model; not eligible for exact benchmark evidence"]
    if exact and (not spec.exact_pinning or spec.lifecycle in {"deprecated", "retired", "legacy"}
                  or (spec.availability == "preview" and not allow_preview)
                  or (spec.availability == "trusted_access" and not allow_trusted)):
        result.update(selectable=False, reason="not eligible for an exact pinned benchmark")
    return result


def catalog_by_provider(provider: str) -> list[ModelSpec]:
    return [s for s in MODEL_CATALOG if s.provider == provider]


def catalog_integrity() -> dict:
    """Return deterministic duplicate/collision checks for CI and ``argo catalog validate``."""
    ids = [s.model_id.lower() for s in MODEL_CATALOG]
    aliases = [(a.lower(), s.model_id) for s in MODEL_CATALOG for a in s.aliases]
    duplicate_ids = sorted({x for x in ids if ids.count(x) > 1})
    id_set = set(ids)
    alias_collisions = sorted({a for a, _owner in aliases if a in id_set})
    duplicate_aliases = sorted({a for a, _owner in aliases
                                if sum(1 for x, _ in aliases if x == a) > 1})
    return {"valid": not (duplicate_ids or alias_collisions or duplicate_aliases),
            "duplicate_ids": duplicate_ids, "alias_canonical_collisions": alias_collisions,
            "duplicate_aliases": duplicate_aliases}


def catalog_diff(previous: dict, current: dict | None = None) -> dict:
    """Compute a reviewable diff between two static snapshots; never contacts a provider."""
    current = current or catalog_snapshot()
    old = {str(x.get("model_id")): x for x in previous.get("models", []) if isinstance(x, dict)}
    new = {str(x.get("model_id")): x for x in current.get("models", []) if isinstance(x, dict)}
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = []
    for key in sorted(set(old) & set(new)):
        if old[key] != new[key]:
            changed.append({"model_id": key, "before": old[key], "after": new[key]})
    return {"from_version": previous.get("version"), "to_version": current.get("version"),
            "from_hash": previous.get("snapshot_hash"), "to_hash": current.get("snapshot_hash"),
            "added": added, "removed": removed, "changed": changed,
            "requires_review": bool(added or removed or changed)}

