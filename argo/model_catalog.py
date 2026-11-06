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
    verified_at: str = "2026-11-06"
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
    # Refreshed 2026-11-06 from the providers' model, pricing and deprecation pages, and each
    # current model probed with a one-line call through its CLI (see docs/backends.md "Model
    # catalog"). "verified" in a note = answered that probe; access caveats are per account/plan.
    #
    # OpenAI / Codex.  Docs: developers.openai.com/api/docs/{models,pricing,deprecations},
    # learn.chatgpt.com/docs/models.  With a ChatGPT sign-in, Codex rejects models the plan does
    # not include, and a profile with `daybreak = true` accepts only Daybreak-compatible models
    # (gpt-6-sol, gpt-5.6-sol were; gpt-6-astra / gpt-6.1-* were not).
    ModelSpec("openai", "gpt-6-astra", 10.0, 50.0, supports_reasoning=True,
              cli_product="codex", cli_available=True,
              notes="Flagship. Verified via Codex (needs daybreak off; not on every ChatGPT plan)."),
    ModelSpec("openai", "gpt-6.1-sol", 2.0, 10.0, supports_reasoning=True,
              cli_product="codex", cli_available=True,
              notes="Verified via Codex (needs daybreak off; not on every ChatGPT plan)."),
    ModelSpec("openai", "gpt-6.1-terra", 1.0, 5.0, supports_reasoning=True,
              cli_product="codex", cli_available=True, minimum_cli_version="0.159.0",
              notes="Mid tier, new 2026-11. Verified via Codex (needs daybreak off)."),
    ModelSpec("openai", "gpt-6-luna", 0.1, 0.5, supports_reasoning=True,
              cli_product="codex", cli_available=True, notes="Verified via Codex."),
    ModelSpec("openai", "gpt-6-sol", 2.0, 10.0, supports_reasoning=True,
              cli_product="codex", cli_available=True,
              notes="Current; superseded by gpt-6.1-sol for new work. Verified via Codex, also "
                    "with daybreak on."),
    ModelSpec("openai", "gpt-6-cyber", 20.0, 100.0, availability="trusted_access",
              notes="Daybreak cyber model; API with approved access only (not ChatGPT sign-in).",
              cli_product="codex", cli_available=False, approval_required=True),
    ModelSpec("openai", "gpt-5.6-cyber", 12.5, 75.0, availability="trusted_access",
              notes="Daybreak Red; authorized security research only; API with Daybreak Red "
                    "enabled (not ChatGPT sign-in).", cli_product="codex",
              cli_available=False, approval_required=True),
    ModelSpec("openai", "gpt-5.6-sol", 4.0, 20.0, availability="legacy", lifecycle="legacy",
              cli_product="codex", cli_available=True,
              notes="Promotional price until 2026-11-30. Verified via Codex with daybreak on."),
    ModelSpec("openai", "gpt-5.6-terra", 2.0, 12.0, availability="legacy", lifecycle="legacy",
              cli_product="codex", cli_available=True, notes="Verified via Codex."),
    ModelSpec("openai", "gpt-5.6-luna", 0.2, 1.2, availability="legacy", lifecycle="legacy",
              cli_product="codex", cli_available=True, notes="Verified via Codex."),
    ModelSpec("openai", "gpt-5.5", 5.0, 30.0, availability="legacy", lifecycle="legacy",
              notes="API only: retired from Codex with ChatGPT sign-in on 2026-10-14."),
    ModelSpec("openai", "gpt-5.4", 2.5, 15.0, availability="legacy", lifecycle="legacy",
              notes="Retired from Codex with ChatGPT sign-in on 2026-08-31; API current."),
    ModelSpec("openai", "gpt-5.4-mini", 0.75, 4.5, availability="legacy", lifecycle="legacy",
              notes="Retired from Codex with ChatGPT sign-in on 2026-08-31; API current."),
    ModelSpec("openai", "gpt-5.3-codex", 1.75, 14.0, availability="legacy", lifecycle="deprecated",
              notes="Shutdown 2027-04-01; replacement gpt-6-sol."),
    ModelSpec("openai", "gpt-5-codex", 1.25, 10.0, availability="legacy", lifecycle="retired",
              notes="Shut down 2026-07-23; replacement gpt-5.6-sol."),
    ModelSpec("openai", "gpt-5", 1.25, 10.0, availability="legacy", lifecycle="deprecated",
              notes="Shutdown 2026-12-11; replacement gpt-5.6-sol."),
    ModelSpec("openai", "o4-mini", 1.1, 4.4, availability="legacy", lifecycle="retired",
              notes="Shut down 2026-10-23; replacement gpt-5.6-terra. Historical price."),
    ModelSpec("openai", "o3", 2.0, 8.0, availability="legacy", lifecycle="deprecated",
              notes="Shutdown 2026-12-11; replacement gpt-5.6-sol."),
    ModelSpec("openai", "gpt-4o", 2.5, 10.0, availability="legacy", lifecycle="deprecated",
              notes="2024 snapshots shut down 2027-01-14; replacement gpt-6-luna."),
    ModelSpec("openai", "gpt-4.1", 2.0, 8.0, availability="legacy", lifecycle="deprecated",
              notes="gpt-4.1-2025-04-14 shuts down 2027-01-14; replacement gpt-6-luna."),
    # Gemini.  Docs: aistudio.google.com/docs/{models,pricing,deprecations}.  Effective-dated
    # rates are modeled in pricing_periods; budgets pass the run date to resolve_pricing().
    ModelSpec("gemini", "gemini-4-argon", 2.0, 10.0, supports_thinking=True,
              pricing_periods=({"until": "2026-11-30", "input": 2.0, "output": 10.0},
                               {"from": "2026-12-01", "input": 4.0, "output": 20.0}),
              notes="Introductory rate through 2026-11-30; $4/$20 thereafter. Exists (probe: 429 "
                    "daily quota on the test account).",
              cli_product="gemini", cli_available=True),
    ModelSpec("gemini", "gemini-3.8-flash", 0.75, 3.75, supports_thinking=True,
              pricing_periods=({"until": "2026-12-31", "input": 0.75, "output": 3.75},
                               {"from": "2027-01-01", "input": 1.5, "output": 7.5}),
              notes="$0.75/$3.75 through 2026-12-31, $1.50/$7.50 from 2027-01-01. Exists (probe: "
                    "503 overloaded).",
              cli_product="gemini", cli_available=True),
    ModelSpec("gemini", "gemini-3.6-flash", 0.75, 3.75, supports_thinking=True,
              pricing_periods=({"until": "2026-12-31", "input": 0.75, "output": 3.75},
                               {"from": "2027-01-01", "input": 1.5, "output": 7.5}),
              notes="$0.75/$3.75 through 2026-12-31, $1.50/$7.50 from 2027-01-01. Verified.",
              cli_product="gemini", cli_available=True),
    ModelSpec("gemini", "gemini-3.5-flash-lite", 0.3, 2.5, supports_thinking=True,
              cli_product="gemini", cli_available=True, notes="Verified."),
    ModelSpec("gemini", "gemini-3.1-flash-lite", 0.25, 1.5, supports_thinking=True,
              cli_product="gemini", cli_available=True,
              notes="Shutdown 2027-05-07. Verified."),
    ModelSpec("gemini", "gemini-3.1-pro-preview", 2.0, 12.0, availability="preview",
              lifecycle="preview", supports_thinking=True, cli_product="gemini",
              cli_available=True, exact_pinning=False,
              notes="$4/$18 above 200k prompt tokens. Exists (probe: 429 daily quota)."),
    ModelSpec("gemini", "gemini-3-flash-preview", 0.5, 3.0, availability="preview",
              lifecycle="preview", supports_thinking=True, cli_product="gemini",
              cli_available=True, exact_pinning=False,
              notes="Recommended replacement: gemini-3.6-flash. Verified."),
    ModelSpec("gemini", "gemini-3.7-flash", 1.5, 7.5, availability="legacy", lifecycle="deprecated",
              notes="Provider automatically routes to 3.8; exact trials must use 3.8."),
    ModelSpec("gemini", "gemini-3.5-flash", 1.5, 9.0, availability="legacy", lifecycle="deprecated",
              notes="Provider automatically routes to 3.6; exact trials must use 3.6."),
    ModelSpec("gemini", "gemini-2.5-flash", 0.3, 2.5, availability="legacy", lifecycle="deprecated",
              notes="Shutdown 2026-12-01 (routes to gemini-3.5-flash-lite). Verified."),
    ModelSpec("gemini", "gemini-2.5-pro", 1.25, 10.0, availability="legacy", lifecycle="deprecated",
              notes="Shutdown 2026-12-01 (routes to gemini-3.8-flash); probe: 404 on the test "
                    "account."),
    # Anthropic.  Docs: platform.claude.com/docs/en/about-claude/{models/overview,
    # model-deprecations,pricing}.  Fable/Mythos need usage credits or verified access on a
    # Claude subscription (probe: "requires usage credits" / no access).
    ModelSpec("anthropic", "claude-fable-5-1", 10.0, 50.0, supports_thinking=True,
              cli_product="claude", cli_available=True,
              notes="Exists; on a Claude subscription it requires usage credits."),
    ModelSpec("anthropic", "claude-mythos-5-1", 10.0, 50.0, availability="trusted_access",
              supports_thinking=True, cli_product="claude", cli_available=True,
              approval_required=True,
              notes="Limited availability: Anthropic verification programs (e.g. Cyber "
                    "Verification Program)."),
    ModelSpec("anthropic", "claude-opus-5-5", 4.0, 20.0, supports_thinking=True,
              cli_product="claude", cli_available=True, notes="Verified."),
    ModelSpec("anthropic", "claude-sonnet-5-5", 2.0, 10.0, supports_thinking=True,
              cli_product="claude", cli_available=True, notes="Verified."),
    ModelSpec("anthropic", "claude-haiku-5-5", 0.1, 0.5, supports_thinking=True,
              cli_product="claude", cli_available=True,
              notes="$0.50/$2.50 for prompts over 100K tokens. Verified."),
    ModelSpec("anthropic", "claude-fable-5", 10.0, 50.0, availability="legacy", lifecycle="legacy",
              supports_thinking=True, notes="Exists; requires usage credits on a subscription."),
    ModelSpec("anthropic", "claude-mythos-5", 10.0, 50.0, availability="trusted_access",
              lifecycle="legacy", approval_required=True, notes="Limited availability."),
    ModelSpec("anthropic", "claude-opus-5", 5.0, 25.0, availability="legacy", lifecycle="legacy",
              notes="Verified."),
    ModelSpec("anthropic", "claude-sonnet-5", 2.0, 10.0, availability="legacy", lifecycle="legacy",
              notes="Verified."),
    ModelSpec("anthropic", "claude-opus-4-8", 5.0, 25.0, availability="legacy", lifecycle="legacy",
              notes="Verified."),
    ModelSpec("anthropic", "claude-opus-4-7", 5.0, 25.0, availability="legacy", lifecycle="legacy",
              notes="Verified."),
    ModelSpec("anthropic", "claude-opus-4-6", 5.0, 25.0, availability="legacy", lifecycle="legacy",
              notes="Verified."),
    ModelSpec("anthropic", "claude-sonnet-4-6", 3.0, 15.0, availability="legacy", lifecycle="legacy",
              notes="Verified."),
    ModelSpec("anthropic", "claude-opus-4-5-20251101", 5.0, 25.0, availability="legacy",
              lifecycle="legacy", notes="Not before 2026-11-24 retirement window. Verified."),
    ModelSpec("anthropic", "claude-haiku-4-5-20251001", 1.0, 5.0, availability="legacy",
              lifecycle="legacy", notes="Verified."),
    ModelSpec("anthropic", "claude-sonnet-4-5-20250929", 3.0, 15.0, availability="legacy",
              lifecycle="deprecated",
              notes="Retires 2026-11-30; replacement claude-sonnet-5-5. Verified."),
    # Mistral (runner mistral-api; Vibe aliases map onto these). Prices: Standard tier, USD/1M,
    # from the docs pricing table; IDs/aliases/context from GET /v1/models; both 2026-11-06.
    # `mistral-large-latest` still resolves to mistral-large-2512 (Large 3, deprecated), NOT
    # Large 4 -- hence the exact `mistral-large-4` default. Medium 3.5 is deprecated (2026-10-31)
    # and has no published price; it is also Vibe's default model (mistral-vibe-cli-latest).
    ModelSpec("mistral", "mistral-large-4", 0.7, 2.1, aliases=("mistral-large-4-0",),
              source_url="https://docs.mistral.ai/inference/pricing", verified_at="2026-11-06",
              notes="Mistral Large 4 (v26.10), 1M context, function calling."),
    ModelSpec("mistral", "mistral-small-2603", 0.15, 0.6,
              aliases=("mistral-small-latest", "mistral-small-4", "mistral-vibe-cli-fast"),
              source_url="https://docs.mistral.ai/inference/pricing", verified_at="2026-11-06", exact_pinning=False,
              cli_product="vibe", cli_available=True,
              notes="Mistral Small 4; aliases are rolling, pin mistral-small-2603 for benchmarks."),
    ModelSpec("mistral", "codestral-2508", 0.3, 0.9,
              aliases=("codestral-latest", "mistral-code-latest"),
              source_url="https://docs.mistral.ai/inference/pricing", verified_at="2026-11-06"),
    ModelSpec("mistral", "mistral-medium-2604",
              aliases=("mistral-medium-latest", "mistral-medium", "mistral-medium-3.5",
                       "mistral-medium-3-5", "mistral-medium-3", "mistral-vibe-cli-latest",
                       "mistral-vibe-cli-with-tools"),
              lifecycle="deprecated", exact_pinning=False, cli_product="vibe", cli_available=True,
              source_url="https://docs.mistral.ai/models/mistral-medium-3-5-26-04",
              verified_at="2026-11-06",
              notes="Medium 3.5, deprecated 2026-10-31 (replacement: Large 4); no published price."),
    ModelSpec("mistral", "mistral-large-2512", aliases=("mistral-large-latest",),
              lifecycle="deprecated", exact_pinning=False, verified_at="2026-11-06",
              notes="Large 3, deprecated (retires 2027-04-30); still the target of "
                    "mistral-large-latest. No published price."),
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
        "version": "2026-11-06",
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
    expected = {"headless": "anthropic", "gemini": "gemini", "codex": "openai",
                "mistral-api": "mistral", "mistral-vibe": "mistral"}.get(backend)
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

