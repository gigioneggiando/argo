# Argo implementation report — v0.10.0 (2026-10-21)

This report records the implementation of `ARGO_MASTER_IMPLEMENTATION_PLAN.txt` against the
current Argo worktree. It deliberately separates shipped behavior from work that needs new
ground-truth data or approved paid runs.

## Shipped

- Central model catalog with canonical IDs, aliases, lifecycle/access scope, API-versus-CLI
  availability, effort capabilities, dated pricing periods, source metadata, integrity checks, and
  reviewable snapshot diffs. New defaults are Astra/Sol/Luna, Gemini 4 Argon/3.8 Flash/Flash-Lite,
  and Claude 5.5/5.1 families; legacy IDs remain readable for old runs.
- Exact requested-versus-served model provenance. Served IDs are extracted from Codex, Gemini, and
  Claude results when the provider exposes them. Exact benchmark mismatches become invalid/fail-closed;
  ordinary runs require explicit `allow_model_substitution` to continue.
- Per-stage backend, model, and effort routing for Codex, Gemini, and Claude, with shared CLI/API/UI
  configuration and effective-routing previews. Credentials remain outside routing profiles.
- Deterministic, read-only target screening and fingerprints, explainable Fast/Economy/Balanced/Deep/
  Custom plans, cost/time ranges, user review, plan IDs, and persisted CLI plans.
- Benchmark provenance, target-commit pinning, repeated trials, invalid-trial separation, cost/latency
  statistics, CLI/model/catalog provenance, and zero-token `bench-validate` checks.
- Benchmark knowledge aggregation with confidence/sample counts and weak-evidence fallback; no
  unlabeled production findings are treated as ground truth.
- Explicit opt-in adaptive escalation (`off` by default), bounded by the existing budget/guardrails and
  recorded in `adaptive_events.jsonl`; benchmark mode freezes it.
- Credential-free saved profiles (list/show/export/import/save), migration-safe run metadata and ledger
  fields, FastAPI endpoints, and the existing vanilla SPA controls for screen/plan/routing.
- Documentation and CLI help updated for current model IDs, pricing semantics, migration behavior,
  benchmark validity, screening safety, profiles, and adaptive routing.

## Evidence and limits

- Baseline before this tranche: 561 passed, 2 skipped.
- Current verification: `python -m pytest -q` → **574 passed, 2 skipped**.
- Additional checks: `python -m compileall -q argo server`; `python -m argo.cli catalog validate`;
  `python -m argo.cli bench-validate --suite benchmarks/corpora`; `git diff --check`.
- The frozen corpus currently contains five independently verified real cases plus the offline mock.
  The plan's 10–20 case expansion remains a data task: new cases need reviewed labels, exact commits,
  and permission/licensing checks. No synthetic labels were invented.
- No paid cross-provider benchmark matrix was run and no default was retuned from unmeasured data.
  Built-in profile routing is therefore explicitly provisional until repeated, comparable trials are
  approved and available.

## Compatibility and safety

Historical run directories retain their original model/catalog provenance. Unknown prices are marked
unknown rather than reported as zero. Screening does not execute target code, network access, or package
managers by default. Existing read-only, no-auto-submit, live/write authorization gates remain intact.

The worktree is intentionally uncommitted; no external push or paid provider call was performed as part
of this implementation.
