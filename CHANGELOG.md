# Changelog

All notable changes to Argo are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — see
[docs/releasing.md](docs/releasing.md) for what that means concretely for this project, in
particular while the version stays `0.y.z`.

## [Unreleased]

## [0.6.0] - 2026-08-18

### Added

- **Web UI: Gemini as a full runner option.** New Run's runner selector and Settings' default-runner
  picker now offer Gemini alongside Claude/Codex/Mock (Settings previously only offered Mock/Claude —
  Codex was missing there too). A Gemini model picker (populated from `GET /models`) + API-key field
  appear when Gemini is selected, mirroring the existing Codex row. The backend (`RunConfig.gemini_model`/
  `gemini_api_key`, `GET /models`' `gemini` entry) already supported this since `v0.4.0`; the webapp
  never wired it up until now.
- **Web UI: cross-backend benchmark + refusal-probe cards** on the Benchmarks page — reads the
  already-existing `GET /benchmark/cross` / `GET /refusal-probe` endpoints (added in `v0.5.0`, never
  surfaced in the UI), rendering per-backend cost/latency/precision/recall/F1 and refusal-flag/
  recovery rates when a report exists.

### Fixed

- Settings' runner selector was missing **Codex** entirely (only Mock/Claude) — an independent,
  pre-existing gap now fixed alongside the Gemini addition.
- The "danger" (real-spend) styling on the runner selector only ever applied to Claude — Codex was
  silently unflagged. `seg()` now takes an explicit danger set so every real backend gets it.
- A New-Run submit-error fallback had inverted logic (`runner === "headless" ? real : free`), which
  would have mislabeled the Start button after a failed Codex/Gemini run. Now checks for `"mock"`.

## [0.5.0] - 2026-08-17

### Added

- **Cross-backend benchmark**: `argo bench-cross --suite DIR --backends headless,codex,gemini
  [--tier cheap|top]` runs the same labeled corpus once per backend and reports
  cost/latency/precision/recall/F1 side by side (`compare_backends()` in `argo/benchmark.py`) — a
  genuinely N-way comparison, distinct from `bench --ab-audit-model`'s same-backend, two-model A/B.
  `--tier cheap` (default) picks each backend's cheapest model (Haiku/`o4-mini`/Flash-Lite);
  `--tier top` picks each backend's own top-tier model (fixed a latent bug along the way:
  `PipelineConfig.calibrated()`'s Codex branch was a no-op, so "top-tier" never actually affected
  Codex runs before this).
- **Per-LLM-call latency tracking**: `duration_ms` is now recorded per call in the ledger and
  per-run `llm_log.jsonl`, alongside a new `failure_kind` column that persists the same
  classification (`moderation_flagged`, `rate_limited`, ...) a `RunnerError` already carried —
  previously only visible inside a raised exception's message, never queryable after the fact.
- **`argo refusal-probe --backends headless,codex,gemini [--trials N] [--tier cheap|top]`**:
  measures how often each backend's OWN safety classifier false-positives on a legitimate,
  authorized security-audit prompt (`refusal_flag_rate`), and how often the same backend's
  existing neutral-register retry recovers it (`refusal_recovery_rate`). Deliberately NOT
  jailbreak/adversarial-prompt testing — see `argo/refusal_probe.py`'s module docstring and
  `tests/fixtures/refusal_prompts.json`.
- **Benchmark corpus**: 4 new real, independently re-verified cases (`libcsp-csp-ps-uaf`,
  `coturn-ipv6-acl-bypass`, `bonjour-service-takeover`, `jsoup-redirect-header-leak`), spanning
  C/JavaScript/Java — see `benchmarks/README.md`.

## [0.4.0] - 2026-08-17

### Added

- **Gemini CLI backend** (`--runner gemini`): a third swappable engine alongside Claude Code and
  Codex, tiered per stage like Claude (`gemini-3.1-pro` / `gemini-3.5-flash` / `gemini-3.1-flash-lite`
  — see `DEFAULT_GEMINI_STAGE_MODELS`), fully composable into the existing fallback chain
  (`--fallback`) and multi-account resilience machinery. Guardrails map onto Gemini's **Policy
  Engine** (a named-tool denylist, the same dialect Claude uses), not `--sandbox`, which was found
  to have a hard, unreliable Docker/Podman dependency during empirical verification against a real
  `gemini` CLI install. `--gemini-model`, `--gemini-api-key`, `--gemini-accounts` CLI flags; matching
  `RunConfig` fields on the HTTP API. See [docs/backends.md](docs/backends.md#gemini-specifics-runner--gemini).

## [0.3.0] - 2026-08-17

### Added

- `argo verify` is now **resumable by default**: re-running it on a run that already has some
  deep-verify verdicts skips findings that got a real answer and only re-attempts unverified or
  infra-failure (`inconclusive`) ones — safe to re-invoke after a backend runs out of credits, a
  rate limit, or a crash without re-spending on already-completed sessions.
- `argo verify --only ID,ID` — force specific findings to (re-)verify regardless of their current
  state, leaving every other survivor untouched (mirrors `fix --only`).

## [0.2.0] - 2026-08-14

First formally tracked release. Argo has been under active development since 2026-06-18 (99
commits) without a real version/release process; rather than reconstruct that history after the
fact, this entry is a snapshot of what the pipeline can do today, and the changelog is precise from
here forward.

### Added

- Core pipeline: ingest → recon → audit → validate → report.
- Opt-in stages: deep verification (`deep_verify`), corroboration, second-opinion
  reconciliation across independent audit passes, dependency/SCA scanning, sandboxed
  runtime verification (loopback-only, `--network=none`), live authorized-target probing,
  mechanical fix generation + re-audit, and sandboxed AddressSanitizer/UBSan PoC generation
  for C/C++ memory-safety findings.
- Multi-backend support (Claude Code, Codex, local open-source models) with cross-backend
  fallback, failure-kind-aware retry/backoff, and a neutral-register recovery path for
  moderation-flagged sessions.
- HTTP API (`server/`) and a no-build web UI (`webapp/`) for run lifecycle, live status, and
  history.
- 388 tests, zero-token by default via a mock runner; a Docker-gated real end-to-end proof for
  the sandboxed stages.
