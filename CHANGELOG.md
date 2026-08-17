# Changelog

All notable changes to Argo are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — see
[docs/releasing.md](docs/releasing.md) for what that means concretely for this project, in
particular while the version stays `0.y.z`.

## [Unreleased]

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
