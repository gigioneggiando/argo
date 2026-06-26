# Testing

The suite runs **entirely on the `MockClaudeRunner`** — zero tokens, no `claude`/`codex` calls —
except for the headless- and Codex-seam tests, which drive the envelope parsers, the command
construction, and the subprocess error paths with crafted inputs and fakes (still no real calls).

## Running

```bash
pip install -r requirements.txt
python -m pytest tests/ -q          # 202 tests (incl. the HTTP API + UI serving on the mock runner)
```

`pytest.ini` pins `--basetemp=.pytest_tmp` so the read-only repo copies the pipeline creates do
not trip Windows' global temp rotation.

## Files and coverage

| File | Covers |
|---|---|
| `test_guardrails.py` | tool-allowlist stripping, `assert_no_network_tools`, **the `research`-stage OSINT carve-out** (research keeps WebSearch/WebFetch but loses the shell; every other stage stays offline), prohibited-technique present/missing/empty, audit-prompt well-formedness, placeholder/`.j2` rendering |
| `test_units.py` | `split_ref` / `dedup_key`, manifest extraction + glob fallback, schema conformance of fixtures, artifact-contract shape |
| `test_runner.py` | the runner strips network/mutation tools even when a stage requests them; headless command is read-only/sandboxed |
| `test_headless.py` | strict parser over the **real** captured envelope, shape-drift fail-loud, recoverable-vs-API-error classification, turn/cost caps, `--max-budget-usd` present / no `--max-turns`, session-budget math, empty/malformed/non-zero-exit handling, audit partial-recovery |
| `test_links.py` | `--links` parsing/normalization/merge, repo-drop safety rule, schema survival, propagation into a rendered prompt, backward compatibility |
| `test_pipeline.py` | full mock pipeline end-to-end, golden `REPORT.md`, dedup/merge, scope-filter + validation drops, missing-manifest fallback, partial-session recovery, oversized-findings (no truncation), ledger cost + resubmission, dry-run, **research stage on/off** (Stage-0 brief + threat intel; `--no-research` stays offline), no-submit guardrail |
| `test_api.py` | the HTTP API on the mock runner: full run lifecycle, dry-run, SSE stream to terminal, artifact whitelist, 404s, costs/knowledge/fixes/**quality** endpoints, chat roundtrip + test-gen, **C3 zip upload → run** (+ non-zip rejected) |
| `test_uploads.py` | **C3 safe extraction**: single-top-dir vs flat repo root, **path-traversal rejected**, entry-count cap, empty/bad-zip rejected |
| `test_fixes.py` | Phase-6 remediation + verify: patch-target parsing, accept a compiling fix, reject one that breaks compile, reject a non-applying patch, **ignore pre-existing errors** (only count introduced ones), end-to-end fix generation; **A3 re-audit** — the `on_patched` hook (incl. a raising hook captured), the still-present matcher, and `generate_fixes(re_audit=True)` aggregation |
| `test_benchmark.py` | Phase-7 scoring: perfect/FN/FP cases, CWE mismatch + alias + line-tolerance matching, suite loading, end-to-end `run_suite` + `--fixes` + A/B; **A1** — case provenance, optional brief, `parallel_cases` (order + provenance); **A3** — `re_audit` rate folded into `patch_quality` |
| `test_quality.py` | **A2 accept-rate**: `record_triager_feedback` + `accept_rate` (severity slice, run-scoping), the old-DB column migration, `quality_report` pairing accept-rate with benchmark recall, and the `argo feedback --import` → `argo quality` CLI flow |
| `test_chat.py` | **B1 re-validation**: candidate backfill, `_validate_candidate` runs the adversarial validator, full `ask()` flow (model writes `CANDIDATE_FINDING.json` → verdict appended, hypothesis file kept out of `generated`), and the no-candidate path |
| `test_cancel.py` | **C1 mid-stage cancellation**: `AgentRunner._exec` runs a real subprocess, kills it **promptly** when the cancel_event fires (not after the full sleep) and on timeout, returns a CompletedProcess on success; the orchestrator turns a mid-stage `RunnerCancelled` into a cancelled run (status.json) |
| `test_runtime.py` | **R1–R4 runtime verification**: the safety validators (`assert_loopback_only` rejects external/scope hosts + protocol-relative; `validate_probe_plan` caps request count, body size, and read-only methods unless opted in), the stage's graceful-skip gating, a **Docker-gated end-to-end sealed-sandbox proof** (`--network=none` app container + a probe container sharing its loopback namespace), **R2** (`_generate_plan` LLM-proposes a plan, `_interpret` returns verdicts, full `run()` generates-then-skips without a recipe), **R3** (`_resolve_launcher` picks explicit config / argo-runtime.json / repo Dockerfile; `_dockerfile_expose` parses the port), **R2-auth** (`auth` login step is loopback-checked; login POST exempt from the read-only gate but probe POST still blocked), and **R4** (the report renders a finding's `runtime` verdict + evidence, and omits the block when absent — golden report stays stable) |
| `test_uplift.py` | the **precision/depth uplift**: recon captures `ground_truth.json`; the **SCA** dependency stage flows a `dependencies` finding into the validated set (and `--no-sca` suppresses it); the **completeness-critic** re-pass adds nothing-but-duplicates in mock and spends extra sessions; **drift-repair** keeps a malformed finding (flagged `schema_repair_failed`) instead of dropping it; `_format_ground_truth` surfaces carve-outs + baseline-correct refs to the validator |
| `test_fallback.py` | **resilience**: `FallbackRunner` retries a session/rate-limited (429) call on the next backend (Claude→Codex→local), propagates non-retryable errors immediately, a circuit breaker skips a walled backend for the rest of the run, and each backend selects its own per-stage model; the chain mixes backends AND accounts (`--claude-accounts` via CLAUDE_CONFIG_DIR, `--codex-accounts` via CODEX_HOME); `build_runner` wraps a chain only when fallbacks/accounts are set |
| `test_codex.py` | the **Codex backend**: the sandbox-mapping guardrails (audit stage is `-s workspace-write` + offline, **never** a `danger-*` escape; only `research` gets network), `--oss`/model flags, token parsing + cost estimation, `build_runner` dispatch, CLI/API config passthrough |

## The two zero-cost modes

- **`--runner mock`** — full glue test end-to-end with deterministic fixtures. Most orchestration
  bugs live in the glue, not the model call; debug them here, not by burning real audits.
- **`--dry-run`** — runs ingest + recon for real, then stops before any audit, so you can eyeball
  the generated prompts before paying.

## Fixtures

```
tests/fixtures/
  brief.txt                 a sample program brief
  links.txt                 --links input exercising every line kind (valid / dup / blank / comment / malformed / repo)
  repo/                     a tiny fake target tree referenced by the findings
  real_envelope.json        the recorded real claude envelope, used by the parser test
  happy/                    the mock scenario: ingest/recon/audit/validate fixtures
tests/golden/REPORT.md      golden file for the deterministic report test
```

The mock scenario deliberately exercises the **failure paths**, not just the happy path: an
out-of-scope finding (scope filter), the same finding from two focuses (dedup), a refuted finding
(drop), a missing manifest (glob fallback), a session that died mid-write (partial recovery), and
an oversized findings file (no truncation). Failure variants are driven by sentinel files in the
scenario dir (e.g. `recon/_no_manifest`, `audit/<slug>._partial`).

## Determinism

The golden `REPORT.md` test injects a fixed `now` and run id and uses the mock's zero cost, so the
report is byte-stable. Report rendering is deterministic code (no LLM) for exactly this reason.

## After changing the real runner

Run the cheap real seam check before trusting a runner/flag/envelope change:

```bash
python -m argo.cli pipeline --smoke      # ≈ $1, one focus, real claude
```

See [headless-runner.md](headless-runner.md#the---smoke-run).
