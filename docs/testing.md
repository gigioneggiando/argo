# Testing

The suite runs **entirely on the `MockClaudeRunner`** — zero tokens, no `claude`/`codex`/`gemini`/
`vibe` calls and no Mistral API requests — except for the backend-seam tests (headless, Codex,
Gemini, Mistral API, Mistral Vibe), which drive the envelope parsers, the command construction and
the subprocess/HTTP error paths with crafted inputs and fakes (still no real calls). A handful of
tests need the real `claude` CLI on `PATH` or Docker and are skipped when absent.

## Running

```bash
pip install -r requirements.txt
python -m pytest tests/ -q          # full suite (incl. the HTTP API + UI serving on the mock runner)
```

`pytest.ini` pins `--basetemp=.pytest_tmp` so the read-only repo copies the pipeline creates do
not trip Windows' global temp rotation.

## Files and coverage

| File | Covers |
|---|---|
| `test_agent_onboarding.py` | Agent entry-point links/headings/imports, documented CLI commands/options, marked discovery/mock-pipeline snippets, and interrupted-run CLI recovery from the agent guide; isolated state, unchanged target, guards against real runner invocation and intercepted Python TCP connections (not a full egress sandbox) |
| `test_guardrails.py` | tool-allowlist stripping, `assert_no_network_tools`, **the `research`-stage OSINT carve-out** (research keeps WebSearch/WebFetch but loses the shell; every other stage stays offline), prohibited-technique present/missing/empty, audit-prompt well-formedness, placeholder/`.j2` rendering |
| `test_config.py` | Vibe key/stored configuration validation, old-config defaults and secret-free resume; smoke presets preserve narrower time/turn/cost/budget and stage-timeout caps |
| `test_units.py` | `split_ref` / `dedup_key`, manifest extraction + glob fallback, schema conformance of fixtures, artifact-contract shape; **neutral-register prompts** — `render_prompt_pair` finds/renders a `.neutral.md` companion or returns `None` when absent, `neutralize_audit_prompt` softens narrative vocabulary while leaving the PROHIBITED TECHNIQUES block byte-identical |
| `test_ledger.py` | `Ledger.run_cost`/`run_call_count` combine a run with its second-opinion children (`-soN`) so the `--budget` ceiling and reported cost reflect TRUE total spend, not just the primary pass's own rows; unrelated runs never leak into each other's total; a run_id containing a literal `%`/`_` doesn't turn into an unintended LIKE wildcard; the `duration_ms`/`failure_kind`/`label` migration adds the columns cleanly to a pre-existing DB fixture |
| `test_runner.py` | the runner strips network/mutation tools even when a stage requests them; headless command is read-only/sandboxed |
| `test_headless.py` | strict parser over the **real** captured envelope, shape-drift fail-loud, recoverable-vs-API-error classification, turn/cost caps, `--max-budget-usd` present / no `--max-turns`, session-budget math, empty/malformed/non-zero-exit handling, audit partial-recovery; **`--claude-api-key`**: injects `ANTHROPIC_API_KEY` into the subprocess env, coexists additively with `CLAUDE_CONFIG_DIR` (both set), stays `None` when neither knob is set, CLI/API config passthrough |
| `test_recon_compare.py` | controlled vuln-index ablation (actual prompt inclusion/omission, base-input hash equivalence, persisted resume config), run-path/JSON normalization, structural signals, confound warnings, global diff bounds, malformed/oversized input rejection, and a read-only zero-model-call CLI comparison |
| `test_links.py` | `--links` parsing/normalization/merge, repo-drop safety rule, schema survival, propagation into a rendered prompt, backward compatibility |
| `test_pipeline.py` | full mock pipeline end-to-end, golden `REPORT.md`, dedup/merge, scope-filter + validation drops, missing-manifest fallback, partial-session recovery, oversized-findings (no truncation), ledger cost + resubmission, dry-run, **research stage on/off** (Stage-1 brief + threat intel; `--no-research` stays offline), no-submit guardrail |
| `test_evidence.py` | **F1 claim/evidence contract**: legacy finding upgrade, idempotent normalization, proof-level derivation across audit/validate/corroborate/deep-verify/ASan/runtime/live/maintainer sources, private-comment separation, contradiction preservation, report/draft obligations, and pipeline ordering |
| `test_api.py` | the HTTP API on the mock runner: full run lifecycle, dry-run, SSE stream to terminal, artifact whitelist, 404s, costs/knowledge/fixes/**quality** endpoints, chat roundtrip + test-gen, **C3 zip upload → run** (+ non-zip rejected) |
| `test_uploads.py` | **C3 safe extraction**: single-top-dir vs flat repo root, **path-traversal rejected**, entry-count cap, empty/bad-zip rejected |
| `test_fixes.py` | Phase-6 remediation + verify: patch-target parsing, **mechanical diff from full-file rewrites** (multi-hunk applies + compiles, new-file, no-op/malformed ignored), accept a compiling fix, reject one that breaks compile, reject a non-applying patch, **ignore pre-existing errors** (only count introduced ones), end-to-end fix generation (via `FIX.json`); **A3 re-audit** — the `on_patched` hook (incl. a raising hook captured), the still-present matcher, and `generate_fixes(re_audit=True)` aggregation |
| `test_benchmark.py` | Phase-7 scoring: perfect/FN/FP cases, CWE mismatch + alias + line-tolerance matching, suite loading, end-to-end `run_suite` + `--fixes` + A/B; **A1** — case provenance, optional brief, `parallel_cases` (order + provenance); **A3** — `re_audit` rate folded into `patch_quality`; **`compare_backends`** — the N-way `{backends, totals_by_backend}` report shape against a single-element `backends=["mock"]` run, plus a backend-agnostic unit test of the aggregation/rollup logic against three hand-built `run_suite`-shaped dicts |
| `test_quality.py` | **A2 accept-rate**: `record_triager_feedback` + `accept_rate` (severity slice, run-scoping), the old-DB column migration, `quality_report` pairing accept-rate with benchmark recall, and the `argo feedback --import` → `argo quality` CLI flow |
| `test_model_catalog.py` / `test_screening_planner.py` | deterministic catalog/pricing, Codex stage precedence, read-only content-keyed screening, explainable plans, profiles, and lazy mixed-backend routing |
| `test_chat.py` | **B1 re-validation**: candidate backfill, `_validate_candidate` runs the adversarial validator, full `ask()` flow (model writes `CANDIDATE_FINDING.json` → verdict appended, hypothesis file kept out of `generated`), and the no-candidate path |
| `test_cancel.py` | **C1 mid-stage cancellation**: `AgentRunner._exec` runs a real subprocess, kills it **promptly** when the cancel_event fires (not after the full sleep) and on timeout, returns a CompletedProcess on success; the orchestrator turns a mid-stage `RunnerCancelled` into a cancelled run (status.json) |
| `test_runtime.py` | **R1–R4 runtime verification**: the safety validators (`assert_loopback_only` rejects external/scope hosts + protocol-relative; `validate_probe_plan` caps request count, body size, and read-only methods unless opted in), the stage's graceful-skip gating, a **Docker-gated end-to-end sealed-sandbox proof** (`--network=none` app container + a probe container sharing its loopback namespace), **R2** (`_generate_plan` LLM-proposes a plan, `_interpret` returns verdicts, full `run()` generates-then-skips without a recipe), **R3** (`_resolve_launcher` picks explicit config / argo-runtime.json / repo Dockerfile; `_dockerfile_expose` parses the port), **R2-auth** (`auth` login step is loopback-checked; login POST exempt from the read-only gate but probe POST still blocked), and **R4** (the report renders a finding's `runtime` verdict + evidence, and omits the block when absent — golden report stays stable) |
| `test_asan_poc.py` | **ASan PoC generation**: the `_applies` CWE/extension gate (memory-safety CWE + C/C++ affected file required), the `10_asan_harness_prompt.neutral.md` companion renders cleanly via `render_prompt_pair`, deterministic `_parse_sanitizer_output` (confirmed on a real ASan error shape, `crashed_no_sanitizer_output` on a signal with no sanitizer report, `not_reproduced` on a clean exit — never refutes the finding), `run()` gating (off by default, no validated findings, no eligible findings, `--max-findings` cap), the graceful skip when Docker is unavailable (asserts no harness session is even attempted), best-effort per-finding behavior (one finding's failure doesn't abort another's), and a **Docker-gated end-to-end proof**: the mock LLM emits a real textbook heap-buffer-overflow one-liner as `harness.c`, and the genuine `clang -fsanitize=address` compile+run+parse cycle must catch it |
| `test_uplift.py` | the **precision/depth uplift**: recon captures `ground_truth.json`; the **SCA** dependency stage flows a `dependencies` finding into the validated set (and `--no-sca` suppresses it); the **completeness-critic** re-pass adds nothing-but-duplicates in mock and spends extra sessions; **drift-repair** keeps a malformed finding (flagged `schema_repair_failed`) instead of dropping it; `_format_ground_truth` surfaces carve-outs + baseline-correct refs to the validator |
| `test_fallback.py` | **resilience**: `FallbackRunner` retries a session/rate-limited (429) call on the next backend (Claude→Codex→local), propagates non-retryable errors immediately, a circuit breaker skips a walled backend for the rest of the run, and each backend selects its own per-stage model; the chain mixes backends AND accounts (`--claude-accounts` via CLAUDE_CONFIG_DIR, `--codex-accounts` via CODEX_HOME); `build_runner` wraps a chain only when fallbacks/accounts are set; **failure-kind-aware backoff** — `_classify_failure_text` direct unit tests (incl. Claude's own safety-refusal wording, confirmed live, classified identically to Codex's moderation flag), `credits_exhausted` gets a longer cooldown than the hint-less default, an unrecognized kind falls back to the default, a `moderation_flagged` failure sleeps before retrying the *same* backend provider but not before a genuinely different one, and an end-to-end regression test drives the REAL `CodexRunner` (not a duck-typed fake) through a real `FallbackRunner` to prove a "produced no output" Codex failure now genuinely falls through instead of killing the run; **`--claude-api-keys`/`--codex-api-keys`** multi-account chains (mirroring the existing `--gemini-accounts` chain test) and directory-list-wins-over-key-list precedence for both backends; secret redaction extended to all 6 `_SECRET_FIELDS`; a write→load round-trip regression test proving a redacted secret never resurrects as the literal `"<redacted>"` string on load (the real bug this pass found in the already-shipped Gemini key handling) |
| `test_codex.py` | the **Codex backend**: the sandbox-mapping guardrails (audit stage is `-s workspace-write` + offline, **never** a `danger-*` escape; only `research` gets network), `--oss`/model flags, token parsing + cost estimation, `build_runner` dispatch, CLI/API config passthrough; **`_invoke` failure classification** — a subprocess timeout and a "no output at all" failure are both now `retryable=True` (previously neither was), classified into `moderation_flagged`/`credits_exhausted`/`unknown_retryable` from the real stderr text; **`--codex-api-key` bootstrap** — the cache-dir hash never contains the literal key, the key is piped over stdin only (never argv), bootstrap happens once then reuses the cached login on later calls, a login failure raises without leaking the key, concurrent bootstraps for the same key are serialized to exactly one real login attempt, `CodexRunner` uses the bootstrapped home and memoizes it across `_invoke` calls, and an explicit `--codex-home` wins over `--codex-api-key` |
| `test_gemini.py` | the **Gemini backend**: command construction (stdin-only prompt delivery, no `-p`; `--include-directories` for repo read access), Policy Engine guardrail mapping (offline stages deny shell/web tools; only `research`/`corroborate` get network), the strict parser over a real captured envelope + error shape, the moderation heuristic (`_looks_like_gemini_refusal` requires phrase co-occurrence, not a single keyword; bridges to `moderation_flagged`; a normal success is never flagged), `_invoke` failure classification (invalid-input exit is not retryable, turn-limit/timeout/startup-crash are), per-stage model tiering (`DEFAULT_GEMINI_STAGE_MODELS`), model override + `calibrated()`, `for_smoke()` priming `gemini_stage_models` too, cost estimation, `build_runner` dispatch, CLI/API config passthrough (`--gemini-model`/`--gemini-api-key`/`--gemini-accounts`) |
| `test_orchestrator_retry.py` | **orchestrator-level auto-retry**: `_run_stage_sequence` retries a retryable stage failure in place (bounded, real sleep mocked in tests) and can still succeed; retries are capped then propagate; `credits_exhausted` and a non-retryable failure are never auto-retried; a reset hint further out than the auto-retry sleep cap is not waited for (surfaces normally instead of hanging an unattended run); a cancelled run is never retried |
| `test_refusal_probe.py` | **cross-backend refusal-rate probe**: loading/validating the curated `refusal_prompts.json` fixture (malformed entries rejected), `_score_backend`'s pairing math — never flagged, flagged-then-recovered-on-retry, flagged-and-retry-also-flagged (not counted as recovered), flagged-with-no-retry-row (not recovered) — and an end-to-end `run_refusal_probe` on the mock runner |
| `test_context.py` | **`atomic_write_json`**: writes correct content and leaves no leftover `.tmp` file, creates missing parent directories, a write that fails before the atomic replace never touches the last-good file on disk, retries a transient Windows `PermissionError` then succeeds, and raises (rather than silently dropping the write) after a persistent one |
| `test_cli_resume_hint.py` | **`cli._run_with_resume_hint`**: returns the wrapped callable's result on success; on a real failure OR a `KeyboardInterrupt` (Ctrl+C is the most likely real-world interruption), prints the exact `argo resume <run_id>` command before re-raising; a clean `typer.Exit` passes through silently (no false-alarm resume hint on ordinary CLI control flow) |
| `test_audit_retry.py` | **audit-focus retry**: a focus whose *session* never started (backend blip, `exit_1`, zero tokens, no partial artifact) is retried once and can then succeed, restoring full coverage; a focus that produced a malformed answer is a RESULT and is never retried (re-rolling it would select on the output); the retry is bounded to one pass and a still-failing focus leaves the run honestly short rather than looping |
| `test_max_focuses.py` | **`--max-focuses`**: the cap keeps the first N planned focuses in slug order (decided before any focus runs, so it cannot depend on what a focus found), is a no-op above the planned count, names every skipped focus in the log, reaches `PipelineConfig` through `_build_config`, and rejects a cap below 1 (a cap of 0 would audit nothing and still exit 0) |
| `test_neutral_retry.py` | **neutral-register moderation-flag recovery**: `AgentRunner.run()` retries once, same backend, with a caller-supplied `neutral_prompt` on a `moderation_flagged` failure (short delay, distinct from `FallbackRunner`'s 90s same-provider cooldown); no retry when `neutral_prompt` is omitted (byte-identical to pre-feature behavior); no retry for any other failure kind; bounded to exactly one retry even if the neutral variant also flags |
| `test_grounding.py` / `test_grounding_fqn.py` / `test_grounding_symbolic.py` / `test_split_ref_locators.py` | **citation grounding** before validation: an explicit file that exists nowhere drops the finding (hallucinated location); a symbol-style or ambiguous citation is kept as `unresolved_refs` with one confidence notch down and an honest validator note; qualified names (`io.x.Foo.bar():26`, `pkg.login()`, inner classes) and prefix-truncated paths resolve to the one real file (cross-extension ambiguity and member-name proof required); `:L30` / `#L68-L73` tails; `split_ref` locator variants; root confinement and symlinks |
| `test_semantic_dedup.py` / `test_batching.py` | cross-focus **semantic dedup** of the same root cause at different call sites; validate/corroborate **batching** cuts session count without changing which findings survive |
| `test_infra_failure_classification.py` | `needs_runtime_verification` / `unknown` caused by an outage, a missing verdict or budget exhaustion is marked as "not examined", distinct from a genuine model judgement |
| `test_static_analysis.py` | bounded **parse-only static context** for validation: supported languages, definition lines, syntactic def-use and possible callers, path-escape rejection, hard size/time bounds, reproducible ordering, explicitly non-semantic |
| `test_checklists.py` / `test_census.py` / `test_design_context.py` | audit-prompt uplifts: the gated coverage **checklist**, the cross-file variant **census** worksheet, and the accepted-by-design list + anti-over-claim impact rules |
| `test_audit_findings_file_choice.py` / `test_audit_schema_nulls.py` | audit robustness for weaker models: picks the model-written findings file over the untouched seed; a schema-forbidden `null` never discards an otherwise valid finding |
| `test_recon.py` / `test_recon_unprefixed_prompts.py` | recon resilience: a synthesis cut-off that wrote ground truth but no audit prompts is repaired instead of aborting; template-conforming prompts saved without the `audit_` prefix are accepted |
| `test_resume.py` | **`argo resume`**: skips done stages with the persisted config, retries only failed audit focuses, upgrades legacy runs (evidence + report), clear error without `config.json`, fallback re-arming after `Retry-After`, redacted API keys must be re-supplied |
| `test_second_opinion.py` / `test_deep_verify.py` / `test_corroborate.py` | the opt-in **second-opinion** blind passes (isolated run dirs, merge before validate), **deep verify** (reconfirm / correct / split / merge / refute, cross-finding aware) and **corroboration** (fixed-upstream appendix, design-accepted suppresses drafts) on the mock runner |
| `test_target_memory.py` / `test_compose.py` / `test_incremental.py` / `test_review_questions.py` | **F2–F5**: revision-bound target memory (stale facts never trusted silently), deterministic exact-context attack-path composition that never alters findings, incremental review treating a diff as invalidation (not a boundary), private context packs and the non-blocking review-question queue with provenance-bearing answers and targeted re-validation |
| `test_freshness.py` | post-pin **freshness** check: commits touching a finding's file after the audited pin (same or sibling branch) are flagged, git failures never modify findings, executable transports/hooks disabled, option-shaped refs rejected, report appendix |
| `test_live.py` | **L1 live-testing safety core**: RoE authorization gate, in-scope-only scope lock, stage gating; the one executor test hits a loopback server the test scope declares in-scope |
| `test_codex_session_guard.py` | Codex local-model hardening: live turn cap, tool-loop and fail-streak tripwires, event capture outside the session cwd, disabled sub-agents, declared context window, recon JSON syntax repair |
| `test_mistral.py` / `test_mistral_vibe.py` / `test_mistral_server.py` | the **Mistral backends** (HTTP faked with `httpx.MockTransport`, the Vibe CLI faked from a captured envelope): routing/config and key precedence, the tool dispatcher's path policy (traversal/symlink escape denied, writes only in scratch), validated JSON writes for both tool paths, the tool loop (tokens, served model, loop/turn caps), HTTP 401/402/429/5xx mapping, OSINT-stage refusal, Vibe's isolated config and exit codes, and the `/models` + `RunConfig` API surface |
| `test_repo_integrity.py` | backend-agnostic **repo-integrity** check around every session: a session that mutates the audited repo copy fails closed with `failure_kind="repo_mutated"` |
| `test_ledger_migration_race.py` / `test_provenance_cli_versions.py` / `test_branding.py` | two processes migrating one fresh ledger; backend CLI versions resolved through PATH/PATHEXT (Windows `.cmd` shims); the "Produced by Argo" provenance footer and its toggle |
| `test_estimate.py` / `test_adaptive_knowledge.py` | cost **estimates** (historical-archetype range vs labelled cold start, extra stages cost more) and explicit, persisted adaptive escalation that defers when the session cap exceeds the remaining budget |

## Fixture replay versus real pre-audit checks

- **`--runner mock`** — full glue test end-to-end with deterministic fixtures. Most orchestration
  bugs live in the glue, not the model call; debug them here, not by burning real audits.
- **`--dry-run` with a real runner is not zero-cost** — runs ingest + recon (and enabled
  research) for real, then stops before audit. Inspect generated prompts before paying for
  the audit, but obtain approval for the recon/ingest spend first.
- **`--smoke` with a real runner is also real model execution**, not a free demo.

See the [agent guide](agent-guide.md) for executable free onboarding examples and
the distinction between static analysis, cloud inference and fully local operation.

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

### Vibe saved-login seam (opt-in, not CI)

First complete `vibe --setup` → **Launch browser** manually on the host/user that will execute
Argo. Use a benign fixture only. Verify the account and relevant Vibe usage counter at the provider;
native saved credentials do not by themselves certify a subscription/billing destination.
Then, after approval to consume allowance:

```bash
python -m argo.cli pipeline --smoke --runner mistral-vibe --mistral-vibe-auth stored \
  --timeout 180 --max-turns 5 --parallel 1 --no-research --no-corroborate
```

Do not add a fallback, API key, runtime/live tools or extra passes to make this succeed. Use an
external 15-minute process-tree deadline for an unattended integration test; session caps are not
a whole-run deadline. Inspect `status.json`, required artifacts, per-call metadata and unchanged
repo, not just the CLI exit code. A turn/time/token-limited session or partially recovered run is
not a completed smoke. A native canary needs enough tokens for Vibe's own system prompt; record
the approved actual caps and usage. Fake tests remain free and do not require the installed CLI,
keyring, subscription or credentials.
