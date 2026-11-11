# Changelog

All notable changes to Argo are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — see
[docs/releasing.md](docs/releasing.md) for what that means concretely for this project, in
particular while the version stays `0.y.z`.

## [Unreleased]

### Added

- `--codex-model-chain <id,id,...>`: a Codex model de-escalation chain, strongest first. It expands
  into one fallback entry per `(model × --codex-accounts)` (model-outer, so a strong tier is
  exhausted across every account before a weaker one), with any `--fallback` backends after. A
  non-terminal `moderation_flagged` or usage limit on a strong model advances the chain to a weaker
  tier automatically. Supersedes `--codex-model` for codex; `--smoke` ignores it. See
  [docs/backends.md](docs/backends.md).

### Fixed

- `corroborate` no longer crashes the pipeline when its offline `corroborate_docs` pass runs on the
  Claude (headless) or Gemini backend. Those default stage-model maps omitted `corroborate_docs`, so
  `model_for("corroborate_docs")` raised `KeyError` (e.g. when corroborate fell back onto Claude),
  killing the run after validate. The offline pass now uses the same model tier as the online
  corroborate pass on every backend.

## [0.15.1] - 2026-11-09

### Fixed

- Mistral Vibe JSON artifacts are validated through Argo's local writer before they can replace
  session files; ingest retains its independent final validation.

## [0.15.0] - 2026-11-09

### Added

- Explicit Mistral Vibe authentication selection (`key` / `stored`) through configuration, CLI,
  HTTP and the existing Vibe UI selector. Stored mode delegates to Vibe's native OS keyring while
  retaining the isolated Argo runtime home, without importing user profiles or falling back to an
  API key. Existing runs default to key mode and retain legacy credential precedence.

### Fixed

- Smoke presets retain narrower explicit session, stage-timeout, turn and cost/budget caps.
- Vibe session-envelope validation, normalized failure diagnostics and non-secret auth/version
  metadata; raw session diagnostics are not treated as safe public artifacts.
- Fresh Vibe homes/exports per invocation preserve private attempts without trying to delete
  native read-only cache blobs during Windows retries/resume.
- Preserve explicitly configured fallback routing for exhausted Vibe credits/unavailable models
  while keeping same-backend stage retries terminal and credential/auth failures fail-closed.
- HTTP preflight and saved execution config respect the same effective research switch; brief-less
  jobs disable both networked stages before checking Mistral routing, matching the CLI.

## [0.14.0] - 2026-11-07

### Added

- **Review questions in the API and web UI (F5).** `GET/POST /runs/{id}/questions` (list, or build
  the queue for a finished run), `POST /runs/{id}/questions/{qid}/answer` (provenance required, no
  model call) and `POST /runs/{id}/revalidate-context` (re-validates only the affected findings).
  A new **Questions** tab answers and re-validates from the browser. `RunConfig` gains
  `review_questions_enabled`. Until now this was CLI-only (`argo questions`, `answer-question`,
  `revalidate-context`).
- **CI integration: `argo sarif` and `argo gate`.** `sarif` exports a finished run's reportable
  findings as SARIF 2.1.0 for GitHub code scanning: one rule per CWE, level and `security-severity`
  from the effective severity, a stable dedup-key fingerprint, and file locations only for explicit
  path citations. It validates against the official OASIS schema. `gate --fail-on High` exits 1
  when reportable findings reach the threshold. Both reuse the report's rules (confirmed only unless
  `--include-unverified`; never design-accepted, fixed-upstream, refuted or stale) and make no model
  calls. New `docs/ci.md` with a GitHub Actions example (`--profile cost-saver`,
  `--incremental-base`, explicit budget).
- **Benchmark corpus: 5 -> 19 cases.** 14 real-target cases (43 labels; moquette, ds4, proxysql,
  gitea, surrealdb, navidrome, pocketbase, baserow, FreshRSS, PHP-CS-Fixer) from maintainer
  verdicts. Only publicly described issues are included (published advisory, CVE or public fix PR),
  and every pinned commit is verified upstream. Each label carries `category` and `severity`.
  `MANIFEST.json` records coverage by category and severity, plus the public-inclusion rule.

### Fixed

- **Web UI: a slow tab could overwrite the one selected after it.** Switching tabs while the
  previous one was still loading showed the stale tab's content. Late responses are now discarded.

### Added

- **Live chat activity (B2).** While the analyst works on a chat turn, the web UI shows a step
  count and the last actions (commands, files read, interim notes) instead of a bare spinner. New
  `POST /runs/{id}/chat/stream` (NDJSON: `activity` lines, then the same payload as
  `POST /runs/{id}/chat`) and `chat.ask(on_activity=)`. Runners expose an optional `on_activity`
  sink: Claude (switching to `--output-format stream-json` only while a viewer is attached; the final
  `result` event is the same envelope), Gemini (also `stream-json`, rebuilt into the json envelope),
  Codex (from its `--json` events) and Mistral API report; Vibe shows the spinner only for now. Results, ledger and guardrails are unchanged.


## [0.13.1] - 2026-11-07

### Fixed

- **Claude backend could not write its artifacts (0.13.0).** Claude Code checks every file write,
  `Write` included, against `Edit(...)` permission rules, so the `Write(./**)` rule shipped in
  0.13.0 authorized nothing and the first session (ingest) failed with "model did not produce
  scope.json". The scoped rule is now `Edit(./**)`: writes inside the session's scratch directory
  are allowed, writes elsewhere are still denied. Verified with a real `--smoke` run.
- **Fallback backends start from a clean scratch directory.** When a backend fails and the chain
  moves on, the failed attempt's files are moved to `<dir>.failed-<n>` instead of being collected
  together with the next backend's output.
- **Runtime probe URLs parsed case-insensitively.** `HTTP://host/...` and host-less `http:` values
  are checked as URLs (and rejected unless loopback), matching how the probe runner sends them.
- **CI:** actions pinned to commit SHAs (Dependabot keeps them current); a Windows job runs the
  suite on Python 3.13.

## [0.13.0] - 2026-11-07

### Changed

- **Breaking for API scripts.** `argo serve` requires its per-process token on every API call
  (`X-Argo-Token` header, or the cookie set by the printed link), and `POST /runs/{id}/fixes` no
  longer accepts `build_cmd`/`docker` (use `argo fix`). The Claude backend runs in the default
  permission mode with path-scoped rules instead of `bypassPermissions`. `--budget` is documented
  as a launch gate, not a hard ceiling.

### Security
- **Claude sessions confined to their working directories.** The Claude backend now runs in the
  default permission mode with path-scoped allow rules: reads only inside the scratch directory and
  the audited repo, writes only in the scratch directory. The Mistral API backend's `glob`/`grep`
  skip symlinked files.
- **Local API hardened.** `argo serve` now prints a tokenized link: every API call needs that
  per-process token (an HttpOnly `SameSite=Strict` cookie set by the link, or an `X-Argo-Token`
  header). CORS is removed, the `Host` header must be a loopback address, and run ids in URLs must be
  a single path component inside the runs directory. `POST /runs/{id}/fixes` no longer accepts
  `build_cmd` or `docker` (CLI-only). Scripts using the API must send the token.
- **Web UI and report hardened against model-controlled HTML.** Rendered markdown is sanitized with
  vendored DOMPurify, chart tooltips escape their labels, the UI is served with a `script-src 'self'`
  CSP (inline script moved to `js/theme-init.js`), and `REPORT.md` escapes `<` in model text
  (identifiers and paths unchanged).
- **Ingest of an untrusted local source.** The copied `.git/config` of a local folder is replaced
  by a minimal one before any git command runs (repository format, object-format extensions and
  the `origin` URL only). Settings that execute commands (`core.fsmonitor`, `core.sshCommand`,
  filters, `include.path`) are gone, hooks are removed, and a `.git` gitdir-pointer file is dropped.
  `_make_readonly` no longer follows symlinks, so links in a target cannot change permissions of
  files outside the run directory.

### Fixed
- **Freshness check could not fetch on Linux/macOS.** Before fetching it restored write access to
  the files in the read-only `.git` but not to its directories, so `git fetch` failed with
  `cannot open '.git/FETCH_HEAD': Permission denied` and no branch was checked.
- **`--budget` enforced at every session launch.** The check moved into the runner, so it covers
  every stage and backend; previously stages checked once before fanning out, and several stages
  not at all. A refused session is `budget_reached` (not retried, no backend fallback); validate
  labels its findings "per-run budget reached". Docs no longer call it a hard ceiling: sessions in
  flight can overshoot it. The Mistral API backend now honours the per-session cost cap.
- **Sessions that fail without a result are ledgered** (timeout, startup failure) with their
  failure kind; a Claude timeout is now retryable like Codex and Gemini.
- **Effective-dated prices applied.** Token-based cost estimates use the price in effect on the
  call date; previously the undated catalog price was used, so an expired introductory rate stayed
  in force.
- **`model_unavailable` not retried in place.** The orchestrator no longer re-runs a stage for it,
  a fallback chain benches that account for the run, and the Codex check reads only stderr and CLI
  error events (not tool output).
- **Live audit log written as requests are sent.** `live_audit_log.jsonl` gets one flushed line per
  request; previously it was written at the end of the stage and lost if the interpret session was
  cancelled or failed.
- **Gemini reports tool calls as turns** (`stats.tools.totalCalls`), so `session_max_turns` applies
  to that backend.
- **Per-finding validate path** (`validate_batch_size <= 1`) flags a malformed verdict file for
  review instead of crashing.
- **`argo serve` failed on a package install.** `python-multipart`, needed by the zip-upload
  endpoint, was listed in `requirements.txt` but not in `pyproject.toml`, so an install from the
  package metadata could not create the app (`RuntimeError: Form data requires
  "python-multipart"`). Found by the 2026-11-07 end-to-end run. It is now declared, and a test
  checks that every runtime requirement is declared in `pyproject.toml` (the same gap as `httpx`
  before v0.12.1).
- **Citation grounding could still drop findings whose file exists.** Whether a cited file exists was
  decided from the content index, which covers only source extensions, files up to 2 MB and the
  first 8000 files. So a prefix-truncated `.vue`/`.svelte`/`.erb` citation, or any file past that cap
  in a large repository, was dropped as "not in repo". The v0.12.4 note ("only an explicit file that
  exists nowhere is dropped") did not hold in those cases. Existence now comes from a complete
  name-only listing (every file, no cap; `.git` and symlinks skipped); the cap applies only to
  reading contents for symbol checks. Files too large to read are never flagged as having an
  out-of-range line.

## [0.12.4] - 2026-11-06

### Fixed

- **Symbol-style citations were dropped as "primary file not in repo".** Validate dropped any
  finding whose primary citation was not a resolvable path: Go/TS/Rust/PHP/Ruby/C++/Swift symbols
  (`auth.Session.Check():7`, `crate::auth::check()`), Kotlin top-level functions, Java inner
  classes and Python packages. Only an explicit file path that exists nowhere is dropped now. An
  unresolved or ambiguous citation is kept in `grounding.unresolved_refs` (new optional field). As
  the primary citation it marks the finding `ungrounded` (confidence -1), with a validator note
  that this is not proof of absence.
- **Citation resolution picked a file by extension order or without proof.** `Foo.java` +
  `Foo.kt` is now ambiguous, and a name-based match needs the cited member in the file (an
  unrelated `auth.py` no longer absorbs `auth.Session.Check()`). `.groovy`/`.kts` are indexed.
  `pkg.login()` resolves to `pkg/__init__.py`, `Outer.Inner.work()` to `Outer.java`, and `:L30` /
  `#L68-L73` line tails are kept.
- **Prefix-truncated paths had no excerpt.** `api/orders.py:7` counted as grounded through its
  basename, but the validator got "source not found". A unique suffix match is now rewritten to the
  real path, so excerpts and static context read that file. Symlinked files are no longer indexed,
  and direct path checks stay inside the repo root.

## [0.12.3] - 2026-11-06

### Fixed

- **Qualified-name citations were dropped as "not in repo".** A finding citing
  `io.x.Foo.bar():26-35` (Java/Kotlin/Scala/C#/Python dotted name) instead of a path was dropped
  pre-validation by citation grounding. Validate now resolves such a citation to the unique repo
  file (`.../io/x/Foo.java:26-35`) before grounding; ambiguous or absent names stay unchanged and
  are still judged. Seen on 4 Mistral Medium findings in the 2026-11-06 moquette replay.
- **Run provenance lost CLI versions on Windows.** `meta.cli_versions` recorded `None` for
  claude/codex/gemini because npm installs them as `.cmd` shims and a bare argv[0] does not apply
  `PATHEXT`. The command is now resolved with `shutil.which` first, as the runners already do.
  Tests stub the probe so mock pipelines no longer spawn the developer's real CLIs.

## [0.12.2] - 2026-11-06

### Changed

- **Model catalog refreshed (2026-11-06)** from the providers' model, pricing and deprecation pages,
  with every current model probed through its CLI. Added `gpt-6.1-terra`, `gpt-6-cyber`, `gpt-5.4`,
  `gpt-5.4-mini`, `gpt-5.3-codex`, `gemini-2.5-flash`/`-pro`, `claude-fable-5`, `claude-mythos-5`,
  `claude-opus-4-8`/`4-7`/`4-6`, `claude-sonnet-4-6`, `claude-opus-4-5-20251101`,
  `claude-sonnet-4-5-20250929`. Corrected prices for `gpt-5.5` ($5/$30), `gpt-5.6-terra` ($2/$12)
  and `gpt-5.6-luna` ($0.20/$1.20). Shut-down models marked `retired`, scheduled ones `deprecated`
  with dates. Defaults unchanged. See `docs/backends.md` "Model catalog".

### Fixed

- **Codex "model unavailable for this login" was retried as transient.** codex-cli refuses a model
  that a ChatGPT plan does not include, or that a `daybreak = true` profile does not allow. These
  are now `failure_kind = model_unavailable`, with the fix in the message: no same-account stage
  retry, but the next `--codex-accounts` entry or `--fallback` backend is still tried.

## [0.12.1] - 2026-11-06

### Fixed

- **`--runner mistral-api` failed to import after `pip install .`** without `requirements.txt`:
  `httpx` was only a `dev` extra in `pyproject.toml`. It is now a runtime dependency.
- **Recon and audit no longer re-run a session that cannot succeed.** Their internal retries
  fired on any session failure, so an exhausted account (observed: Mistral `402 API budget
  exhausted`) or a rejected key was retried once more for nothing. Failures in
  `runner.TERMINAL_FAILURE_KINDS` (`credits_exhausted`, `auth_failed`, `credential_bootstrap`,
  `invalid_request`, `unsupported_stage_tool`, `repo_mutated`, `model_mismatch`) now end the stage's
  own retry; transient failures (timeouts, network) are still retried once. Cross-backend
  `--fallback` is unchanged.

## [0.12.0] - 2026-11-06

### Added

- **`--runner mistral-api`: Mistral models on any OS.** Argo runs the agent loop itself over the
  Mistral Chat Completions API (`argo/mistral_api.py`): the model gets only `read_file`, `list_dir`,
  `glob`, `grep` (repo copy + scratch dir, `realpath`-confined) and `write_file` (scratch dir only,
  when the stage grants it); no shell, no network. Key from `ARGO_MISTRAL_API_KEY` /
  `MISTRAL_API_KEY`, only as the `Authorization` header. 401/403 fail fast (`auth_failed`), 429
  honours `Retry-After`, tool loops and the tool-call cap stop the session, old tool outputs are
  elided near the context window. `research`/`corroborate` (web) are refused in preflight unless
  disabled or rerouted. `.json` writes are validated in the tool (the model gets the exact error
  back and fixes it, instead of the stage failing on an unparseable findings file). New
  `--mistral-api-model`; `--stage-runner`/`--stage-model` accept `mistral-api`.
- **`--runner mistral-vibe`: the Mistral Vibe CLI, headless.** Each session runs `vibe -p` with an
  isolated, Argo-written `VIBE_HOME`: only `read_file` (+ `write_file` when the stage grants it),
  shells/web/MCP/subagents off, `outside_workdir = "deny"`, the repo readable through one encoded
  path grant (never `--add-dir`). Tokens and Vibe's cost estimate from `export.json`; exit codes
  mapped (1 config, 2 runtime, 3 limit); 401/403 fail fast. Verified with mistral-vibe 3.1.0.
  New `--mistral-vibe-model`.
- **Mistral models in the catalog, with verified prices** (docs pricing table + `GET /v1/models`,
  2026-11-06): `mistral-large-4` ($0.70/$2.10 per 1M, the `mistral-api` default),
  `mistral-small-2603` ($0.15/$0.60), `codestral-2508` ($0.30/$0.90). `mistral-large-latest`
  (still Large 3) and `mistral-medium-latest` (Medium 3.5) are listed as deprecated with no price,
  so their cost stays `unknown` instead of `$0`. Run provenance now records the `vibe` CLI version.
- **Mistral in the HTTP API and web UI.** `RunConfig` takes `mistral_api_model` /
  `mistral_vibe_model` / keys (redacted) and `research_enabled` / `corroborate_enabled`; `GET /models`
  lists both Mistral backends (catalog prices, Vibe `installed`); the New Run and Settings runner
  selectors offer them and switch web research/corroboration off for them. `POST /runs` now answers
  400 (not 500) for an invalid routing/config. `bench-cross` cheap tier uses `mistral-small-2603`;
  adaptive validation escalation may pick a configured Mistral fallback.
- **Repo-integrity check on every backend.** Each LLM session is bracketed by a metadata
  fingerprint of the audited repo copy (path, type, size, mtime, mode; symlinks not followed). A
  session that modifies the copy fails closed with `failure_kind="repo_mutated"` (not retryable)
  after its call is logged. Until now repo safety rested on ingest's best-effort chmod plus each
  backend's own policy; this detects a breach regardless of backend.

### Fixed

- **Parallel runs crashed on a fresh ledger.** Two `argo` processes opening a new shared ledger
  in the same second both ran the schema migration; the slower `ALTER TABLE` failed with
  `duplicate column name`. That benign race is now tolerated; other SQLite errors still raise.

## [0.11.1] - 2026-11-05

### Fixed

- **Real findings dropped as "ungrounded citation".** `split_ref` only understood `path:LINE`;
  citations such as `File.java:addToTree()`, `File.java (method x)` or `File.java#L10` were
  treated as a whole-string path, so citation grounding declared a real file "not in repo" and
  dropped the finding before validation. The leading file path (and a `#L`/`line N` locator) is
  now extracted; genuinely missing files are still dropped.
- **Recon prompts silently ignored without the `audit_` prefix.** A template-conforming prompt
  saved as e.g. `authorization_bypass.md` was dropped, so planned focuses never ran (a local 9B
  lost 2 of 3). Such files are now accepted (renamed `audit_<name>.md`) only when they carry the
  template's section headers, and still pass the unchanged well-formedness gate.
- **Audit focus re-run although findings existed.** When the model wrote its findings to a
  differently named `SECURITY_FINDINGS__*.json` (local models drop the `audit_` slug prefix), Argo
  picked its own untouched seed file, reported "no checkpointed findings" and re-ran the focus.
  The model-written file now wins over an untouched seed.
- **Validate crashed on `"validation": {}`.** Empty stage objects are treated as absent, and the
  audit stage now drops model-supplied `validation`/`corroboration`/`verification` entirely: an
  auditor must not pre-fill (or self-confirm) verdicts owned by later stages.

## [0.11.0] - 2026-11-05

### Fixed

- **Audit findings checkpointed incrementally.** Each focus seeds its findings JSON before the
  session and the backend rewrites it after every finding, so a crash or timeout keeps the
  findings written so far (#60).
- **Codex turn cap was never enforced.** `num_turns` was hard-coded to 0 for Codex, so
  `--max-turns` had no effect. Codex events are now streamed and the cap is enforced mid-session.
- **Runaway Codex sessions.** Identical-call loops and failure streaks (e.g. a broken sandbox) stop
  the session early (`failure_kind = tool_loop`) instead of running to the stage timeout or the
  model server's context limit.
- **Recon discarded on one bad character.** A malformed `repo_profile.json` gets one syntax-only
  repair session before the unchanged validity gate; the original is kept as `.malformed`.
- **Valid findings dropped over one `null`.** Audit normalization now treats a schema-forbidden
  `null` on an optional property as absent (and on a required array as `[]`), recursively, before
  the unchanged schema gate. Local models emitted `"validation": null` and
  `"obligations_satisfied": null`; each previously discarded a correct finding.
- **Offline Codex stages could search the web.** The workspace-write sandbox does not cover
  Codex's provider-side `web_search` tool; an audit session used it and Ollama forwarded the query
  to its cloud endpoint. Every non-network stage now runs with `web_search="disabled"`.

### Added

- `argo revalidate-context` re-runs adversarial validation only for findings marked stale by
  answered context questions, refreshing evidence/questions/report and preserving the rest.
- `argo resume` reopens audit at focus granularity: completed focuses are skipped and only
  missing/retryable ones re-run (#58).
- `--verify-high` deep-verifies only validation-confirmed High/Critical survivors;
  `--verify-max-findings N` caps the sessions (#59).
- Redesigned web audit workspace; clearer synthetic-demo labelling and Argo branding.
- Agent-first onboarding (`AGENTS.md`, agent guide) and documentation refreshes (#50–#57, #61).
- `--codex-context-window` / `codex_context_window` declares a local model's window so Codex
  auto-compacts before Ollama/LM Studio silently discard context.
- Codex session events are persisted under `<run>/work/.argo_sessions/`.

### Changed

- **`--max-turns` now applies to Codex runs** (one turn = one completed tool call). Codex runs that
  set a low cap and previously finished will now stop at it; size it for a whole session.
- Codex sessions run with `--disable multi_agent` (`codex_disable_features`): sub-agents escaped
  every per-session guard and the event stream.

## [0.10.0] - 2026-10-21

### Added

- **Model catalog and provenance.** Current Codex/Gemini/Claude IDs, lifecycle/pricing metadata,
  requested-versus-served model IDs, CLI versions, effort, and mismatch state are persisted with
  each run; exact pins fail closed unless substitution is explicitly enabled.
- **Per-stage and mixed-provider routing.** `--stage-runner`, `--stage-model`, and Claude-only
  `--stage-effort` support deterministic user overrides while preserving shared guardrails.
- **Offline screening/planning.** `argo screen`, `argo plan`, `argo show-routing`, and credential-free
  `argo profiles` provide explainable fingerprints, objective plans, and pre-run routing review.

- **Benchmark evidence and adaptive routing.** Repeated trials now separate invalid runs, preserve
  target/model/catalog provenance, and expose cost/latency statistics. Evidence-aware planner hints,
  budget-bounded opt-in adaptive escalation, and a validated frozen corpus are included.

- **Shared API/UI controls.** The FastAPI service and vanilla SPA expose the same screening, planning,
  catalog, routing, and profile behavior as the CLI.

- **Recon ablation comparison.** `pipeline --no-vuln-index` isolates the curated index input, while
  `compare-recon` checks commit/input/backend comparability and emits bounded structural diffs of
  existing recon artifacts. It is offline and deliberately does not turn proxy counts into a
  precision or recall claim.
- **Backend/account attribution.** Each LLM call now records a redaction-safe backend/account
  label in llm_log.jsonl, making fallback and multi-account behavior auditable without exposing
  credential paths or API keys.

### Fixed

- Normalize Windows-shaped account directories on every host before deriving redaction-safe
  backend labels, so CI and local logs never leak the configured path.

## [0.9.0] - 2026-10-08

### Added

- **Revision-bound target memory.** Carry provenance-backed facts between runs while checking
  their source revision; stale or unsupported context is not treated as current evidence.
- **Incremental review.** Prioritize changed code and its neighborhood while retaining full-repository
  coverage; unchanged code is not declared safe merely because it was not changed.
- **Evidence-gated attack paths.** Compose paths only from exact, supported relationships, without
  changing finding severity or inventing missing edges.
- **Private context packs and review questions.** Export bounded context for human/model review and
  surface provenance-backed questions without blocking the pipeline.

## [0.8.0] - 2026-10-05

### Added

- **Deterministic evidence contract before reporting.** Findings now carry an additive exact claim,
  attacker start, preconditions, capabilities, proof obligations, remaining uncertainty, and typed
  evidence records. The new pipeline stage runs immediately before report generation, makes no model
  call or probe, and keeps native artifacts intact.
- **Proof-aware reports and drafts.** REPORT.md identifies the technical proof level, open
  obligations, and evidence-consistency warnings. Contradictory technical evidence, stale
  claim/revision snapshots, or unresolved consistency errors stay reviewable but suppress
  submission/PR drafts rather than silently deleting a finding.
- **Separate external disposition.** Current-run maintainer acceptance/rejection is recorded
  separately from technical proof; private feedback prose is not copied into run artifacts.

### Changed

- Runtime/live evidence only promotes technical proof when it has both an explicit interpretation
  and a decisive captured observation. A fallback based only on a probe matching an expected result
  cannot promote proof, and normalized evidence does not copy raw response bodies.
- Resuming a completed run created before the evidence stage now regenerates its report and drafts
  instead of leaving the old report stale.

### Fixed
- **`survivors_not_actually_validated` reported 0 for runs whose validation sessions had failed.**
  The detector matched a hand-written list of rationale prefixes, one of which read
  `"validation session failed:"` with a colon while the stage writes
  `"validation session failed; see the local LLM log for diagnostics"` with a semicolon. Every run
  that lost a validation batch to a session or backend failure therefore reported that nothing had
  been skipped, while its own log said findings had been flagged for human review — the statistic
  that exists to catch a degraded gate was the one hiding it. The rationales are now module
  constants referenced at both the write sites and the detector, so they cannot drift apart again.
  Same treatment applied to `corroborate.py`, where `"corroboration row failed schema validation"`
  was never in the list at all. Two further survivors now counted honestly: a schema-repaired
  finding kept without adversarial validation (the stage already logged it as "kept unvalidated"),
  and a corroboration row that failed schema validation. The existing tests could not have caught
  this — they listed the same strings by hand, so test and code shared one belief; they now iterate
  the modules' own constants and assert the exact sentence each stage writes.
- **Audit: a focus whose session never started is now retried once instead of abandoned.**
  Both backends can fail inside the same minute (a transient limit, `exit_1` with zero
  tokens and no partial artifact) and the stage used to drop that focus permanently — a run
  could finish clean having audited one of three focus areas, which makes its finding count a
  property of when it ran rather than of the target. Retried once after `audit_retry_delay_s`
  (90 s), controlled by `audit_retry_passes` (0 restores the old behaviour). Only SESSION
  failures retry: a malformed or schema-invalid findings file is a result and stands, because
  re-rolling until the model emits something parseable would be selecting on the output.


### Added

- **`--max-focuses N`** on `pipeline`, `run` and `estimate` — cap the audit fan-out to the first N
  of the focus areas recon planned, in slug order. The config field already existed but was
  reachable only through `--smoke` (which pins it to 1). Recon decides the fan-out from the
  repository, and across 108 real runs it chose anywhere from 1 to 7 focuses (mode 3), so a raw
  finding count is only comparable across targets when the audited surface is held constant. The
  cut is content-blind and fixed before any focus runs, so it cannot depend on what a focus found,
  and the skipped slugs are named in the log rather than dropped silently. A cap below 1 is
  rejected at parse time.
- Web UI **Overview dashboard** (the new landing at `#/`): KPI stat tiles plus theme-aware,
  dependency-free charts — findings by severity, findings by verification (proven vs.
  needs-runtime-check), runs by outcome, top CWEs, spend by run, runs by archetype — aggregated
  across all runs. A severity-mix donut also appears on each run's Findings tab.
- Self-hosted **Inter + JetBrains Mono** variable fonts (`webapp/assets/fonts/`) — no runtime CDN,
  offline-safe with system fallbacks.

### Changed

- Web UI restyle: refreshed dark palette and typography, a redesigned New-run page (focal
  code-to-audit input, mode option cards), the Costs page upgraded to stat tiles + cost-by-model/stage
  charts, and a monochrome SVG icon set (`webapp/js/icons.js`) replacing all emoji glyphs.

## [0.7.0] - 2026-08-21

### Added

- `argo corroborate --only ID,ID` for targeted re-corroboration that preserves every other
  survivor's existing verdict; deep-verify now prints the exact follow-up command when a finding
  splits into new children.
- Deterministic, zero-LLM grounding metadata now flags conservative "possible composite finding"
  signals for human review in logs and `REPORT.md`, without changing verdict or severity.

- **Explicit API keys for the Claude and Codex backends** (`--claude-api-key`/`--claude-api-keys`,
  `--codex-api-key`/`--codex-api-keys`), matching what Gemini already had. Claude needs only a bare
  `ANTHROPIC_API_KEY` (coexists additively with `--claude-accounts`); Codex does not accept a bare
  env var — Argo bootstraps a dedicated, cached `CODEX_HOME` for it via `codex login
  --with-api-key` (key piped over stdin only, never argv; cached under
  `~/.argo/codex_homes/<sha256-of-key>`, never the literal key in a path). Both are real secrets —
  redacted in `runs/<id>/config.json`, `type="password"` in the web UI, never echoed back over the
  HTTP API. `argo resume` gained `--claude-api-key`/`--codex-api-key` (alongside the pre-existing,
  now-actually-working `--gemini-api-key`) to re-supply a redacted key on resume.

### Fixed

- Citation grounding now detects numeric `affected` line citations beyond the actual file length,
  downgrading confidence and warning the validator without auto-dropping the finding.
- **`pipeline_config_from_dict` never de-redacted a secret on load.** A `config.json` written by a
  Gemini run stored the literal string `"<redacted>"` for `gemini_api_key`; loading it back (`argo
  resume`/`argo chat`) set the field to that literal string — truthy, so it was injected as the
  actual `GEMINI_API_KEY`, clobbering any real ambient key and silently breaking auth. Found and
  fixed while adding the Claude/Codex key fields (which would have tripled the blast radius);
  redacted secrets now come back `None`/`[]` on load, never resurrected as the sentinel string.
- `argo resume --gemini-api-key` didn't actually exist as a CLI option despite `docs/backends.md`
  documenting it — `resume` now genuinely accepts it (and the new Claude/Codex equivalents).
- **`corroborate` mixed repo content and network access in one session**, contradicting its own
  documented guarantee. Now runs two isolated passes per finding: an offline docs/VCS-history pass
  (repo-mounted, no network) and a separate OSINT pass (networked, no repo mount, no source
  excerpts in its prompt) — closing the gap without losing the OSINT capability.
- A full self-audit pass (Argo audited its own codebase, then a dedicated pass over the new
  API-key code) surfaced and fixed dozens more real issues: git clone/checkout hardened against
  option and `ext::` transport injection, guardrail scope/host/redirect checks tightened, secrets
  redacted consistently across config/logs/failure diagnostics, several path-containment and
  permission gaps closed, and Codex credential-bootstrap directory validation hardened.
- A guardrail's audit-prompt check required one exact safety-instruction phrasing; a model that
  paraphrases it equivalently no longer fails the check.
- `runtime.py` was missing an import that would crash any real run with Docker actually available
  (a live-Docker-only code path, so untested by CI).
- `report.py` could leave a stale submission draft behind for a finding a later stage went on to
  refute — drafts are now cleaned up to match the current survivor set on every regeneration.
- Two spots (`argo/stages/second_opinion.py`, the test suite's own cleanup helper) restored write
  permission on the wrong path when removing a hardened repo copy — POSIX needs it on the *parent*
  directory to delete anything inside, not the entry itself; this passed on every prior CI run
  purely because nothing had exercised a hardened directory tree deeply enough to hit it before.

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
