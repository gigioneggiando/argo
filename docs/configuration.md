# Configuration

All tunables live in `PipelineConfig` (`argo/config.py`), an immutable dataclass. The CLI
builds one from flags; tests and the orchestrator can build one directly. Derive variants with
`with_overrides(...)`, `with_stage_model(stage, model)`, `calibrated()`, or `for_smoke()`.

## Model assignment

Model IDs:

```python
OPUS   = "claude-opus-5"
SONNET = "claude-sonnet-5"
HAIKU  = "claude-haiku-4-5-20251001"   # cheapest; used by --smoke

# Gemini, tiered per stage the same way (DEFAULT_GEMINI_STAGE_MODELS):
GEMINI_PRO        = "gemini-3.1-pro"
GEMINI_FLASH      = "gemini-3.5-flash"
GEMINI_FLASH_LITE = "gemini-3.1-flash-lite"   # cheapest; used by the Gemini --smoke run

# Codex, flat (not per-stage) — see the `runner` field below:
CODEX_TOP   = "gpt-5-codex"   # Codex's own coding-focused top model
CODEX_CHEAP = "o4-mini"       # a real lighter/cheaper model, mirrors Haiku/Flash-Lite's role
```

Per-stage defaults (`DEFAULT_STAGE_MODELS`), each overridable per run:

| Stage | Default | Why |
|---|---|---|
| ingest | Sonnet | cheap extraction, but never Haiku — misreading scope/RoE has outsized cost |
| recon | Opus | highest-leverage step; the whole audit's quality depends on the synthesis |
| audit | Sonnet | high-volume parallel fan-out (the headline tunable — see below) |
| validate | Opus | the lever on the accepted-report rate (downgrade-don't-delete; ground-truth-aware) |
| report | Sonnet | only used if report LLM-polish is ever enabled; report is deterministic by default |
| sca | Opus | software-composition analysis: read dependency manifests, flag known-vuln pins |
| corroborate | Sonnet | networked docs/VCS cross-check of each survivor (design-accepted / fixed-upstream) |
| verify | Opus | **opt-in** deep re-derivation of each survivor, full repo access, cross-finding aware |
| runtime | Sonnet | R2: propose loopback probe plans (offline, read-only repo) + interpret results |

**The audit model is the tunable that matters.** Validation can only remove false positives; it
cannot recover a bug the audit model never surfaced. So the audit model sets the missed-bug rate.
`--calibration` forces audit → Opus (use it for the first few programs and for high-value targets);
drop to Sonnet for broad low-value sweeps once a target class reliably yields good findings.

`config.for_smoke()` overrides everything to Haiku **except recon → Sonnet** (the recon synthesis
is guardrail-gated and Haiku is too unreliable at reproducing the template verbatim).

## Tool allowlists (defense in depth)

```python
READ_ONLY_TOOLS   = ("Read", "Grep", "Glob")            # analysis only
ARTIFACT_TOOLS    = ("Read", "Grep", "Glob", "Write")   # + write to the scratch cwd
NETWORK_TOOLS     = {Bash, WebFetch, WebSearch, Task, Agent, ...}   # NEVER allowed
MUTATION_TOOLS    = {Edit, MultiEdit, NotebookEdit}                 # NEVER allowed
```

The runner re-applies these on every call, so a stage cannot widen them. See
[guardrails.md](guardrails.md).

## Budgets and caps

| Field | CLI flag | Effect |
|---|---|---|
| `budget_usd` | `--budget` | HARD per-run ceiling; aborts remaining sessions once real spend hits it |
| `session_max_cost_usd` | `--session-budget` | per-session cap → the CLI's native `--max-budget-usd` |
| `session_max_turns` | `--max-turns` | per-session turn tripwire (post-hoc; this CLI has no native turn cap) |
| `session_timeout_s` | `--timeout` | default per-session wall-clock cap (1800s) |
| `stage_timeouts` | — | per-stage timeout overrides (`timeout_for(stage)`); seeded with `DEFAULT_STAGE_TIMEOUTS` (recon + audit → 3600s, since the deep ground-truth extraction and per-family walk need headroom) |
| `max_parallel_audits` | `--parallel` | concurrency cap for Stage 3 / Stage 4 fan-out (default 3) |
| `max_focuses` | (set by `--smoke`) | cap the audit fan-out to the first N focuses; truncation is logged |
| `audit_critic_passes` | `--critic-passes` | completeness-critic re-passes per audit focus (depth lever; default 1, 0 disables; loops until a pass adds nothing) |
| `audit_retry_passes` | — | retry a focus whose SESSION never produced anything (default 1, 0 disables). Only session failures retry; a malformed or schema-invalid answer is a result and stands. |
| `audit_retry_delay_s` | — | pause before that retry (default 90 s), long enough for a short backend backoff to clear |
| `validate_batch_size` | — | findings per adversarial-validation session (default 8). Collapses the one-session-per-finding fan-out — the main driver of session/rate-limit cost — with no precision loss (each finding is judged independently in the shared session). `1` = legacy per-finding path (also used by chat/B1 re-validate). |
| `corroborate_batch_size` | — | survivors per corroboration session (default 8), same batching rationale for the networked docs/VCS cross-check. |
| `sca_enabled` | `--sca / --no-sca` | run the software-composition (dependency) stage between audit and validate (default on) |
| `second_opinion_passes` | `--second-opinion N` | **opt-in** (default 0 = off): run N additional, fully independent blind recon+audit passes over the already-ingested scope/repo before validate, then merge their findings in. Uses the SAME model tiers as recon/audit (`model_for("recon")`/`model_for("audit")`) — no dedicated stage model. See [architecture.md](architecture.md#second-opinion-an-llm-audit-is-one-noisy-sample-not-the-answer) |
| `second_opinion_backend` | `--second-opinion-backend` | (`--second-opinion`) runner override for the extra passes only (e.g. `headless` when the primary run used `codex`), for genuine cross-engine diversity rather than re-sampling the same model. `None` = reuse the primary's backend |
| `verify_enabled` | `--verify / --no-verify` | **opt-in** deep-verify after corroborate (default **off** — the most expensive annotation stage: one full agentic session per finding, never batched, no excerpt budget). Independently re-derives each survivor from the actual source and reasons across the whole survivor set; see [architecture.md](architecture.md#deep-verify-why-a-separate-stage-from-validate) |
| `verify_max_findings` | `--verify-max-findings` | (`--verify`) hard cap on how many survivors get a deep-verify session (cost control on a large survivor set); `None` = every survivor. Findings past the cap are kept, un-deep-verified |
| `verify_max_attempts` | — | (`--verify`) retries per finding on a transient session failure before falling back to `inconclusive` (default 2 = 1 retry). Verify sessions are unbounded with no excerpt budget — real runs have seen 1-4M input tokens and $1-4/session — so a bare retry is worth the cost, unlike validate/corroborate's cheaper per-session failures. `1` disables the retry. |
| `runtime_enabled` | `--runtime` | **opt-in** sandboxed runtime verification after validate (default **off**) — build the target into an egress-blocked, loopback-only container and probe ONLY the local instance; see [runtime-verification-study.md](runtime-verification-study.md) |
| `runtime_image` / `runtime_run_cmd` / `runtime_port` | `--runtime-image` / `--runtime-run-cmd` / `--runtime-port` | explicit launcher (highest priority). **R3** also auto-resolves an `argo-runtime.json` recipe or the repo's own `Dockerfile` when these are unset |
| `runtime_build_timeout_s` | — | R3: max seconds to docker-build a recipe/repo Dockerfile (default 1800) |
| `runtime_max_requests` / `runtime_min_request_interval_s` / `runtime_max_payload_bytes` / `runtime_allow_state_changing` | — | anti-DoS caps + read-only-by-default method gate enforced by `guardrails.validate_probe_plan` |
| `live_enabled` | `argo live --i-have-authorization` | ⚠️ **opt-in, default off, AUTHORIZED USE ONLY.** Bounded **read-only** requests to the program's **in-scope** hosts to confirm findings. RoE-gated (`assert_live_authorized`: automation/safe-harbor/prohibited), in-scope-only (`assert_inscope_only`: out-of-scope/unknown/loopback blocked), capped + audit-logged. See [guardrails §2c](guardrails.md#2c-the-opt-in-live-exception-the-live-stage-in-scope-hosts-only) |
| `live_allow_writes` | `argo live --allow-writes` | **second** opt-in: permit **non-destructive** state-changing methods POST/PUT/PATCH (default read-only GET/HEAD/OPTIONS). **DELETE is never allowed.** A mutation's body is recorded in the audit log |
| `live_max_writes` | `argo live --max-writes` | (L3) separate cap on state-changing requests, enforced by `assert_live_write_policy` (default 5) |
| `live_max_requests` / `live_min_request_interval_s` / `live_request_timeout_s` / `live_max_payload_bytes` | `--max-requests` / `--min-interval` | anti-DoS caps (total count / rate / per-request timeout / body size); an oversized plan is rejected whole |
| `live_max_retries` / `live_max_redirects` / `live_user_agent` | — | executor robustness: retry transient errors (timeout/`5xx`/`429`) for **idempotent methods only**; follow at most N redirects, **each re-validated in-scope** (off-host redirects recorded, never chased); identify the tool via a `User-Agent` |

## Other fields

| Field | Default | Meaning |
|---|---|---|
| `runner` | `headless` | `headless` (Claude Code) · `codex` (Codex CLI / OpenAI / OSS) · `gemini` (Gemini CLI) · `mock` — see [backends.md](backends.md) |
| `runner_fallbacks` | `--fallback` | ordered fallback backends (e.g. `--fallback codex,gemini`) — when the primary hits a **retryable** failure (session/rate-limit, timeout, or a classified moderation-flag/credits-exhaustion signature), the same call is transparently retried on the next backend (`FallbackRunner`), with a per-run circuit breaker whose cooldown length depends on the failure's classified kind (longer for credits exhaustion, a real delay before retrying the *same* backend provider again after a moderation flag). Each backend selects its own model for the stage. See [architecture.md](architecture.md#the-agentrunner-abstraction) for the full failure-kind/backoff breakdown. |
| `claude_accounts` / `claude_config_dir` | `--claude-accounts` | **multi-account Claude**: an ordered list of `CLAUDE_CONFIG_DIR` paths, each a separate logged-in account (limits are **per-account**). The headless backend becomes an account-fallback chain — `account A → account B → --fallback`. Set up each once with `CLAUDE_CONFIG_DIR=<dir> claude login`. The runner injects `CLAUDE_CONFIG_DIR` (normalized, `~` expanded) per `claude` invocation. |
| `codex_accounts` / `codex_home` | `--codex-accounts` | **multi-account Codex**: the same via `CODEX_HOME` (default `~/.codex`). Set up each once with `CODEX_HOME=<dir> codex login`. A `codex` backend (primary or fallback) expands to one runner per account. |
| `codex_model` / `codex_oss` / `codex_local_provider` | `None` / `False` / `None` | (runner=codex) model id (e.g. `CODEX_TOP`/`CODEX_CHEAP`); open-source provider toggle; `ollama`/`lmstudio`. Codex cost is **token-estimated** (`MODEL_PRICING`), not authoritative |
| `gemini_stage_models` | `DEFAULT_GEMINI_STAGE_MODELS` | (runner=gemini) per-stage model dict, tiered like Claude's `stage_models` (`GEMINI_PRO`/`GEMINI_FLASH`/`GEMINI_FLASH_LITE`) — only consulted when `runner == "gemini"` |
| `gemini_api_key` / `gemini_accounts` | `--gemini-api-key` / `--gemini-accounts` | (runner=gemini) API key; **multi-account Gemini** via an ordered list of keys (the automation-auth lever is the `GEMINI_API_KEY` env var, so accounts are keys, not config dirs like Claude/Codex) |
| `claude_api_key` / `claude_api_keys` | `--claude-api-key` / `--claude-api-keys` | (runner=headless) `ANTHROPIC_API_KEY` for this run; a **separate** mechanism from `claude_config_dir`/`claude_accounts` — coexists **additively** (both env vars injected, no collision) since a bare key needs no login step, unlike Codex. Multi-account via an ordered list of keys. |
| `codex_api_key` / `codex_api_keys` | `--codex-api-key` / `--codex-api-keys` | (runner=codex) OpenAI API key; unlike Claude/Gemini, a bare env var does **not** authenticate `codex exec` — Argo bootstraps (once, cached under `~/.argo/codex_homes/<hash>`) a dedicated logged-in `CODEX_HOME` for it via `codex login --with-api-key` (key piped over stdin, never argv). `codex_home`/`codex_accounts` **win** if both are set for the same backend (avoids ambiguity between two ways of resolving one `CODEX_HOME` value). See [architecture.md](architecture.md#the-agentrunner-abstraction). |
| `excerpt_context_lines` | 40 | ± lines of source attached around each cited `file:line` in Stage 4 |
| `excerpt_max_bytes` | 60000 | hard cap on total excerpt bytes per finding |
| `attribution` | `--attribution / --no-attribution` | append a "Produced by **Argo**" provenance footer to `REPORT.md` / drafts + an attribution block to `fixes_report.json` (with `Generated-with:` / `Co-authored-by:` trailers for remediation PRs). **Default on** for every user; opt out with `--no-attribution`. Attribution only — never changes any license. See [`argo/branding.py`](../argo/branding.py). |
| `runs_dir` | `runs` | root dir for run artifacts |
| `prompts_dir` | `argo/prompts` | the version-pinned assets |
| `ledger_path` | `argo/ledger.sqlite` | the cost + findings ledger |
| `fixtures_dir` / `fixtures_scenario` | `tests/fixtures` / `happy` | mock-runner fixtures |

## Programmatic example

```python
from argo.config import PipelineConfig, OPUS

cfg = (PipelineConfig(runner="headless", budget_usd=20.0, max_parallel_audits=2)
       .with_stage_model("audit", OPUS))      # high-value target: audit on Opus
```
