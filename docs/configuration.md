# Configuration

All tunables live in `PipelineConfig` (`argo/config.py`), an immutable dataclass. The CLI
builds one from flags; tests and the orchestrator can build one directly. Derive variants with
`with_overrides(...)`, `with_stage_model(stage, model)`, `calibrated()`, or `for_smoke()`.

## Model assignment

Model IDs:

```python
OPUS   = "claude-opus-4-8"
SONNET = "claude-sonnet-4-6"
HAIKU  = "claude-haiku-4-5-20251001"   # cheapest; used by --smoke
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
| `sca_enabled` | `--sca / --no-sca` | run the software-composition (dependency) stage between audit and validate (default on) |
| `runtime_enabled` | `--runtime` | **opt-in** sandboxed runtime verification after validate (default **off**) — build the target into an egress-blocked, loopback-only container and probe ONLY the local instance; see [runtime-verification-study.md](runtime-verification-study.md) |
| `runtime_image` / `runtime_run_cmd` / `runtime_port` | `--runtime-image` / `--runtime-run-cmd` / `--runtime-port` | explicit launcher (highest priority). **R3** also auto-resolves an `argo-runtime.json` recipe or the repo's own `Dockerfile` when these are unset |
| `runtime_build_timeout_s` | — | R3: max seconds to docker-build a recipe/repo Dockerfile (default 1800) |
| `runtime_max_requests` / `runtime_min_request_interval_s` / `runtime_max_payload_bytes` / `runtime_allow_state_changing` | — | anti-DoS caps + read-only-by-default method gate enforced by `guardrails.validate_probe_plan` |

## Other fields

| Field | Default | Meaning |
|---|---|---|
| `runner` | `headless` | `headless` (Claude Code) · `codex` (Codex CLI / OpenAI / OSS) · `mock` — see [backends.md](backends.md) |
| `runner_fallbacks` | `--fallback` | ordered fallback backends (e.g. `--fallback codex`) — when the primary hits a **retryable** session/rate-limit (429), the same call is transparently retried on the next backend (`FallbackRunner`), with a per-run circuit breaker. Each backend selects its own model for the stage. |
| `codex_model` / `codex_oss` / `codex_local_provider` | `None` / `False` / `None` | (runner=codex) model id; open-source provider toggle; `ollama`/`lmstudio`. Codex cost is **token-estimated** (`MODEL_PRICING`), not authoritative |
| `excerpt_context_lines` | 40 | ± lines of source attached around each cited `file:line` in Stage 4 |
| `excerpt_max_bytes` | 60000 | hard cap on total excerpt bytes per finding |
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
