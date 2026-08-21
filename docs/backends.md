# Backends (model providers)

Argo runs the same multi-stage pipeline on a **swappable agent backend**, so a user can run it with
whatever they already have — **Claude Code**, the **Codex CLI** (OpenAI), the **Gemini CLI**
(Google), or a **local / open-source** model — without changing the audit logic. This also makes
Argo a vehicle for **cross-model comparison** in the study: identical prompts and pipeline,
different model, measured side by side.

## The abstraction

Every LLM call goes through one chokepoint, `AgentRunner.run()` (`argo/runner.py`), which is
backend-neutral: it derives the **session policy**, enforces guardrails, logs cost, applies caps,
then delegates two per-backend steps:

- `_invoke(...)` — launch the backend and return its raw result;
- `parse_envelope(...)` — normalize that result into the common `LLMResult`.

```
AgentRunner (ABC)
├─ HeadlessClaudeRunner   # `claude -p` — Claude Code
├─ CodexRunner            # `codex exec` — OpenAI, or local/OSS via --oss
├─ GeminiRunner           # `gemini` — Google, tiered per stage like Claude
└─ MockClaudeRunner       # fixtures (zero tokens; the test suite)
```

`build_runner(config)` dispatches on `config.runner ∈ {headless, codex, gemini, mock}`.

## The guardrails are backend-neutral, enforced per backend

The invariants are one **`SessionPolicy`** (`guardrails.session_policy(stage)`) — *"no network except
the `research` stage; the repo is never writable"* — and each backend translates it into its own CLI
dialect. This is the safety-critical part and is unit-tested for **both** backends.

| Guarantee | Claude (`HeadlessClaudeRunner`) | Codex (`CodexRunner`) | Gemini (`GeminiRunner`) |
|---|---|---|---|
| Repo **read-only** | repo via `--add-dir`; ingest also chmods it read-only | repo lives **outside** the workspace + chmod read-only → readable, not writable (we deliberately do **not** `--add-dir` the repo, which would make it writable) | repo via `--include-directories`; the SAME `ingest`-time chmod backs this, backend-agnostically — see the note below |
| Writes only the scratch dir | session cwd = scratch + `Write` tool | `-s workspace-write` with cwd = scratch | session cwd = scratch (no additional path-scoping beyond the repo chmod — see the note below) |
| **No network** (all stages but research) | network tools stripped from the allowlist | `-s workspace-write` (sandbox denies egress) | Policy Engine denies `google_web_search`/`web_fetch` (and `run_shell_command`, always) |
| **Network only for `research`**/`corroborate` | OSINT tools kept for those two stages | `-c sandbox_workspace_write.network_access=true` for those two stages | the two web-tool `deny` rules are simply omitted from the policy for those two stages |
| No interactive blocking | `--permission-mode bypassPermissions` | `codex exec` is non-interactive (no approval prompt) | `--approval-mode yolo` |
| Never a sandbox escape | network/mutation tools always disallowed | never `danger-full-access` / `--dangerously-bypass-*` | `run_shell_command` always denied; no yolo-mode escape hatch used |

Tests: `tests/test_guardrails.py` (the policy + Claude tool stripping), `tests/test_codex.py`
(`test_build_cmd_is_sandboxed_and_offline_for_audit`, `test_only_research_gets_network` — the
equivalent re-validation for the Codex sandbox), and `tests/test_gemini.py`
(`test_offline_stage_denies_shell_and_web_tools`, `test_only_research_and_corroborate_get_network`
— the equivalent for the Gemini Policy Engine).

> **Note on the network guarantee.** For Claude, "no network" is enforced by the tool denylist
> (a named-capability allowlist). For Codex it relies on the **OS sandbox** contract of
> `workspace-write` (writes confined to the workspace, egress denied). For Gemini it is the **Policy
> Engine** tool denylist (same *dialect* as Claude's — see "Gemini specifics" below for why this
> backend does NOT use `--sandbox`). We assert our command never enables network outside
> `research`/`corroborate` and never uses an escape flag; for Codex the sandbox itself is the
> enforcement, for Gemini the Policy Engine's tool removal is. A real network-blocked smoke is
> recommended before high-stakes Codex/Gemini use.
>
> **Note on repo-write safety across ALL three backends.** The strongest guarantee — the audited
> repo is never mutated — does not actually come from any backend-specific mechanism above. It comes
> from `argo/stages/ingest.py:_make_readonly`, which `os.chmod`'s every file in the acquired repo
> copy to strip write bits **before any runner touches it**, identically regardless of which backend
> the run uses. A `Write`/`write_file` call targeting a path inside the repo fails at the OS level no
> matter what a backend's own sandbox/policy would otherwise allow.

## Codex specifics (`runner = codex`)

`codex exec` with: `-s workspace-write`, `--skip-git-repo-check`, `--ephemeral`, `--json`,
`-o <last-message file>`, prompt on stdin. Options:

- `--codex-model <id>` (e.g. `gpt-5-codex`) — **omit to use the Codex CLI's own configured model** (recommended: it tracks the current best for your account).
- `--codex-oss` + `--codex-local-provider <ollama|lmstudio>` — run a **local / open-source** model
  through Codex (`--oss`). With a local provider the cost is ~$0.

### Local / open-source models (Ollama / LM Studio)

Any model that **Ollama** or **LM Studio** serves works — including **Qwen** (`qwen2.5-coder`,
`qwen3`, …) and **DeepSeek** (`deepseek-coder`, `deepseek-v3`, `deepseek-r1`, …). Pull it, then point
Argo at it:

```bash
ollama pull qwen2.5-coder:32b      # (or a DeepSeek model)
python -m argo.cli pipeline --runner codex --codex-oss --codex-local-provider ollama \
  --codex-model qwen2.5-coder:32b --brief BRIEF.txt --repo PATH
```

Argo just adds `--oss --local-provider ollama -m <model>` to `codex exec` (unit-tested in
`tests/test_codex.py::test_oss_and_model_flags`); cost is ~$0 (local models estimate to $0).

**Caveat — model capability, not plumbing.** Some stages are format-strict: recon must emit audit
prompts that carry the RoE / prohibited-techniques / "Do NOT patch" anchors *verbatim* (a
well-formedness guardrail), and audit must emit schema-valid findings JSON. A **capable** coder model
(e.g. `qwen2.5-coder:32b`, `deepseek-v3`/`-r1`) is recommended; very small models (≈7B) may fail the
strict stages. Which local models clear the bar is exactly what the **benchmark** (`argo bench`)
measures — that cross-model comparison is a study result, not an assumption. The OpenAI path
(gpt-5.5) is validated end-to-end; a local-model run depends on your having Ollama/LM Studio up with
the model pulled.

**Cost is estimated, not authoritative.** Claude Code returns `total_cost_usd` per call (and Argo
hands it `--max-budget-usd` for a hard mid-session kill). Codex reports **tokens, not dollars**, so
Argo *estimates* USD from token usage × a small price table (`config.MODEL_PRICING` /
`estimate_cost_usd`); unknown and OSS/local models estimate to **$0** (tokens are still logged). The
consequence: with Codex the hard *mid-session* budget kill is unavailable; the per-run budget abort
between stages still applies, on the estimated cost. This is a deliberate, documented degradation —
see [design-decisions.md](design-decisions.md).

## Gemini specifics (`runner = gemini`)

`gemini --output-format json --skip-trust --approval-mode yolo -m <model> --policy <toml>
--include-directories <repo_dir>`, prompt on **stdin only** — no `-p` (confirmed: `-p` APPENDS
stdin rather than replacing it, and piping the prompt alone triggers the identical non-interactive
JSON path, avoiding that quirk and any OS argv-length limit on Argo's large audit prompts).
`--skip-trust` is **required**: a fresh, never-interactively-trusted scratch dir otherwise makes the
CLI exit 55 ("not running in a trusted directory") — every headless automation hits this, not just
Argo. Options:

- `--gemini-model <id>` (e.g. `gemini-3.1-pro`) — flat override across **every** stage, applied
  before `--calibration`/`--audit-model` so those can still bump individual stages on top. Omit to
  use the built-in per-stage tiering (below).
- `--gemini-api-key <key>` — sets `GEMINI_API_KEY` for this run; omit to use the ambient env var or
  an existing `gemini` CLI login (OAuth). **This is a real secret** (unlike `--claude-accounts`/
  `--codex-accounts`, which are directory paths) — it is redacted to `<redacted>` in
  `runs/<id>/config.json`, so `argo resume --gemini-api-key <key>` needs the key re-supplied to use
  it again (`resume` accepts the equivalent `--claude-api-key`/`--codex-api-key` for those two
  backends too — see [API keys](#api-keys----claude-api-key----codex-api-key) below). A narrow,
  deliberate deviation from `resume`'s normal zero-flags behavior.
- `--gemini-accounts key-a,key-b` — chain multiple `GEMINI_API_KEY` **values** (multi-account,
  limits are per-key). Unlike Claude's `CLAUDE_CONFIG_DIR` dirs or Codex's `CODEX_HOME` dirs, Gemini's
  practical automation-auth lever is the key value itself, so this list holds raw secrets, not paths
  — same redaction as above applies.

### Why the Policy Engine, not `--sandbox`

Gemini CLI has its own OS-level sandbox (`--sandbox` / `-s`), and an early version of this backend's
design planned to use it, mirroring Codex's `-s workspace-write`. Empirical testing (2026-08-17,
`gemini-cli` v0.49.0) found two problems that changed that plan:

1. **Hard external dependency.** `--sandbox` pulls a remote Docker/Podman image
   (`.../gemini-cli/sandbox:<version>`) and fails outright (`FatalSandboxError`) if no
   Docker/Podman daemon is reachable — confirmed live: it failed on a dev machine that had Docker
   Desktop *installed* but not *running*. Claude and Codex have no such dependency; making Gemini
   runs less reliable than the other two backends purely because a daemon wasn't up would be a real
   regression, not a wash.
2. **Not network/write-decoupled on the one dependency-free path anyway.** On Windows without
   Docker targeted, the CLI's own docs describe write-only confinement via `icacls` with no network
   control at all; the Docker/Podman engine (Linux, the most relevant path for CI/production) has no
   documented flag to keep writes confined while independently toggling network, the way Codex's
   `sandbox_workspace_write.network_access` does.

Instead, `GeminiRunner` uses the **Policy Engine** (`--policy <file>.toml`, `[[rule]] toolName=...
decision="allow"|"deny"|"ask_user"`) — confirmed live: a `deny` rule removes the tool from the
model's declared tool set entirely (the model reports having no such tool, never attempts the call),
clean and headless-safe, zero external dependencies. This is structurally the same *dialect* Claude
already uses (a named-tool allowlist/denylist), not Codex's OS-sandbox dialect — see the guardrails
table above. Repo-write safety does not depend on this policy at all; see the ingest-chmod note
above.

### Model tiering

Gemini is tiered per stage like Claude (not flat like Codex) — `DEFAULT_GEMINI_STAGE_MODELS`
(`argo/config.py`):

| Tier | Model | Stages |
|---|---|---|
| Pro | `gemini-3.1-pro` | recon, validate, verify, sca, remediate, asan_poc |
| Flash | `gemini-3.5-flash` | ingest, audit, report, chat, research, runtime, live, corroborate |

`for_smoke()` uses Flash-Lite (`gemini-3.1-flash-lite`) everywhere except recon (Flash) — the same
reasoning as Claude's Haiku/Sonnet smoke split. Pricing (`config.MODEL_PRICING`, confirmed
2026-08-17 from `ai.google.dev/gemini-api/docs/pricing`, USD/1M tokens, ≤200k-token prompts): Pro
$2.00 in / $12.00 out, Flash $1.50 / $9.00, Flash-Lite $0.25 / $1.50. As of 2026-04-01 Pro has **no
free tier** — only Flash/Flash-Lite retain free-tier access, which is exactly why the smoke config
avoids Pro entirely.

**Cost is estimated, not authoritative** — same caveat as Codex above (Gemini reports tokens, not
USD). One extra wrinkle found empirically: if `-m` is omitted, the CLI makes an internal
"utility_router" model call to pick a model, which also shows up in the envelope's token stats —
Argo always pins `-m`, and `estimate_cost_usd` sums tokens across every model that appears in a
call's stats regardless, so this never silently undercounts even in the (avoided) unpinned case.

**Moderation handling is heuristic, not a fixed signature — a known, documented gap.** Unlike
Claude's/Codex's classifiers, Gemini CLI does not surface a structured refusal signal in its JSON
output; a soft safety refusal comes back as an ordinary **success**-shaped response containing
declining prose. `GeminiRunner.parse_envelope` detects this via a conservative heuristic
(a first-person refusal phrase co-occurring with a safety/authorization-flavored word) and forces
the same `moderation_flagged` handling Claude/Codex get. A refusal phrased unusually enough to dodge
the heuristic will instead surface as a downstream "no artifact produced" failure — worth knowing if
a Gemini run behaves oddly on a sensitive-sounding brief.

## API keys (`--claude-api-key` / `--codex-api-key`)

Gemini has always supported an explicit per-run API key (above); Claude and Codex now do too,
closing a real gap — a real self-audit run this session needed the key set by hand in the shell
(`export ANTHROPIC_API_KEY=...`) before Argo itself could use it. Both are real secrets — redacted
to `<redacted>` in `runs/<id>/config.json`, never echoed back over the HTTP API, `type="password"`
in the web UI — see `PipelineConfig._SECRET_FIELDS`.

- **Claude — `--claude-api-key <key>`**: sets `ANTHROPIC_API_KEY` for this run. A bare key is
  enough on its own — no login step needed (confirmed empirically), unlike Codex below. Coexists
  **additively** with `--claude-accounts`/`CLAUDE_CONFIG_DIR` (two different env vars, no
  collision) — the Claude CLI itself gives billing precedence to `ANTHROPIC_API_KEY` when present.
  `--claude-api-keys key-a,key-b` chains multiple keys (multi-account via key, a separate mechanism
  from directory-based `--claude-accounts` — the directory list wins if both are set).
- **Codex — `--codex-api-key <key>`**: unlike Claude/Gemini, a bare ambient `OPENAI_API_KEY` env
  var does **not** authenticate `codex exec` (confirmed empirically: `codex login status` against
  a fresh `CODEX_HOME` with only the env var set reports "Not logged in"). Codex needs a real,
  stateful `codex login --with-api-key` bootstrap into a dedicated `CODEX_HOME` first. Argo does
  this for you: the key is piped over **stdin only** (never a CLI argument, so it never appears in
  process listings), into a directory cached under `~/.argo/codex_homes/<sha256-of-key>` (never the
  literal key in a path) — bootstrapped once, then reused on every later call/run with the same
  key. `--codex-home`/`--codex-accounts` (an explicit, already-logged-in directory) **win** if both
  are set for the same run — resolving to one `CODEX_HOME` value is a real collision, and an
  explicit directory is the stronger signal. `--codex-api-keys key-a,key-b` chains multiple keys
  (each gets its own bootstrapped `CODEX_HOME`; `--codex-accounts` wins if both are set).

## Verify your backend

```bash
# Claude
python -m argo.cli pipeline --smoke                          # the bundled ~$1 Claude smoke
python -m argo.cli pipeline --smoke --claude-api-key "$ANTHROPIC_API_KEY"   # via API-key billing
# Codex (OpenAI)            — needs `codex login`
python -m argo.cli pipeline --smoke --runner codex          # uses your Codex default model
python -m argo.cli pipeline --smoke --runner codex --codex-api-key "$OPENAI_API_KEY"   # via API-key bootstrap
# Codex (local / open-source) — free, needs Ollama/LM Studio running
python -m argo.cli pipeline --smoke --runner codex --codex-oss --codex-local-provider ollama
# Gemini (Google)           — needs GEMINI_API_KEY or an existing `gemini` CLI login
python -m argo.cli pipeline --smoke --runner gemini
```

`--smoke` keeps it cheap (one focus, low caps, research off). The mock runner (`--runner mock`)
covers the whole pipeline for free regardless of backend.

> **Validated end-to-end on real Codex.** A `--smoke --runner codex` run on the bundled fixtures
> drove all six LLM calls through `codex exec` (ingest → recon → audit → validate → report), every
> stage `is_error: false`: recon generated the custom audit prompts, audit produced findings,
> adversarial validation ran — the prompts are portable and the sandbox held. (Cost showed `$0`
> because the model logged as `codex-default`; tokens are recorded — see the cost note above.)

> **Validated end-to-end on real Gemini (2026-08-17, gemini-cli v0.49.0), honestly reported.** A
> `--smoke --runner gemini` run on the bundled fixtures produced a real, complete `REPORT.md` with a
> genuine finding (a left-pad prototype-pollution dependency, correctly surfaced by SCA → validate →
> report) and correctly DROPPED three audit-hallucinated findings whose citations didn't ground in
> the actual repo — real proof the full command → JSON-parse → cost-estimate → ledger → validate →
> report chain works for real. **Not a fully clean run, reported as such rather than rounded up**:
> `ingest`/`audit`/`sca` came back `is_error: false` (3 real logged sessions, $0.0755 total); `recon`
> hit a REAL free-tier daily quota exhaustion mid-session ("You have exhausted your daily quota on
> this model") — an operational constraint of Phase 0's own earlier testing having already spent a
> chunk of a very thin free-tier allowance (confirmed: the quota error itself reported a limit of
> just 20 requests/day for `gemini-3.5-flash`), not a GeminiRunner defect. What that failure *did*
> prove: it was correctly classified and surfaced as a `RunnerError`, and Argo's existing (Gemini-
> agnostic) recon partial-artifact recovery handled it gracefully — the pipeline still completed
> with real output, zero Gemini-specific recovery code needed. A fully clean run needs either a paid
> `GEMINI_API_KEY` or the free tier's daily quota to reset.

## Why this matters for the paper

Keeping the pipeline LLM-direct (no CPG/AST — see [design-decisions.md](design-decisions.md)) means
the *only* thing that changes between backends is the **model**. That turns Argo into a clean
instrument for a **cross-model study**: same corpus, same prompts, same guardrails, different model →
the precision (registry accept rate) and recall (benchmark) numbers become directly comparable across
Claude / OpenAI / Google / open-source models. The contribution is the pipeline + methodology; the
backend is a knob.

**Run the comparison**: `argo bench-cross --suite benchmarks/corpora --backends
headless,codex,gemini [--tier cheap|top]` runs the SAME labeled corpus once per backend at a
comparable model tier and reports cost/latency/precision/recall/F1 side by side (a genuinely N-way
comparison — `bench --ab-audit-model` stays a same-backend, two-model A/B, a different question).
`argo refusal-probe --backends headless,codex,gemini` measures a complementary, non-adversarial
axis: how often each backend's OWN safety classifier false-positives on a legitimate, authorized
security-audit prompt (`refusal_flag_rate`), and how often the same backend's existing neutral-
register retry recovers it (`refusal_recovery_rate`) — deliberately NOT jailbreak-resistance
testing, see `argo/refusal_probe.py`'s module docstring. Both default to a cheap tier so a full
3-backend sweep costs cents; `--tier top` is real, non-trivial spend across three paid APIs — see
[benchmarks/README.md](../benchmarks/README.md) before running it for actual paper numbers.
