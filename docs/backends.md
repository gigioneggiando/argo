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
├─ CodexRunner            # `codex exec` — OpenAI, or local/OSS via --oss / a custom provider (vLLM)
├─ GeminiRunner           # `gemini` — Google, tiered per stage like Claude
├─ MistralApiRunner       # Mistral Chat Completions + Argo's own sandboxed tool loop (argo/mistral_api.py)
├─ MistralVibeRunner      # `vibe` CLI under an isolated, Argo-written config (argo/mistral_vibe.py)
├─ MockClaudeRunner       # fixtures (zero tokens; the test suite)
└─ FallbackRunner         # an ordered chain of the above (accounts and backends; see "Fallback")
```

`build_runner(config)` dispatches on `config.runner ∈ {headless, codex, gemini, mistral-api,
mistral-vibe, mock}` and wraps a `FallbackRunner` when `--fallback` or multiple accounts are set.

## The guardrails are backend-neutral, enforced per backend

The invariants are one **`SessionPolicy`** (`guardrails.session_policy(stage)`) — *"no network except
the OSINT stages `research` and `corroborate`; the repo is never writable"* — and each backend
translates it into its own dialect. This is the safety-critical part and is unit-tested per backend.
The two Mistral backends have no web tools at all, so they refuse the OSINT stages up front (run them
with `--no-research --no-corroborate`, or route those stages to another backend); their read-only and
scratch-only rules are in [Mistral API specifics](#mistral-api-specifics-runner--mistral-api) and
[Mistral Vibe specifics](#mistral-vibe-specifics-runner--mistral-vibe).

| Guarantee | Claude (`HeadlessClaudeRunner`) | Codex (`CodexRunner`) | Gemini (`GeminiRunner`) |
|---|---|---|---|
| Repo **read-only** | repo via `--add-dir` (read access; no write rule covers it); ingest also chmods it read-only | repo lives **outside** the workspace + chmod read-only → readable, not writable (we deliberately do **not** `--add-dir` the repo, which would make it writable) | repo via `--include-directories`; the SAME `ingest`-time chmod backs this, backend-agnostically — see the note below |
| Writes only the scratch dir | session cwd = scratch + the path-scoped rule `Edit(./**)`; default permission mode denies everything else | `-s workspace-write` with cwd = scratch | session cwd = scratch (no additional path-scoping beyond the repo chmod — see the note below) |
| **No network** (all stages but research) | network tools stripped from the allowlist | `-s workspace-write` (sandbox denies egress) | Policy Engine denies `google_web_search`/`web_fetch` (and `run_shell_command`, always) |
| **Network only for `research`**/`corroborate` | OSINT tools kept for those two stages | `-c sandbox_workspace_write.network_access=true` for those two stages | the two web-tool `deny` rules are simply omitted from the policy for those two stages |
| No interactive blocking | `--permission-mode default` (in `-p`, unapproved actions are denied, not prompted) | `codex exec` is non-interactive (no approval prompt) | `--approval-mode yolo` |
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
> **Note on repo-write safety across ALL backends.** The strongest guarantee — the audited
> repo is never mutated — does not actually come from any backend-specific mechanism above. It comes
> from `argo/stages/ingest.py:_make_readonly`, which `os.chmod`'s every file in the acquired repo
> copy to strip write bits **before any runner touches it**, identically regardless of which backend
> the run uses. A `Write`/`write_file` call targeting a path inside the repo fails at the OS level no
> matter what a backend's own sandbox/policy would otherwise allow.
>
> chmod is prevention, and best effort (a process can chmod a file back). **Detection** sits on top of
> it, also backend-agnostic: `AgentRunner._run_attempt` fingerprints the repo copy
> (`runner.repo_fingerprint`: every entry's path, type, size, mtime and mode, symlinks not followed)
> before and after every session. Any change fails the session closed with
> `failure_kind="repo_mutated"` (not retryable), after the call has been logged, so its output is
> never used. Directory timestamps are excluded (NTFS updates them lazily); child
> creates/deletes/renames still show in the entry listing.

## Codex specifics (`runner = codex`)

`codex exec` with: `-s workspace-write`, `--skip-git-repo-check`, `--ephemeral`, `--json`,
`-o <last-message file>`, `--disable multi_agent`, prompt on stdin. Options:

- `--codex-model <id>` is a compatibility flat override. New runs use the explicit stage map:
  `gpt-6-astra` for recon/validate/verify, `gpt-6.1-sol` for audit/runtime, and `gpt-6-luna`
  for ingest/SCA/report. Use repeatable `--stage-model STAGE=ID` to override one stage.
- `--codex-model-chain <id,id,...>` is a model **de-escalation chain**, strongest first
  (e.g. `gpt-6-astra,gpt-6.1-sol,gpt-5.6-sol`). It expands into one chain entry per
  `(model × account)`, model-outer, so the strong tier is exhausted across every `--codex-accounts`
  entry before a weaker tier is tried; `--fallback` backends follow the whole codex chain. A
  moderation flag (`moderation_flagged`) or usage limit on a strong model is non-terminal, so it
  advances to the next tier automatically. It supersedes `--codex-model` for codex and assumes no
  per-stage codex models. Note: tiers in the same model family often share one moderation classifier,
  so a tier-chain mainly buys rate/usage-limit resilience; keep a different backend (Claude via
  `--fallback headless`) as the terminal low-moderation escape. Account/model pairs a plan does not
  serve (e.g. a `daybreak` account asked for a too-new model) surface as a non-terminal
  `model_unavailable` and are skipped at call time.
- `--stage-runner STAGE=backend` deliberately mixes providers while retaining the same guardrails;
  `argo show-routing` prints the resolved map before spending tokens.
- `--codex-oss` + `--codex-local-provider <ollama|lmstudio>` — run a **local / open-source** model
  through Codex (`--oss`). With a local provider the cost is ~$0.

### Local / open-source models (Ollama / LM Studio / vLLM)

Any model that **Ollama** or **LM Studio** serves works, including Qwen and DeepSeek. Pull it, then
point Argo at it:

```bash
ollama pull qwen3.8:27b
python -m argo.cli pipeline --runner codex --codex-oss --codex-local-provider ollama \
  --codex-model qwen3.8:27b --codex-context-window 131072 --brief BRIEF.txt --repo PATH
```

Argo just adds `--oss --local-provider ollama -m <model>` to `codex exec` (unit-tested in
`tests/test_codex.py::test_oss_and_model_flags`). A local model's cost is estimated at $0 but
recorded as `cost_source = unknown`, never as proven free (GPU time is not in the ledger).

**vLLM (or any OpenAI-compatible server).** Codex reaches it through a custom provider in its own
`CODEX_HOME`; Argo needs no extra flag. This is the setup of the 2026-11 replay experiments
(DeepSeek-V4.1-Flash, GLM-5.3 on B200 GPUs):

```toml
# $CODEX_HOME/config.toml
model = "deepseek-ai/DeepSeek-V4.1-Flash-1017"   # the server's --served-model-name
model_provider = "localvllm"

[model_providers.localvllm]
name = "local vLLM"
base_url = "http://127.0.0.1:8000/v1"
wire_api = "responses"
```

```bash
CODEX_HOME=/path/to/that/dir python -m argo.cli pipeline --runner codex \
  --codex-model deepseek-ai/DeepSeek-V4.1-Flash-1017 --codex-context-window 131072 \
  --no-research --no-corroborate --brief BRIEF.txt --repo PATH
```

Serve the model with tool calling enabled (vLLM `--enable-auto-tool-choice` plus the model's
`--tool-call-parser`), and run a one-file `codex exec` probe first: a model that cannot emit tool
calls fails every stage.

**Declare the server's context window.** Codex has no metadata for a local model ("Model metadata
... not found; defaulting to fallback metadata"), so it never auto-compacts and the server silently
drops context instead (Ollama logs `slot context shift`). Pass the window the server actually
loaded — `--codex-context-window 131072` for `OLLAMA_CONTEXT_LENGTH=131072` — and Argo adds
`-c model_context_window=N -c model_auto_compact_token_limit=0.8N`.

**Session guards (all Codex runs).** Argo streams the `--json` events while the session runs:

- `--max-turns N` is enforced **mid-session** (one turn = one completed tool call). Before this
  it was never enforced for Codex at all, so size N for a whole recon/audit session (a synthetic
  fixture recon used ~20–30 calls; real repositories need far more).
- The same tool call with the same result 6× in a row, or 20 consecutive failed tool calls,
  stops the session (`failure_kind = tool_loop`, retryable once). A sandbox that rejects every
  command shows up here instead of as a stage timeout.
- Every event is kept in `<run>/work/.argo_sessions/<stage>.codex.<label>.jsonl` — outside the
  model's working directory, so it cannot read its own transcript back or edit it.
- Codex `multi_agent` is disabled (`codex_disable_features`): a spawned sub-agent's tool calls,
  tokens and turns never reach the session's event stream, and a recon sub-agent was observed
  writing audit prompts without the safety template.

**Web search is a separate switch.** The sandbox's network denial does not cover Codex's
provider-side `web_search` tool, so Argo passes `-c web_search="disabled"` on every stage except
research. For local-only runs also start Ollama with `OLLAMA_NO_CLOUD=1`, so a model cannot reach
ollama.com through server-side tools.

**Sandbox prerequisite.** `workspace-write` needs a working bubblewrap. In unprivileged
containers (e.g. Kubernetes without `CAP_SYS_ADMIN`) bwrap may fail on `--dev` or `--remount-ro`;
every shell command then fails and a local model retries indefinitely. Verify with a one-file
`codex exec` probe before a pipeline run.

**Caveat — model capability, not plumbing.** Some stages are format-strict: recon must emit audit
prompts that carry the RoE / prohibited-techniques / "Do NOT patch" anchors *verbatim* (a
well-formedness guardrail), and audit must emit schema-valid findings JSON. A **capable** coder model
is recommended. Measured on a moquette replay (11 maintainer-validated vulnerabilities, 2026-11):
DeepSeek-V4.1-Flash and Qwen3.8-27B reached 8/11 in their best run, GLM-5.3-Flash 5/11 with a recon
format failure in one of two runs, Qwen3-Coder-Next 80B 1/11 and Qwen3.5-9B 0/11. Run-to-run
variance is large, so compare means over several runs before choosing (`argo bench` on the frozen
corpus). The OpenAI path depends on what the Codex login's plan allows: some current models are
refused by a ChatGPT plan or a `daybreak` profile (see [Model catalog](#model-catalog)); Argo
reports that as `model_unavailable` and moves to the next account or fallback backend.

**Cost is estimated, not authoritative.** Claude Code returns `total_cost_usd` per call (and Argo
hands it `--max-budget-usd` for a hard mid-session kill). Codex reports **tokens, not dollars**, so
Argo *estimates* USD from token usage × a small price table (`config.MODEL_PRICING` /
`estimate_cost_usd`); unknown and OSS/local models are marked **unknown** rather than falsely treated
as free (tokens are still logged). The
consequence: with Codex the hard *mid-session* budget kill is unavailable; the per-run budget abort
between stages still applies, on the estimated cost. This is a deliberate, documented degradation —
see [design-decisions.md](design-decisions.md).

## Mistral API specifics (`runner = mistral-api`)

`mistral-api` calls the Mistral developer API (Chat Completions with function calling) and runs
the agent loop **inside Argo** (`argo/mistral_api.py`). There is no external agent CLI, so it works
the same on Windows, Linux and macOS. The API only *proposes* tool calls; nothing touches the host
unless Argo's dispatcher executes it, so the dispatcher is this backend's enforcement:

| Tool | Scope |
|---|---|
| `read_file`, `list_dir`, `glob`, `grep` | read-only, inside the audited repo copy or the session scratch dir; paths resolved with `realpath`, so `..` and symlinks pointing outside are refused |
| `write_file` | only when the stage grants `Write`; only inside the scratch dir; never through a symlink; 4 MB cap |
| shell, process, network | **not offered** |

- **Offline stages only.** `research` and `corroborate` need web tools, which this backend does not
  have: the CLI refuses the run before any model call unless you pass `--no-research
  --no-corroborate` or route them elsewhere (`--stage-runner research=headless`). Without a brief
  both are off anyway.
- **Repo safety** is the dispatcher, ingest's chmod, and the per-session repo-integrity
  fingerprint (see the note above), the same layers as every other backend.
- **Key.** `ARGO_MISTRAL_API_KEY`, else `MISTRAL_API_KEY`; sent only as the `Authorization` header,
  redacted from `config.json`, errors and the event log. No key → `credential_bootstrap` before any
  request.
- **Errors.** 401/403 → `auth_failed` (not retried); 402 → `credits_exhausted`; 429 → waits for
  `Retry-After` (up to 8 times); 5xx/network → bounded backoff; other 4xx → `invalid_request`.
  Tool mistakes (bad path, bad regex) go back to the model as tool results, not as failures.
- **Bounds.** `--max-turns` caps tool calls per session; identical consecutive tool calls (4x) stop
  the session as `tool_loop`; tool results are size-capped; once the conversation nears the context
  window (`mistral_api_context_window`, default 128k tokens) the oldest tool outputs are elided,
  keeping the 8 most recent. The per-session event log is written next to (not inside) the scratch
  dir: `work/.argo_sessions/<stage>.mistral.<label>.jsonl`.
- **Models.** `--mistral-api-model` for every stage, `--stage-model STAGE=ID` per stage; default
  **`mistral-large-4`** (exact ID, priced $0.70/$2.10 per 1M tokens in/out, 1M context). Checked
  2026-11-06: `mistral-large-latest` still points at the deprecated Large 3 (`mistral-large-2512`)
  and `mistral-medium-latest` at the deprecated Medium 3.5, both without a published price, so they
  stay selectable but cost is `unknown` and budgets cannot be enforced on them. Cheap tier:
  `mistral-small-2603` ($0.15/$0.60). An alias resolving to a dated model is recorded in
  `served_models`, not treated as a substitution.

```
export ARGO_MISTRAL_API_KEY=...            # or MISTRAL_API_KEY
argo pipeline --repo ./target --brief brief.txt --runner mistral-api --no-research --no-corroborate
argo show-routing --runner mistral-api --stage-model audit=mistral-large-latest
```

## Mistral Vibe specifics (`runner = mistral-vibe`)

`mistral-vibe` runs the Mistral **Vibe** coding-agent CLI headless (`vibe -p --output json`),
verified with mistral-vibe 3.1.0 on Windows. Install it with `uv tool install mistral-vibe`. Vibe is
an agent with its own shell and web tools, so Argo never imports your Vibe configuration: every session gets
an **isolated `VIBE_HOME`** (next to, not inside, the scratch dir) with an Argo-written
`config.toml`:

- **Tools:** `read_file`, plus `write_file` when the stage grants `Write`. Every shell
  (`bash`/`powershell`/`git_bash`), `web_fetch`/`web_search`, `task`, `skill` and `edit` are
  disabled, and the shells are additionally `permission = "never"` (Vibe 3.1 may still *offer*
  `file_system.bash` to the model; a call is refused, never run).
- **Paths:** `--workdir` is the scratch dir and `outside_workdir = "deny"`, so writes stay in
  scratch. The repo is readable through a single encoded grant on `read_file` only
  (`vibe-path:directory_recursive:<repo>`). `--add-dir` is never used: it would make the repo
  writable. Observed: a write into the repo is refused (`tool_denied`).
- **Off:** MCP, subagents, connectors, background processes, project context (`AGENTS.md`),
  telemetry, update checks. Never `--auto-approve`, `--trust`, `--add-dir`.
- **Limits:** `--max-turns`, `--time-limit` (session timeout − 15 s), the process tree is killed on
  cancel/timeout. Exit 1 (config) → `invalid_request`; 2 (runtime) and 3 (a limit) → recoverable,
  partial scratch artifacts salvaged. Rejected credentials → `auth_failed`, known policy conflicts
  → `invalid_request`, exhausted allowance → `credits_exhausted`; these stop same-backend retries.
  Exhausted credits/unavailable models can still advance through an explicitly configured fallback
  chain; bootstrap/auth/invalid-request failures do not silently select another backend or account.
  A generic 403 is not proof of expired login, and a generic 429 is not proof of exhausted billing.
  Argo's dollar caps use reported/estimated usage and are checked after a Vibe call; this backend
  does not pass a native price cap. They are not hard in-flight billing limits. Keep time/turn caps
  as well as an approved budget and check the subscription counter separately.
- **Authentication:** explicit `--mistral-vibe-auth key|stored`, default **key** for compatibility
  (including old saved runs). In key mode the precedence is `config.mistral_vibe_api_key` →
  `ARGO_MISTRAL_VIBE_API_KEY` → `config.mistral_api_key` → `ARGO_MISTRAL_API_KEY` →
  `MISTRAL_API_KEY`; the resolved value reaches Vibe only as the child's `MISTRAL_API_KEY`.
  Missing/invalid keys never silently fall back to a saved login.
- **Saved login:** `stored` lets Vibe resolve the OS keyring itself, without Argo reading a token
  or copying your home/`.env`. Complete `vibe --setup` → **Launch browser** manually first. The
  same OS user must run Vibe and Argo (or the server); browser login on a client machine is not
  authentication for a remote server. Mistral key environment overrides are removed from the
  child; an explicit Vibe key in config is incompatible with stored mode. No `auto`, profile-home,
  dotenv bridge, or automatic browser setup. If the keyring is unavailable, fail and reauthenticate
  outside Argo rather than weakening isolation. Unsupported OIDC overrides are not enabled by Argo.
- **Models:** Vibe **aliases** (`--mistral-vibe-model`, default `mistral-medium-3.5` →
  `mistral-vibe-cli-latest`, i.e. Medium 3.5, which Mistral has deprecated for the API but still
  ships as Vibe's default); the served API name is recorded in `served_models`. Tokens and Vibe's
  own cost estimate come from `export.json` (`cost_source = provider_estimated`).
- **Trade-off:** Vibe 3.1 has no `grep` tool (search goes through the shell, which stays off), so
  this backend reads code with `read_file` only. Prefer `mistral-api` for large repos.
- Like `mistral-api`, `research`/`corroborate` are refused in preflight (no web tools).

These are native Vibe **tool/path policies, not an OS sandbox**. Argo keeps the repo-integrity
check as defense in depth. Inherited Vibe configuration overrides must not widen the policy;
the user/project home is never imported. Treat all session exports/transcripts as private even
when Vibe redacts config. API/UI expose only allowed artifacts and metadata, not raw sessions.
Each invocation gets a fresh home/export directory; prior attempts are kept private rather than
deleted or reused. This avoids stale dotenv/agent state and Windows read-only Vibe cache deletion
failures during retries or resume.

Stored mode identifies the chosen credential mechanism, not an independently verified browser
identity or entitlement. Resume preserves the mode but resolves credentials again: it cannot
guarantee the same person still occupies the keyring slot. Per-call auth metadata must say
`unknown` when the actual source cannot be verified. Provider-estimated USD cost and tokens are
not the subscription's billed amount or remaining allowance; check the relevant product/workspace
usage counter before expanding a real test. Do not use an account's monthly allowance as an Argo
spend authorization, and do not silently switch from Vibe included usage to the direct API.

```bash
uv tool install mistral-vibe
# Legacy key mode (default):
export ARGO_MISTRAL_VIBE_API_KEY=...
argo pipeline --repo ./target --brief brief.txt --runner mistral-vibe --no-research --no-corroborate
# Alternatively, after manual browser login, with separately approved usage:
argo pipeline --repo ./target --runner mistral-vibe --mistral-vibe-auth stored \
  --no-research --no-corroborate
```

## Gemini specifics (`runner = gemini`)

`gemini --output-format json --skip-trust --approval-mode yolo -m <model> --policy <toml>
--include-directories <repo_dir>`, prompt on **stdin only** — no `-p` (confirmed: `-p` APPENDS
stdin rather than replacing it, and piping the prompt alone triggers the identical non-interactive
JSON path, avoiding that quirk and any OS argv-length limit on Argo's large audit prompts).
`--skip-trust` is **required**: a fresh, never-interactively-trusted scratch dir otherwise makes the
CLI exit 55 ("not running in a trusted directory") — every headless automation hits this, not just
Argo. Options:

- `--gemini-model <id>` — flat override across **every** stage, applied
  before `--calibration`/`--audit-model` so those can still bump individual stages on top. Omit to
  use the built-in per-stage tiering (below).
- `--gemini-api-key <key>` — sets `GEMINI_API_KEY` for this run; omit to use the ambient env var or
  an existing `gemini` CLI login (OAuth). **This is a real secret** (unlike `--claude-accounts`/
  `--codex-accounts`, which are directory paths) — it is redacted to `<redacted>` in
  `runs/<id>/config.json`, so `argo resume --gemini-api-key <key>` needs the key re-supplied to use
  it again (`resume` accepts the equivalent `--claude-api-key`/`--codex-api-key` for those two
  backends too — see [API keys](#api-keys---claude-api-key----codex-api-key) below). A narrow,
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

Gemini is tiered per stage — `DEFAULT_GEMINI_STAGE_MODELS`
(`argo/config.py`):

| Tier | Model | Stages |
|---|---|---|
| Argon | `gemini-4-argon` | validate, verify, remediate, asan_poc |
| Flash | `gemini-3.8-flash` | recon, audit, runtime, live, corroborate |
| Flash-Lite | `gemini-3.5-flash-lite` | ingest, report, research, SCA/smoke |

`for_smoke()` uses Flash-Lite (`gemini-3.1-flash-lite`) everywhere except recon (Flash) — the same
reasoning as Claude's Haiku/Sonnet smoke split. Pricing is resolved from the date-stamped static
catalog (`argo/model_catalog.py`): Gemini 4 Argon is currently $2/$10 input/output per 1M tokens
(promotional through 2026-11-30, then $4/$20), and Gemini 3.8/3.6 Flash is currently $0.75/$3.75
(promotional through 2026-12-31, then $1.50/$7.50). Unknown/custom IDs remain explicitly
unpriced. As of 2026-04-01 Pro has **no
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

## Model catalog

`argo/model_catalog.py` is the single source for model IDs, prices (USD per 1M tokens, with
effective-dated `pricing_periods` for announced price changes), lifecycle and access. Selection
checks, cost estimates and budgets all read it. `argo catalog validate` checks it for duplicates.

**Refreshed 2026-11-06** from the providers' model, pricing and deprecation pages (Anthropic
`platform.claude.com/docs`, OpenAI `developers.openai.com/api/docs` + `learn.chatgpt.com/docs/models`,
Google `aistudio.google.com/docs`, Mistral `docs.mistral.ai` + `GET /v1/models`), then every current
model was probed with a one-line "reply OK" call through its CLI:

| Provider | Answered | Exists, but the test account could not use it | Gone / unavailable |
|---|---|---|---|
| Anthropic (Claude Code) | opus/sonnet/haiku-5-5, opus-5, sonnet-5, opus-4-8/4-7/4-6, sonnet-4-6, opus-4-5, haiku-4-5, sonnet-4-5 | fable-5-1, fable-5 (need usage credits on a subscription); mythos-5-1, mythos-5 (limited access) | — |
| OpenAI (Codex, ChatGPT login) | gpt-6-astra, gpt-6.1-sol, gpt-6.1-terra (daybreak off), gpt-6-sol, gpt-6-luna, gpt-5.6-sol/terra/luna | gpt-6-cyber, gpt-5.6-cyber (API with approved Daybreak access only) | gpt-5.5, gpt-5, o3, gpt-5-codex, o4-mini (not on Codex with ChatGPT login; several shut down) |
| Gemini (Gemini CLI) | 3.6-flash, 3.5-flash-lite, 3.1-flash-lite, 3-flash-preview, 2.5-flash | 4-argon, 3.1-pro-preview (429 daily quota), 3.8-flash (503 overloaded) | 2.5-pro (404) |
| Mistral (API) | mistral-large-4, mistral-small-2603 (calls, same day) | — | `-latest` aliases point at deprecated Large 3 / Medium 3.5 |

Changes in this refresh: added `gpt-6.1-terra` ($1/$5, Codex ≥ 0.159), `gpt-6-cyber`, `gpt-5.4`,
`gpt-5.4-mini`, `gpt-5.3-codex`, `gemini-2.5-flash`/`-pro` (shut down 2026-12-01),
`claude-fable-5`, `claude-mythos-5`, `claude-opus-4-8/4-7/4-6`, `claude-sonnet-4-6`,
`claude-opus-4-5-20251101`, `claude-sonnet-4-5-20250929` (retires 2026-11-30). Corrected prices:
`gpt-5.5` $5/$30 (was $1.25/$10), `gpt-5.6-terra` $2/$12 (was $2.50/$15), `gpt-5.6-luna`
$0.20/$1.20 (was $1/$6). Marked `gpt-5-codex`, `o4-mini` retired and `gpt-5`, `o3`, `gpt-4o`,
`gpt-4.1` deprecated with their shutdown dates. Defaults (`OPUS`/`SONNET`/`HAIKU`, `CODEX_*`,
`GEMINI_*`, `MISTRAL_*`) are unchanged: every default model still exists.

**Codex account caveats found by the probe.** With a ChatGPT login, Codex refuses models the plan
does not include ("not supported when using Codex with a ChatGPT account"), and a profile with
`daybreak = true` accepts only Daybreak-compatible models ("Daybreak is unavailable for model
…": `gpt-6-sol` and `gpt-5.6-sol` work, `gpt-6-astra`/`gpt-6.1-*` do not). Argo reports both as
`failure_kind = model_unavailable`: no same-account stage retry, but still eligible for the next
account in `--codex-accounts` or another `--fallback` backend.

**Re-running the check** (spends a few cents of real calls; run from an empty directory):

```
claude -p "Reply with exactly the word OK" --model <id> --max-turns 1 --output-format json
codex exec -s read-only --skip-git-repo-check --ephemeral -m <id> "Reply with exactly the word OK"
GEMINI_CLI_TRUST_WORKSPACE=true gemini -m <id> -p "Reply with exactly the word OK"
curl -s https://api.mistral.ai/v1/models -H "Authorization: Bearer $MISTRAL_API_KEY"   # free
```

Update prices only from the providers' own pricing pages, set `verified_at`, and keep an announced
future price as a `pricing_periods` entry instead of overwriting the current one.

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

### Per-session backend/account attribution

Every invocation is recorded in runs/<id>/llm_log.jsonl with backend and backend_account. The
account value is a safe label such as codex:codex-b[2] or codex:api-key[1]: this attribution field
never contains a credential or the full CODEX_HOME path. It makes fallback and rate-limit behavior
auditable without adding machine usernames or secrets to the per-call log. Existing cost and token
fields remain unchanged.

## Fallback and partial-work recovery

When a backend call fails, the bounded retry/fallback policy (`argo/runner.py`) retries the same
backend after a cooldown or switches to the next configured `--fallback` backend/account. Work is
not silently lost: stages that write incremental scratch artifacts (notably `audit`) glob the
scratch directory on a `RunnerError` and recover any partial findings a session left behind before
it died (the partial-salvage path in `runner.py`; `audit.py` salvage). The audit is **per focus**,
so a fallback redoes only the focus that failed, not the focuses that already succeeded.

Two failure shapes leave nothing to salvage, and they are the ones most often seen in practice:

- **Rate-limit / session-limit (HTTP 429).** The request is rejected before the model runs, so there
  is no partial output and essentially no token cost for that attempt; the focus is retried on the
  fallback (or after the reset) from scratch.
- **Content-moderation refusal.** The model returns no usable artifact (and may consume a small
  amount of input tokens); there is no partial finding to recover.

### Rejected: replaying the interrupted backend's transcript

A natural idea is, on fallback, to have the next backend read the *conversation transcript* of the
interrupted one (the Codex rollout JSONL, or the headless-Claude session `.jsonl`) so any findings
or reasoning produced before the interruption are not lost. We evaluated this and decided **not** to
build it:

- For the two common failure shapes above there is **nothing useful to read** — a 429 produced no
  model turn at all, and a moderation refusal produced only a refusal.
- The one case it would help — a session that produced substantial findings and then died *before*
  the write step — is **already covered** by the incremental-scratch checkpointing below.
- Re-feeding another backend's raw transcript has real downsides: a moderation-flagged transcript
  can **re-trigger** moderation on the fallback; transcript formats differ per backend; and it adds
  session-id→path resolution and transcript parsing surface for little gain.

Rather than parse a dead session's chat log, the recoverable case is made *always* recoverable by
the incremental checkpointing below, and a fully-failed focus is made independently resumable (see
"Runner resilience" in the roadmap — both shipped 2026-11).

## Incremental audit checkpoints

Each audit focus initializes its scratch findings JSON before the backend starts. The audit prompt
requires the backend to rewrite that file as valid JSON immediately after every completed finding,
keeping all earlier findings in each checkpoint. If a session crashes, times out, or returns without
a manifest, the existing scratch glob recovers the last valid checkpoint and the normal schema
repair/dedup pipeline still runs before the artifact reaches `runs/<id>/findings/`.

An untouched empty seed is not treated as an answer: normal bounded retry/fallback behavior still
applies when the backend failed before producing its first finding. Common pre-execution failures
such as rate limits and moderation refusals therefore do not turn into false empty audit results.

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
