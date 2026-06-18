# Backends (model providers)

Argo runs the same five-stage pipeline on a **swappable agent backend**, so a user can run it with
whatever they already have — **Claude Code**, the **Codex CLI** (OpenAI), or a **local / open-source**
model — without changing the audit logic. This also makes Argo a vehicle for **cross-model
comparison** in the study: identical prompts and pipeline, different model, measured side by side.

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
└─ MockClaudeRunner       # fixtures (zero tokens; the test suite)
```

`build_runner(config)` dispatches on `config.runner ∈ {headless, codex, mock}`.

## The guardrails are backend-neutral, enforced per backend

The invariants are one **`SessionPolicy`** (`guardrails.session_policy(stage)`) — *"no network except
the `research` stage; the repo is never writable"* — and each backend translates it into its own CLI
dialect. This is the safety-critical part and is unit-tested for **both** backends.

| Guarantee | Claude (`HeadlessClaudeRunner`) | Codex (`CodexRunner`) |
|---|---|---|
| Repo **read-only** | repo via `--add-dir`; ingest also chmods it read-only | repo lives **outside** the workspace + chmod read-only → readable, not writable (we deliberately do **not** `--add-dir` the repo, which would make it writable) |
| Writes only the scratch dir | session cwd = scratch + `Write` tool | `-s workspace-write` with cwd = scratch |
| **No network** (all stages but research) | network tools stripped from the allowlist | `-s workspace-write` (sandbox denies egress) |
| **Network only for `research`** | OSINT tools kept for that one stage | `-c sandbox_workspace_write.network_access=true` for that one stage |
| No interactive blocking | `--permission-mode bypassPermissions` | `codex exec` is non-interactive (no approval prompt) |
| Never a sandbox escape | network/mutation tools always disallowed | never `danger-full-access` / `--dangerously-bypass-*` |

Tests: `tests/test_guardrails.py` (the policy + Claude tool stripping) and `tests/test_codex.py`
(`test_build_cmd_is_sandboxed_and_offline_for_audit`, `test_only_research_gets_network` — the
equivalent re-validation for the Codex sandbox).

> **Note on the network guarantee.** For Claude, "no network" is enforced by the tool denylist
> (a named-capability allowlist). For Codex it relies on the **OS sandbox** contract of
> `workspace-write` (writes confined to the workspace, egress denied). We assert our command never
> enables network outside `research` and never uses an escape flag; the sandbox itself is Codex's
> enforcement. A real network-blocked smoke is recommended before high-stakes Codex use.

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

## Verify your backend

```bash
# Claude
python -m argo.cli pipeline --smoke                          # the bundled ~$1 Claude smoke
# Codex (OpenAI)            — needs `codex login`
python -m argo.cli pipeline --smoke --runner codex          # uses your Codex default model
# Codex (local / open-source) — free, needs Ollama/LM Studio running
python -m argo.cli pipeline --smoke --runner codex --codex-oss --codex-local-provider ollama
```

`--smoke` keeps it cheap (one focus, low caps, research off). The mock runner (`--runner mock`)
covers the whole pipeline for free regardless of backend.

> **Validated end-to-end on real Codex.** A `--smoke --runner codex` run on the bundled fixtures
> drove all six LLM calls through `codex exec` (ingest → recon → audit → validate → report), every
> stage `is_error: false`: recon generated the custom audit prompts, audit produced findings,
> adversarial validation ran — the prompts are portable and the sandbox held. (Cost showed `$0`
> because the model logged as `codex-default`; tokens are recorded — see the cost note above.)

## Why this matters for the paper

Keeping the pipeline LLM-direct (no CPG/AST — see [design-decisions.md](design-decisions.md)) means
the *only* thing that changes between backends is the **model**. That turns Argo into a clean
instrument for a **cross-model study**: same corpus, same prompts, same guardrails, different model →
the precision (registry accept rate) and recall (benchmark) numbers become directly comparable across
Claude / OpenAI / open-source models. The contribution is the pipeline + methodology; the backend is
a knob.
