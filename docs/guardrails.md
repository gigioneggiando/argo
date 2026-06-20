# Guardrails

The non-negotiable rules are enforced **in code, not just in prompts**. This page maps each
guardrail to the exact place it is enforced, so a reviewer can verify it is real.

## 1. Never auto-submit

Stage 5 stops at DRAFT bundles; submission is a manual human action.

- There is **no submission code path** anywhere — `grep` finds no `requests`/`urllib`/`socket`/
  `http` client in the tree.
- `stages/report.py` writes `submission_drafts/<id>.md` files, each opening with
  `# DRAFT - NOT SUBMITTED`.
- The CLI exposes **no `submit` command** (`tests/test_pipeline.py::test_cli_has_no_submit_command`).

## 2. Never contact, scan, or exercise a live host (any stage)

Holds even for `source_and_live` targets — live steps against the program's hosts exist only as
text plans a human runs.

- `config.NETWORK_TOOLS` lists every network/sub-agent tool (`Bash`, `WebFetch`, `WebSearch`,
  `Task`, …). `guardrails.enforce_session_tools()` **strips** them from any session's allowlist
  and adds them to `--disallowedTools`.
- `runner.AgentRunner.run()` calls `guardrails.assert_no_network_tools()` immediately before a
  session launches — a hard stop.
- The code-audit sessions (`recon`, `audit`, `validate`) pass the repo via `--add-dir` (a
  no-internet sandbox) and never add a network tool to `--allowedTools`.
- Tests: `test_guardrails.py` (`enforce_session_tools`, `assert_no_network_tools`),
  `test_runner.py::test_run_strips_network_and_mutation_tools`,
  `test_runner.py::test_headless_cmd_is_readonly_sandboxed`.

**Backend-neutral by design.** The rule is one `SessionPolicy` (`guardrails.session_policy(stage)` —
*no network except `research`, repo never writable*); each backend enforces it in its own dialect:
the Claude runner via the tool allow/deny lists above; the **Codex** runner via the OS **sandbox**
(`-s workspace-write`, network re-enabled only for `research`, never a `danger-*` escape). The Codex
mapping is re-validated in `tests/test_codex.py` — see [backends.md](backends.md#the-guardrails-are-backend-neutral-enforced-per-backend).

### 2a. The one bounded exception: the `research` stage (OSINT only)

Stage 0 (`stages/research.py`, opt-out via `--research/--no-research`, **on by default**) is the
**only** stage allowed any network access, and only the **OSINT subset** — `WebSearch` + `WebFetch`
(`config.OSINT_TOOLS`). It is for *public* threat intelligence (CVEs, advisories, the source repo,
docs) that makes the later static audit smarter — the same category as `git clone` fetching source.

The boundary is enforced, not just prompted:

- `enforce_session_tools(..., stage="research")` permits **only** `WebSearch`/`WebFetch`; it still
  strips `Bash`, `Task`/`Agent`, `BashOutput`, `KillShell`, and all mutation tools. Every **other**
  stage (and `stage=None`) still loses the OSINT tools entirely — proven by
  `test_guardrails.py::test_only_research_gets_network`.
- The research session is given **no repo** (`repo_dir=None`) — the networked session never sees the
  code; the code-seeing sessions never get the network. Two disjoint capabilities.
- It must **never** touch the program's **live in-scope hosts** (web/api/mobile assets): those are
  injected into the prompt as an explicit *FORBIDDEN LIVE HOSTS* denylist. Research reads public
  third-party sources only — never the bug-bounty target itself.
- Best-effort: a research failure never aborts the run (recon just proceeds without the brief).
- `--no-research` (CLI) / `research: false` (API) keeps a run **100% offline**, exactly as before.

### 2b. The other bounded exception: the `runtime` stage (loopback-only sandbox)

Runtime verification (`stages/runtime.py`, **opt-in** via `--runtime`, default **off**) runs a live
instance — but **never the program's live in-scope host.** It builds the OSS target from the
**cloned source** into an ephemeral, **egress-blocked** Docker container (`--network=none`, so the
network namespace has *only* loopback) and probes **only `127.0.0.1`** inside that sealed namespace.
Same trust model as `verify.py`'s offline builds; the "never a live host" rule (§2) is preserved and
extended to the probe layer:

- **Loopback-only gate** — `guardrails.assert_loopback_only(plan, scope)` rejects any probe whose
  target (URL host, `Host:` header, or `//host` form) is not loopback, **or** that names a scope
  in/out-of-scope host. A violation **aborts** runtime; it never proceeds.
- **Anti-DoS / method gate** — `guardrails.validate_probe_plan(...)` caps total request count, body
  size, and rate, and allows **read-only** methods only (GET/HEAD/OPTIONS) unless
  `runtime_allow_state_changing` is explicitly opted in (honors `prohibited_techniques`: no DoS).
- **No model execution primitive** — the model proposes a probe plan (R2); a deterministic validator
  gates it and a **fixed** stdlib probe runner (not model-controlled) executes it; the target image
  needs no probe tooling because a separate probe container *joins the app's sealed namespace*.
- **Best-effort + isolated** — throwaway `copytree` + `--rm` containers; gracefully skips (never
  fails the run) when disabled, Docker absent, no launcher recipe, or no probe plan. Full design:
  [runtime-verification-study.md](runtime-verification-study.md).

## 3. Repo mounted read-only to every session; the pipeline never patches

- The session **cwd is a separate writable scratch dir**, never the repo. The repo is exposed
  only via `--add-dir`.
- `stages/ingest._make_readonly()` strips write bits from every copied repo file (defense in
  depth on top of the tool restriction).
- `config.MUTATION_TOOLS` (`Edit`, `MultiEdit`, `NotebookEdit`) are always disallowed.
- There is no code path that writes into `repo/`.

## 4. `prohibited_techniques` propagated into every rendered prompt; render fails if missing

- `guardrails.assert_prohibited_present(text, prohibited)` raises `PromptGuardrailError` if any
  prohibited technique is missing from a rendered prompt — **and rejects an empty list**, since a
  real program always has hard limits.
- Enforced at every prompt boundary:
  - `stages/recon.py` — on the rendered meta-prompt, and `assert_audit_prompt_wellformed()` on
    **each generated audit prompt** (must also carry the template's RoE sections and "Do NOT
    patch"). Just before that gate, `ensure_prohibited_present()` **deterministically re-inserts**
    any prohibited technique the model paraphrased away when it regenerated the template — it only
    ever *adds* the scope's own constraints (never removes/relaxes), so a model paraphrase can't
    silently drop a limit *or* fail an otherwise-valid run; the hard gate still runs afterwards.
  - `stages/audit.py` — again on the prompt that actually drives each audit session.
  - `stages/validate.py` — on the rendered validation prompt.
- Tests: `test_guardrails.py` (present / missing / empty / malformed-template cases).

## 5. Validate against the JSON Schemas; log every LLM call

- `schemas.validate_scope()` gates Stage 1; `schemas.validate_findings()` gates Stage 3 (and the
  per-finding normalization in Stage 4). Draft-07, schemas are authoritative.
- `ledger.log_call()` runs inside `AgentRunner.run()` for **every** call (prompt sha256, model,
  tokens, `cost_usd`), plus a `runs/<RUN_ID>/llm_log.jsonl` line. Cost logging happens even when
  the session errors.
- Prompt-asset versions used by a run are recorded in `meta.json` (`asset_versions`, sha256 each).

## Additional code-side defenses

- **Scope filter, independent of the LLM verdict.** `guardrails.out_of_scope_match()` drops any
  finding whose affected reference falls under an explicit `out_of_scope` token — applied in
  `stages/validate.py` *before* validation, so an out-of-scope finding never even reaches the
  validator.
- **Conservative ingest defaults.** If the brief is silent on automation, `automation_allowed`
  is treated as false; if `prohibited_techniques` is empty, a conservative default set is
  injected (`stages/ingest._DEFAULT_PROHIBITED`).
- **Budget is a hard guard.** `--budget` aborts remaining sessions once real spend (from the
  ledger) reaches the ceiling; the abort is logged, never silent.

## What the guardrails deliberately do *not* do

They do not vouch for finding quality — that is the job of the audit and validation prompts.
They guarantee the pipeline stays inside the authorized envelope: source-static only, read-only,
no live contact, no submission.
