# Guardrails

The non-negotiable rules are enforced **in code, not just in prompts**. This page maps each
guardrail to the exact place it is enforced, so a reviewer can verify it is real.

## 1. Never auto-submit

Stage 5 stops at DRAFT bundles; submission is a manual human action.

- There is **no submission code path** anywhere — no finding/report is ever transmitted. The only
  HTTP client in the tree is the **gated live-probe executor** (`stages/live.py`, §2c): it makes
  read-only, in-scope verification requests, never a submission, and is **off by default**.
- `stages/report.py` writes `submission_drafts/<id>.md` files, each opening with
  `# DRAFT - NOT SUBMITTED`.
- **Provenance.** Human-facing artifacts (`REPORT.md`, drafts) carry a "Produced by **Argo**" footer
  (`branding.attribution_footer`, `config.attribution`, **default on** for every user; opt out with
  `--no-attribution`). It tells a reviewer the output is AI-assisted; attribution only, no license
  change, and not a claim of authorship over the target code.
- The CLI exposes **no `submit` command** (`tests/test_pipeline.py::test_cli_has_no_submit_command`).

## 2. Never contact, scan, or exercise a live host (except the opt-in, gated `live` stage)

Every stage of the **default** pipeline is fully offline against the program's hosts: even for
`source_and_live` targets, live steps exist only as text plans a human runs. The **one** way Argo
itself touches a live in-scope host is the **opt-in `live` stage (§2c)** — default **off**, gated by
an explicit authorization acknowledgement, scope-locked to in-scope assets, capped, and audit-logged.
With `live` disabled (the default), the absolute "never a live host" rule below holds in full.

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

### 2a. The bounded exception: the OSINT stages `research` + `corroborate`

Exactly **two** stages are allowed any network access, and only the **OSINT subset** — `WebSearch` +
`WebFetch` (`config.OSINT_TOOLS`, gated by `guardrails._OSINT_STAGES`): Stage 0
(`stages/research.py`, `--research/--no-research`, **on by default**) for *public* threat
intelligence before the audit, and the post-validation `corroborate` stage
(`stages/corroborate.py`, `--corroborate/--no-corroborate`, **on by default**) which cross-checks
each surviving finding against the project's **docs** and the repo's **VCS history**. Both read the
same category of *public* source as `git clone`; neither touches the bug-bounty target itself.

The boundary is enforced, not just prompted:

- `enforce_session_tools(..., stage="research"|"corroborate")` permits **only**
  `WebSearch`/`WebFetch`; it still strips `Bash`, `Task`/`Agent`, `BashOutput`, `KillShell`, and all
  mutation tools. Every **other** stage (and `stage=None`) still loses the OSINT tools entirely —
  proven by `test_guardrails.py::test_only_networked_stages_get_network`.
- Both networked sessions are given **no repo** (`repo_dir=None`) — the networked session never sees
  the code (corroborate receives the relevant code as read-only *excerpts in the prompt*); the
  code-seeing sessions never get the network. Two disjoint capabilities.
- They must **never** touch the program's **live in-scope hosts** (web/api/mobile assets): those are
  injected into the prompt as an explicit *FORBIDDEN LIVE HOSTS* denylist. They read public
  third-party sources (advisories, docs, the public source repo) only.
- Best-effort: a failure in either never aborts the run (recon proceeds without the brief; corroborate
  leaves the finding `unknown`).
- `--no-research` / `--no-corroborate` (CLI) keeps those stages off; a brief-less local review and
  `--smoke` force both off for a **100% offline** run.

### 2a-bis. `verify` (deep-verify): offline like `validate`, not a third networked stage

The opt-in `verify` stage (`stages/deep_verify.py`, `argo verify` / `--verify` on `pipeline`, default
**off**) gets **full read-only repo access** (`ARTIFACT_TOOLS` — `Read`/`Grep`/`Glob`/`Write`, no
excerpt budget) but **no network**: `session_policy("verify").network` is `False`, same as
`validate`. `enforce_session_tools(..., stage="verify")` strips `WebSearch`/`WebFetch` exactly like
every non-OSINT stage — proven by the same `test_only_networked_stages_get_network` test that
covers every other offline stage. It is the deepest stage in terms of *tool budget* (one full
session per finding, never batched) but stays inside the same two-disjoint-capabilities rule as
everything else: repo access and network access never coexist in one session.

### 2b. The other bounded exception: the `runtime` stage (loopback-only sandbox)

Runtime verification (`stages/runtime.py`, **opt-in** via `--runtime`, default **off**) runs a live
instance — but **never the program's live in-scope host.** It builds the OSS target from the
**cloned source** into an ephemeral, **egress-blocked** Docker container (`--network=none`, so the
network namespace has *only* loopback) and probes **only `127.0.0.1`** inside that sealed namespace.
Same trust model as `argo/verify.py`'s offline builds (Phase-6 fix-patch build verification — not to
be confused with the `deep_verify` pipeline stage in §2a-bis below); the "never a live host" rule (§2) is preserved and
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

### 2c. ⚠️ The opt-in live exception: the `live` stage (in-scope hosts only)

This is the **one** capability that, by design, contacts the program's **real, live in-scope host** —
a deliberate, heavily-gated relaxation of §2 for **authorized** bug-bounty engagements whose rules of
engagement permit automated interaction. **Off by default** (`live_enabled=False`); the standalone
`argo live` command additionally requires the explicit `--i-have-authorization` acknowledgement.
It is the live analog of the runtime sandbox: same propose→validate→execute→interpret shape, but the
target is the in-scope host instead of loopback — so the validators are **inverted and tightened**:

- **RoE authorization gate** — `guardrails.assert_live_authorized(scope)` **refuses** unless the scope
  authorizes it: `automation_allowed` is true, `safe_harbor` is not explicitly false, and
  `prohibited_techniques` is non-empty (no touching a live host without declared hard limits).
- **In-scope-only scope-lock** — `guardrails.assert_inscope_only(plan, scope)` requires every request
  to use an **absolute URL whose host is a registered in-scope web/api asset**; out-of-scope, unknown,
  *and loopback* hosts are all **hard-blocked** (careful wildcard matching, no `*.acme.com` overmatch).
  A violation **aborts before any request is sent**.
- **Read-only + anti-DoS caps** — `guardrails.validate_probe_plan(...)` allows **read-only** methods
  only (GET/HEAD/OPTIONS) unless `live_allow_writes` (a deliberate **second** opt-in, `--allow-writes`)
  is set; total request count, body size, and rate (`live_min_request_interval_s`) are capped. An
  oversized plan is **rejected whole** (fail-loud, no silent truncation), honoring "no DoS".
- **State-changing policy (L3)** — when writes are opted in, `guardrails.assert_live_write_policy(...)`
  adds extra rails on top of the method allowlist: **DELETE is never permitted** (destructive ops are
  out of bounds for an automated confirmation probe, even in write mode), and state-changing requests
  (POST/PUT/PATCH) are capped **separately** by `live_max_writes` so a flood of mutations is impossible.
  Read requests omit headers/body from the audit log (so secrets aren't logged); a **state-changing
  request records its body** in `live_audit_log.jsonl` — a mutation must be fully accountable.
- **No model execution primitive** — the plan (hand-written, L1; or LLM-generated, L2) is run by a
  **fixed** stdlib executor, not a model shell; the model never gets a network tool. In L2 the propose
  and interpret sessions are **offline** (read-only repo, no network — `stage="live"` gets no network
  tools, exactly like the audit stages); only the executor touches the network, and only after the
  same deterministic gates (`assert_inscope_only` + `validate_probe_plan`) pass on the generated plan.
- **Hardened executor** — the fixed runner (a) sends a tool-identifying `User-Agent`
  (`live_user_agent`); (b) **never auto-follows redirects** — a custom handler hands each `3xx` back so
  the executor **re-validates the redirect target is in-scope** before following (an off-host redirect
  is recorded, never chased — closing the gap where urllib would silently leave scope), and writes are
  never re-followed; (c) **retries transient errors** (timeout / connection reset / `5xx` / `429` with
  `Retry-After`) for **idempotent methods only** — a write is never retried (no double-mutation);
  (d) captures security-relevant **response headers** + the redirect chain as evidence; (e) supports a
  **differential `control`** request per probe (run as a baseline; nested controls are gated exactly
  like any request via `_entry_requests`) so the interpret stage judges the *difference*, cutting
  false positives on access-control findings.
- **Full accountability** — every request (probe + control) is written to `runs/<id>/live_audit_log.jsonl`
  (timestamp, method, URL, status, size; a mutation's body); results land in `live_results.json`.
- **Best-effort + off-by-default** — skips silently when disabled or no plan exists; any gate failure
  aborts the stage and sends nothing.
- Tests: `test_live.py` (RoE gate accept/refuse; in-scope accept; out-of-scope/unknown/loopback/
  relative reject; wildcard no-overmatch; oversized-plan rejection; executor + audit log against a
  loopback server the test scope declares in-scope).

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
  real program always has hard limits. A technique counts as present in **either** its literal form
  **or** its JSON-`\uXXXX`-escaped form, so a non-ASCII constraint (an em dash or accented word —
  common in non-English briefs) is matched whether the prompt embeds it as the raw scope.json text
  (escaped) or as the parsed string (literal); without this the check spuriously failed on any
  non-ASCII prohibited technique.
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
no submission, and **no live contact unless you explicitly opt into the gated `live` stage** (§2c),
which itself stays scope-locked, read-only-by-default, capped, and audit-logged.

## See also

This page is the **safety** envelope (can Argo do something it shouldn't?). The adjacent question —
*how the pipeline stays trustworthy given that the model hallucinates and is non-deterministic* — is
covered in [determinism-and-guardrails.md](determinism-and-guardrails.md): mechanical diffs,
ground-truth build verification, physical budget/timeout/request caps, the scope-lock asserts above
viewed as anti-hallucination gates, and commit-pin reproducibility.
