# Determinism & anti-hallucination controls

LLMs hallucinate and are non-deterministic. Argo's design **assumes this** and wraps the model in
deterministic gates and hard physical limits, so a wrong, invented, or unlucky model output is
**caught, bounded, or made harmless** — never silently trusted or acted on. Three principles run
through the whole pipeline:

1. **Take determinism out of the model's hands** wherever a plain algorithm can do the job.
2. **Verify every consequential model claim against ground truth** — the code, a schema, a real
   build, an actual observation.
3. **Physically bound** what any run can consume or reach.

The model is a powerful *proposer*; the value comes from what the deterministic scaffolding does with
its proposals. This page collects those controls in one place. For the **safety** guardrails (no live
host, no auto-submit) with their exact enforcement points see [guardrails.md](guardrails.md); for why
Argo is LLM-direct with no CPG/AST engine see [design-decisions.md](design-decisions.md).

---

## 1. Deterministic computation instead of model output

Where a mechanical step can replace a model-authored artifact, it does — removing an entire class of
hallucination.

- **Patch diffs are computed, not written.** In remediation ([Phase 6](api.md#remediation--fix-verification-phase-6))
  the model supplies a **full-file rewrite** (`new_content`) or exact **search/replace `edits`**; Argo
  computes the unified diff with `difflib` (`fixes._mechanical_diff`). The model **never authors hunk
  headers**, so it cannot miscount `@@` ranges — the "corrupt patch" failure that broke multi-hunk
  diffs on large repos. `fixes._apply_edits` requires each `search` to match the file **exactly once**;
  a missing/ambiguous block **rejects the whole file** rather than half-applying it.
- **Live probes run in a fixed executor, not a model shell.** In the opt-in `live`/`runtime` stages the
  model proposes and interprets a probe plan, but a **stdlib executor** (not the model) issues the
  requests. The model never gets a network/execution primitive directly.
- **Scoring is a deterministic matcher, not an LLM judge.** `argo bench` matches findings to labels by
  **normalized CWE + file-suffix + line tolerance** (`benchmark.score_run`) — reproducible numbers,
  no model in the loop.
- **Dedup is a pure key.** Cross-run/among-focus dedup uses a deterministic `dedup_key`
  (file + line + CWE), not a model similarity call.

## 2. Verify every model claim against ground truth

Nothing consequential is trusted on the model's say-so; each claim is checked against something real.

- **Schema gates.** Ingest validates `scope.json` against `scope_schema.json` (`validate_scope`) and
  refuses to proceed if `scope.prohibited_techniques` is empty; every finding is
  `Finding.model_validate`d. A **malformed** audit finding is **repaired and flagged, never a silent
  whole-focus loss** (drift-repair).
- **Fixes must build, not just look right.** A proposed patch is accepted **only** if it deterministically
  **applies** (`git apply -p1`, fallback `patch --fuzz=0`) **and compiles/builds** (`py_compile`,
  `node --check`, `go build`, `cargo check`, or your `--build-cmd`/`--docker`) **and introduces no new
  errors** versus a pre-patch baseline — all on an **isolated copy** (`verify.verify_patch`). A model's
  "this is fixed" is worthless until the compiler agrees. `--re-audit` adds a second, unbiased check.
- **Runtime / live confirmation.** A static hypothesis becomes `confirmed` **only** when an observed
  runtime signal or in-scope HTTP response agrees with it (opt-in [runtime](runtime-verification-study.md)
  / live stages). The model interprets, but the **observation is real** — and a differential `control`
  probe is captured so the interpreter judges the *difference*, cutting false positives.
- **Adversarial, refute-first validation.** Each finding is re-examined in isolation with a
  refute-first prompt; a user-proposed "why didn't you find X?" candidate is re-validated the same way,
  and is labelled an **interactive probe**, never silently promoted into the findings set.
- **Corroboration against reality.** Findings are cross-checked against the project's docs and VCS
  history (public OSINT) to downgrade by-design behavior and exclude already-fixed issues.

## 3. Physical / resource limits (hard caps)

Unbounded model behavior — an infinite loop, a runaway agent, a decompression bomb of tokens — is
capped by wall-clock and cost ceilings that fire regardless of what the model is "trying" to do.

- **Wall-clock timeouts.** `session_timeout_s` (default **1800s**) and per-stage `stage_timeouts`; a
  hung or looping session is **killed**, not waited on forever. Cancellation kills the whole process
  tree mid-stage.
- **Cost ceilings.** `budget_usd` is a **hard per-run USD ceiling** (deterministic abort, surfaced in
  the UI); `session_max_cost_usd` caps a single session natively (`--max-budget-usd`);
  `session_max_turns` is a per-session turn tripwire.
- **Concurrency + fan-out caps.** `max_parallel_audits` (default 3); `max_focuses` bounds audit fan-out
  (used by `--smoke`).
- **Sandbox anti-DoS caps.** Runtime: `runtime_max_requests` (50), `runtime_max_payload_bytes`,
  boot/request timeouts. Live: `live_max_requests` (30), `live_max_writes` (5, **DELETE always
  blocked**), `live_max_redirects` (3, each re-validated in-scope), a per-request interval and payload
  cap. An oversized probe plan is **rejected whole**, not truncated.

## 4. Isolation & reproducibility

The same inputs produce the same run, and a bad output can't escape its sandbox.

- **Read-only repo, single chokepoint.** The target repo is mounted **read-only** to every session
  (`_make_readonly`); the detection pipeline **never patches** the target; remediation writes **only**
  to `runs/<id>/patches/`. The `AgentRunner` is the one place tools are granted, so guardrails apply
  everywhere at once.
- **Offline by default.** Non-live stages get **no network tools** (`assert_no_network_tools`); only the
  bounded OSINT stages reach the public web, and **never** the program's in-scope hosts.
- **Files are the source of truth.** Every stage writes its output to disk; downstream stages re-read
  those artifacts, so behavior is reproducible and inspectable (nothing hides in model memory).
- **Commit pinning.** `argo pipeline --commit <sha>` (and a case's `commit`) pins the analyzed source
  to an **exact revision** — identical input every time, and the basis for reproducible benchmark
  corpora.
- **Full ledger.** Every LLM call is logged (model, tokens, cost) to the SQLite ledger — auditable, no
  hidden spend or untracked action.

## 5. Scope & authorization locks (deterministic gates)

Before any privileged or networked action, a plain-code assertion must pass — the model cannot talk
its way past these (they run on the *plan*, not on a prompt):

| Gate (`argo/guardrails.py`) | Enforces |
|---|---|
| `assert_prohibited_present` / `assert_audit_prompt_wellformed` | the prohibited-techniques block is present in the rendered prompt (render fails otherwise) |
| `assert_no_network_tools` | non-live stages are given no network/mutation tools |
| `assert_loopback_only` + `validate_probe_plan` | runtime probes hit **only** `127.0.0.1`, within request/payload caps |
| `assert_live_authorized` | live testing refused unless RoE `automation_allowed` + `safe_harbor` |
| `assert_inscope_only` | every live URL is an absolute, registered **in-scope** host (out-of-scope/unknown/loopback hard-blocked; no wildcard overmatch) |
| `assert_live_write_policy` | writes only behind a second opt-in; **DELETE never allowed**; state-changing requests capped separately |

---

## The net effect

Every consequential step is either **computed deterministically**, **verified against ground truth**,
or **physically bounded**. So a hallucinated or unpredictable model output degrades to the safe
outcome — *a rejected finding, an unverified patch, a refused probe, an aborted-on-budget run* — and
**never** a wrong action, a silently-trusted false claim, or an unbounded cost. That is the property
that makes an LLM-native auditor safe to point at an arbitrary repository.
