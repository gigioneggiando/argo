# Roadmap — UI & advanced features on top of the pipeline

Status: planning. This document analyzes each requested feature (feasibility / utility / priority
/ needed?), proposes a phased build order, and tracks the todo list. The pipeline (CLI + stages +
`AgentRunner` + ledger) is the engine; everything here sits **on top** of it and must keep its
guardrails intact (no live host, no patching the target, read-only repo, no auto-submit).

## Precision & depth uplift — ✅ DONE (2026-06-19)

Triggered by a head-to-head: a 3-prompt, multi-pass manual Claude audit of Umbraco-CMS surfaced
~50 credible findings (incl. runtime-verified + SCA) vs Argo's 12 (a near-subset). Root cause was
**not** model capability but **methodology** — the manual prompts were saturated with ground truth
(exact invariants, a baseline-correct reference to diff every sibling against, enumerated variant
families, explicit FP carve-outs). Shipped, mirroring that into the automated pipeline:

- **Deep ground-truth recon** — recon emits `ground_truth.json` + bakes INVARIANT CHECKLIST /
  BASELINE-CORRECT REFERENCES / VARIANT FAMILIES / FP CARVE-OUTS into every audit prompt
  (`prompts/00_…`, `prompts/01_…`, `stages/recon.py`).
- **Enumeration forcing-function** — audit must emit a `VARIANT_HUNT_LOG` (row per family member),
  plus a **completeness-critic** loop-until-dry re-pass (`--critic-passes`, default 1).
- **Downgrade-don't-delete validate** — `refuted` only for code-contradicted findings; carve-outs +
  baseline refs injected so the validator stops refuting real bugs (`stages/validate.py`, `prompts/02_…`).
- **SCA stage** — dependency manifests → known-vuln pins (`stages/sca.py`, `--sca/--no-sca`).
- **Drift-repair** — a malformed audit finding is repaired + kept (flagged), never a whole-focus loss.

Validation: re-run the full pipeline on Umbraco-CMS (Claude, no budget) and measure recall/precision
vs the ~50 reference findings. Tests: `tests/test_uplift.py` (147 total, all green).

## Constraints that shape every decision (read first)

1. **Cost.** A full real run was ~**$34** (recon Opus + 3 Sonnet audits + ~26 Opus validations).
   A UI that invites "click to run" must have: a **cost preview**, a hard **budget** control
   (already in the engine), a cheap default tier, and `--runner mock` for free dry-runs. Cost is a
   first-class UX concern, not an afterthought.
2. **Run time.** Real runs take **minutes to ~30+ min**. The "loading screen" must show a **stage
   timeline + live cost + partial results as they land** — not a blind spinner. The engine's
   *files-are-the-source-of-truth* design makes streaming partial artifacts almost free (show
   `scope.json` after ingest, the generated prompts after recon, each focus's findings as it
   finishes).
3. **Guardrails.** The runner is already the single chokepoint (read-only repo, no network/mutation
   tools). Any new execution path (other model backends, static-analysis tools, test generation)
   must route through or mirror that chokepoint. Test generation writes **new** files to an
   artifacts dir — it must never modify the target repo.
4. **The `AgentRunner` is already swappable.** Multi-backend is *architecturally* prepared; the
   real cost of adding a backend is re-validating the guardrails + sandbox for it, not the interface.

## Per-feature analysis

| Feature | Feasibility | Utility | Needed? | Priority |
|---|---|---|---|---|
| **Backend API + job orchestration** | High | — (enabler) | **Yes** (prerequisite for all UI) | **P0** |
| **Core UI** (paste links/brief/repo → run → live progress → results) | High | High | **Yes** (the ask) | **P0/P1** |
| **Settings page** over existing knobs (budget, Claude models, caps, mock) | High | Med-High | Useful (engine works on defaults) | **P2** |
| **"Let the AI choose"** recommended config | High (pure heuristic) | Med-High (less friction) | Nice | **P2** |
| **Interactive chat layer** (explain / "why not found" / test-gen) | High (synergistic) | **High** | High-value, not strictly needed | **P3** |
| **Vulnerability index per archetype** | High (partly exists) | Med-High | Partly redundant — value is curation + UI | **P4** |
| **Light static metadata** (AST / call-graph via tree-sitter) | Med | Med | Useful context, cheap | **P4** |
| **Multi-backend runners** (Codex / open-source) | Med (per backend) | Med (cost / lock-in) | Not needed (Claude works) | **P5** |
| **Deep static analysis** (CPG / PDG / CFG, e.g. Joern) | Low-Med (heavy, per-language) | Uncertain on top of a strong LLM | Experimental | **P5** |

### Notes that change the priorities

- **Vuln index already half-exists.** The meta-prompt carries archetype-keyed vulnerability classes
  and `repo_profile.json` emits `historical_bug_classes`. The new work is a **curated, persistent
  knowledge base** (consistent across runs, helps weaker models) + **surfacing it in the UI** — not
  building it from scratch. Use it as "also consider", never "only these" (don't suppress novel finds).
- **CPG/PDG: best as a *validation* aid, not raw context.** Feeding a whole code-property-graph to
  an LLM is impractical (huge). The value is mechanical taint precision the LLM lacks: let the LLM
  propose sources/sinks, let the graph engine find/confirm paths, feed **query results** to the
  *validation* stage to confirm/refute a finding's data flow. Prefer **parse-only** tooling
  (tree-sitter: AST, call graph — no build, respects "no code execution") over build-based CPG
  (Joern needs to compile → runs build scripts → safety + setup cost). Start light (AST/call-graph),
  defer full CPG/PDG until there's evidence the LLM is missing flows it would catch.
- **"Let the AI choose" needs no LLM call.** A heuristic over repo size (LOC), language, archetype,
  and stated target value can pick models/budget/parallelism. Cheap, deterministic, good default.
- **Chat layer directly attacks the core failure mode.** Bug-bounty value is dominated by **false
  negatives** (bugs never surfaced). A chat that re-investigates "why didn't you find X?" with the
  user's domain knowledge + the run's full context is the highest-leverage *quality* feature.
- **Test generation is allowed, patching is not.** Generating a test suite that *would catch* a
  CWE is a new artifact for the human — fine, as long as it writes to `generated_tests/` and the
  target repo stays read-only. This is a guardrail nuance to enforce in code, not just prompt.

## Phased build order

Dependency-first, value-and-readiness next. Each phase is independently shippable.

### Phase 0 — Backend API & job orchestration (foundation) — ✅ DONE
Goal: drive a run programmatically with live progress; everything else hangs off this.
See [api.md](api.md). Implemented in `argo/progress.py` + `server/`.
- [x] Pipeline emits structured progress: `runs/<id>/status.json` per stage (state, timestamps,
      live cost, ready artifacts) via `ProgressReporter`; `run_pipeline` takes an optional reporter
      + cancel event (no behavior change when absent — all existing tests still green).
- [x] FastAPI service (`server/app.py`): `POST /runs`, `GET /runs`, `GET /runs/{id}`,
      `GET /runs/{id}/events` (SSE), `POST /runs/{id}/cancel`, `GET /runs/{id}/report`,
      `GET /runs/{id}/artifacts/{name}`, `GET /runs/{id}/{prompts,findings,drafts}`.
- [x] Background job manager (`server/jobs.py`): daemon-thread runs, cancellation at stage
      boundaries. (`runner=mock` is the default → zero-token by default.)
- [x] Map request → `PipelineConfig`. Ledger in WAL mode for concurrent read (API) + write (job).
- [x] `python -m argo.cli serve` command; API tests on the mock runner (`tests/test_api.py`).
- [x] Surface the budget abort in the UI — the run view shows a distinct "Run stopped — budget reached"
      banner (matches the engine's "Per-run budget … reached" / "session exceeded … cost cap" errors).
- [x] **Mid-stage cancellation** (backlog **C1**) — the runner kills the in-flight CLI process tree
      on Cancel (`AgentRunner._exec`/`_kill_tree`); the orchestrator marks it cancelled.
- [ ] _Later:_ subprocess isolation per run (backlog **C2**).

### Phase 1 — Core UI (the MVP) — ✅ DONE
Goal: a non-CLI user pastes 3 inputs, clicks start, watches progress, reads results.
See [ui.md](ui.md). Implemented in `webapp/` (no-build: vanilla ES modules + modern CSS, served
by the API), tested in `tests/test_api.py`.
- [x] Frontend scaffold — **no build step** (vanilla ES modules + CSS, hash router, vendored
      `marked`), served by FastAPI at `/app`. Reliability over toolchain.
- [x] Input form (description / links / repo) + Advanced (runner, budget, audit model, parallel,
      dry-run); client-side validation.
- [x] Cost-aware launch: default runner **Mock (free)**; switching to Real reveals a cost warning.
- [x] Live run view: SSE stage timeline (pulsing active stage), live cost, **artifact cards that
      reveal as files land** (scope → prompts → per-focus findings → validated → report → drafts);
      Cancel button.
- [x] Results: rendered `REPORT.md`; findings table (sortable + severity filter + detail drawer);
      drafts; raw artifacts viewer. (Dry-run shows the generated prompts.)
- [x] Run history list (re-open any past run).
- [x] **Repo zip upload** (backlog **C3**) — `POST /uploads` (safe extract) + an Upload .zip button.
- [ ] _Later:_ richer in-browser visual polish pass.

### Phase 2 — Settings & "Let the AI choose" — ✅ DONE
Goal: full configurability + a one-click recommended config. Plus a **light/dark theme** toggle.
- [x] Settings page bound to `PipelineConfig` (runner, budget, parallelism, audit model,
      calibration, **per-stage models**); persisted server-side (`server/settings.py` →
      `GET/PUT /settings`); the New Run form loads them as defaults.
- [x] Per-run override panel (the Advanced section in New Run, incl. a calibration toggle).
- [x] "Let the AI choose": deterministic recommender (`server/recommend.py`, `POST /recommend`) —
      a quick/standard/thorough tier nudged by a quick **local** repo LOC measurement; returns a
      config + rationale, applied to the form with one click. Runner stays Mock (never auto-spend).
- [x] **Light + dark theme** with a topbar toggle (persisted, respects `prefers-color-scheme`,
      no flash). Tests: `tests/test_api.py` (settings roundtrip, recommend tiers, per-stage models).

### Phase 3 — Interactive chat / interrogation layer — ✅ DONE
Goal: turn a one-shot report into a conversation that attacks false negatives.
Implemented in `argo/chat.py` + `server/` (`GET/POST /runs/{id}/chat`, `GET .../generated`)
+ a Chat tab in the UI. See [ui.md](ui.md), [api.md](api.md).
- [x] Chat endpoint: an `AgentRunner` session seeded with the run's artifacts (scope, repo_profile,
      synthesis_notes, validated_findings) + **READ-ONLY** repo; history persisted to
      `runs/<id>/chat.jsonl`; chat uses the run's runner (free for mock runs) and its cost is
      added to the run total.
- [x] Canned actions in the UI: "explain a finding", "why didn't you find…", "generate tests for a
      CWE", "what did you deprioritize?".
- [x] Test-suite generation: written to `runs/<id>/generated/` only — the target repo stays
      read-only (verified: generated files never land in `repo/`). Served via `GET .../generated`.
- [x] **"why-not-found" → candidate → re-validate** (backlog **B1**) — `chat.ask` re-validates a
      model-proposed `CANDIDATE_FINDING.json` via `validate._validate_one`; verdict in the UI.
- [ ] _Later:_ token-streaming replies (backlog **B2**).

### Phase 4 — Context enrichment — ◑ PARTIAL (vuln index done; AST metadata deferred)
Goal: raise recall/quality with cheap, structured context; surface it in the UI.
- [x] Curated archetype→vuln knowledge base (`argo/data/vuln_index.yaml`: 8 archetypes, ~50
      CWE/vuln-class entries). Loader in `argo/knowledge.py`; **injected into recon** as
      additive reference ("apply the relevant classes, do NOT limit yourself to them").
- [x] UI: a **Vuln index** page (`#/knowledge`) browsing the index by archetype; `GET /knowledge`.
- [x] **Stage-0 web research / threat intel** (`stages/research.py`, opt-out `--research`, default
      on): public web OSINT (CVEs, advisories, the project's security history, the curated links) →
      `research_brief.md` + `threat_intel.json`, **injected into recon** so the generated audit
      prompts are threat-targeted. The **only** networked stage — bounded to OSINT, no repo, never
      the live in-scope hosts (see [guardrails.md](guardrails.md#2a-the-one-bounded-exception-the-research-stage-osint-only)).
      UI toggle + `research` API flag + `research_brief`/`threat_intel` artifacts.
- [ ] **DECIDED AGAINST (for now)** — light static metadata via **tree-sitter** (parse-only AST /
      call-graph sidecar). Deliberately not built: unproven ROI on top of a strong LLM + added
      per-language complexity. See [design-decisions.md](design-decisions.md) §2. **Trigger to
      revisit:** the benchmark (Phase 7) shows recall loss attributable to missed inter-procedural /
      multi-file data flow. Parse-only (no build) would be the first step if so.
- [ ] _Measure_ the index's impact with the baseline dry-run diff (see prompt-synthesis.md).

### Phase 5 — Advanced / experimental (gated by demand + measured ROI)
- [x] **Multi-backend runners — DONE.** `CodexRunner` (`runner=codex`) runs the Codex CLI for
      **OpenAI** models, and **local / open-source** models via `--codex-oss --codex-local-provider
      ollama|lmstudio`. The guardrails were re-expressed onto Codex's OS sandbox (read-only repo /
      writable scratch / no network except research) and re-validated (`tests/test_codex.py`), with a
      real Codex smoke. Cost is token-estimated (Codex reports tokens, not USD). See
      [backends.md](backends.md). (OpenAI + OSS both ship through the one Codex backend; a separate
      native `OpenSourceRunner` is unnecessary.)
- [ ] **DECIDED AGAINST (for now)** — deep static analysis (CPG/PDG/CFG, e.g. Joern) as a data-flow
      validation aid. Two hard reasons (see [design-decisions.md](design-decisions.md) §2): build-based
      CPG must **compile the target**, conflicting with the no-code-execution / read-only guardrail;
      and bolting a graph on **confounds the study** (can't tell LLM findings from graph findings).
      Would only follow the parse-only AST step above, sandboxed, as a confirm/refute aid — gated on
      benchmark evidence, never as raw context.

### Phase 6 — Remediation (fix) pipeline — ✅ DONE (opt-in, separate from the audit)
The audit pipeline stays **detection-only** (a hard guardrail). A *separate, opt-in* remediation
mode turns confirmed findings into **proposed fixes for human review** — never auto-applied to the
target, never submitted. The target repo is **never** mutated: all work happens on an **isolated
copy** under `runs/<id>/fix_workspace/`.
- [x] A `remediate` flow (`argo/fixes.py`, `argo fix <run_id>` CLI): for each confirmed finding,
      generate a **patch as a reviewable unified diff** into `runs/<id>/patches/` (model runs with
      read-only repo + artifact tools; the diff is produced, not applied in place).
- [x] A **verify** stage (`argo/verify.py`) — the user's hard requirement: apply each patch to a
      throwaway copy, then **(1) confirm it still builds/compiles** and **(2) confirm it introduces
      no NEW errors** vs. a pre-patch baseline. Build/compile runs **locally** (auto-detected per
      language: `python -m py_compile`/`ruff`, `tsc`/`node --check`, `go build`, `cargo check`, …)
      or **in Docker** (`--docker <image>`) for a clean, isolated toolchain. A patch that fails to
      apply, fails to compile, or adds a new error is flagged `verified: false` and quarantined.
- [x] UI: a **Fixes** results tab — "Propose & verify fixes" shows each patch (diff) with its
      verify verdict (✓ verified / ⚠ reason). API: `POST /runs/{id}/fixes`, `GET …/fixes`,
      `GET …/patches`. CLI: `argo fix --run <id>`.
- [x] Guardrail: writes only to `patches/`; verification copies the repo and restores write bits on
      the **copy** — the source mount is **never** modified; nothing is applied in place; no PR.
- [ ] _Later:_ richer fixes (multi-file, test-included), a "regenerate this patch" loop, and PR-draft
      export; today's fix is one minimal root-cause diff per finding.
- [x] **Diff fidelity on large real repos — ✅ DONE (2026-07-15).** On a real ChatPlugin run
      (Java, deep multi-module paths), 7/11 model-generated unified diffs failed `git apply` with
      "corrupt patch" — the model miscounted multi-hunk `@@` line ranges (paths were correct, files
      existed; the 4 simpler single-hunk diffs applied + verified). Fixed: the remediation session now
      writes the change into `FIX.json` — a **full rewrite** (`new_content`) or, for **large files**,
      search/replace **`edits`** (each `search` must match exactly once, applied by
      `fixes._apply_edits`) — and Argo computes the unified diff **mechanically** (`difflib`,
      `fixes._mechanical_diff`), so the model never authors (or miscounts) hunk headers. A raw `*.diff`
      is still accepted as a legacy fallback; the mock runner emits `FIX.json`. Tests:
      `tests/test_fixes.py` (multi-hunk-applies-and-compiles, new-file, no-op, search/replace edits).

### Phase 7 — Benchmarks & evaluation — ✅ DONE (core harness)
Measure quality so prompt/model changes are decisions, not guesses. Implemented in
`argo/benchmark.py` + `argo bench` CLI + `GET /benchmark` + a **Benchmarks** UI page. A suite lives
under `benchmarks/<case>/` (`case.json` + `expected_findings.json`); see [benchmarks/README.md](../benchmarks/README.md).
- [x] **Per-run archetype captured** (prerequisite): recon records the canonical archetype into
      `meta.json` (`argo/archetype.py`).
- [x] **Findings quality**: **precision / recall / F1** by matching validated findings against
      labeled corpora (normalized-CWE + file-suffix + optional line tolerance; labels treated as
      exhaustive). Sliced **by archetype** and **by CWE**. Bundled `acme-widgets` mock case scores
      the harness for free; add real labeled repos as new case dirs.
- [x] **Patch quality** (Phase 6 tie-in): `--fixes` folds in the share of confirmed findings whose
      proposed fix **verified** (applies + compiles + no new errors).
- [x] A repeatable harness + an **A/B mode** (`--ab-audit-model`): run the suite under two configs
      and report the precision/recall/F1 delta (B − A).
- [x] **Seeded-bug corpora at scale** (backlog **A1**) — provenance + `--parallel-cases` + corpus recipe.
- [x] **Re-audit the patched copy** (backlog **A3**) — `patch_quality.re_audit_confirmed_rate`, `--re-audit`.
- [x] **Triager accept-rate** (backlog **A2**) — `argo feedback`/`argo quality`, `GET /quality`, `quality.json`.

### Phase 8 — Cost model & economics — ✅ DONE (cost side; quality side needs Phase 7)
Turn the ledger into guidance. Implemented in `argo/costs.py` + `GET /costs` + a **Costs** UI page.
- [x] **Observed** economics from `llm_calls` (real `total_cost_usd`, not a static price list):
      totals + **average cost per run**, **by-model** (calls, cost, $/call, **$/1k output tokens**,
      share), **by-stage** (where the money goes), recent-run costs, and the **cheapest model per
      1k output tokens**.
- [x] Fed back into "Let the AI choose": the recommendation's rationale appends your observed
      average run cost. UI: a **Costs** page (`#/costs`).
- [x] **By-archetype** cost breakdown: recon now records the classified archetype in `meta.json`
      (`argo/archetype.py` + `stages/recon._capture_archetype`); `/costs` groups per-run cost by it.
      This is also the data the Phase-7 benchmarks group/calibrate on.
- [ ] _Later (needs Phase 7):_ the **cost/quality frontier** (cheapest config that *holds quality*)
      requires ground-truth quality metrics to pair with these costs.

### Phase 9 — Dynamic / runtime analysis (opt-in, sandboxed) — ✅ R1–R4 DONE
> Full design in **[runtime-verification-study.md](runtime-verification-study.md)**. Motivated by the
> Umbraco head-to-head: the reference audit's edge was 5 **HTTP-level live confirmations**. Runtime
> verification is **opt-in** (`--runtime`, default off), best-effort (graceful skip), and preserves
> the core guardrail — it builds the OSS target from the cloned source into an **ephemeral,
> egress-blocked, loopback-only** container and probes only that local instance, never the program's
> live hosts (same model as `verify.py`'s `--network=none` builds).
> Phases (all shipped): **R1** safe harness (sealed sandbox + `assert_loopback_only`/
> `validate_probe_plan`; proven live on Umbraco) → **R2** LLM proposes+interprets probe plans
> (validated; proven live) → **R3** launcher auto-detection (explicit / `argo-runtime.json` / repo
> Dockerfile) → **R4** verdicts rendered in `REPORT.md`. Decisions: user-recipe-first provisioning,
> Docker required (else skip), read-only probes by default. (Benchmark `runtime_confirmed_rate`
> deferred — needs a runtime recipe per labeled case.)

Goal: extend Argo beyond **static** detection toward a **confirm-by-running** capability, so a
finding can be backed by an observed runtime signal (a crashing input, a triggered assertion, an
exploited path) rather than a static hypothesis alone. This is the natural complement to the
LLM-native SAST: static finds the *candidate*, dynamic *proves* it.

This is a **deliberate boundary expansion**, so it must be designed carefully against the current
guardrails — today **no code execution** is a hard rule. The design constraints:
- **Opt-in and isolated.** Like Phase 6 (fix-verify), it runs only on an **isolated copy**, never the
  source mount, and never against the program's **live in-scope hosts** (that stays prohibited).
  Execution happens in a **locked-down sandbox** (offline container, `--network=none`, resource caps).
- **LLM proposes, harness runs.** The model writes the harness (a unit test, a fuzz target, a PoC
  script for a candidate finding); the sandbox executes it and feeds the **observed result** back to
  validation to confirm/refute — the model never gets an execution primitive directly.
- **Where it pays off.** Turns `needs_runtime_verification` findings into confirmed ones; gives the
  benchmark a ground-truth signal; raises precision without a second model. Closest existing seam:
  Phase 6's `verify.py` already builds/compiles an isolated copy — runtime analysis generalizes that
  from "compiles" to "executes a generated harness".
- **Why it's later, not now.** It crosses the static-only line that currently makes Argo safe to point
  at any repo. It needs a hardened sandbox story before it ships, and it should be **clearly separated**
  (a distinct opt-in mode) so the default tool stays static-only. Until then, Argo emits the
  `live_verification_plan` text for a human to run.

### Phase 10 — Live target interaction (opt-in, scope-locked) — ✅ L1–L3 DONE
> Full safety model in **[guardrails.md §2c](guardrails.md#2c-the-opt-in-live-exception-the-live-stage-in-scope-hosts-only)**.
> The deliberate, heavily-gated relaxation of the "never a live host" rule, for **authorized**
> bug-bounty engagements whose RoE permit automated interaction. The live analog of Phase 9's runtime
> sandbox: same propose→validate→execute→interpret shape, but the target is the **real in-scope host**
> instead of loopback — so the validators are **inverted and tightened**. **Off by default**, and the
> `argo live` command additionally requires an explicit `--i-have-authorization` acknowledgement.

Goal: let the agent do **bounded live recon/verification** against the program's in-scope assets to
**confirm findings and cut false positives** — exactly the edge a human researcher gets from touching
the target — without ever leaving the authorized envelope. Why it's a separate, gated mode (not the
default): it crosses the single hardest standing guardrail, so it stays opt-in, scope-locked, capped,
and audit-logged, and the default tool remains 100% offline against the program's hosts.

- **L1 — read-only live recon — ✅ DONE.** Hand-written `runs/<id>/live_probe_plan.json` →
  RoE-authorization gate (`assert_live_authorized`: `automation_allowed` + `safe_harbor` + declared
  `prohibited_techniques`) → **in-scope-only scope-lock** (`assert_inscope_only`: absolute URL whose
  host is a registered in-scope asset; out-of-scope/unknown/loopback hard-blocked; no wildcard
  overmatch) → read-only methods + anti-DoS caps (`validate_probe_plan`, oversized plan rejected whole)
  → a **fixed stdlib executor** (not a model shell) runs it with a rate cap, writing `live_results.json`
  + a full `live_audit_log.jsonl`. CLI: `argo live --run <id> --i-have-authorization`. Stage:
  `argo/stages/live.py`; config `live_enabled`/`live_allow_writes`/`live_max_requests`/
  `live_min_request_interval_s`/`live_request_timeout_s`/`live_max_payload_bytes` (all off/conservative
  by default). Tests: `tests/test_live.py` (gates + executor against an in-scope loopback server).
- **L2 — LLM-proposed live probe plan — ✅ DONE.** With no hand-written plan, an **offline** LLM
  session (`stages/live._generate_plan`, prompt `06_live_probe_prompt.md`) writes a plan from the
  validated findings — using **absolute in-scope URLs** (the inverse of R2's loopback-relative paths) —
  then the **same** deterministic gates run before any request; a second offline session
  (`_interpret`, `07_live_interpret_prompt.md`) judges each finding `live_confirmed/refuted/inconclusive`
  from the observations and attaches a `validation.live` block to `validated_findings.json`. Both
  sessions are network-free (`stage="live"` gets no network tools); only the fixed executor reaches the
  host. Still read-only. Mock-runner tested end-to-end (generate→gate→execute→interpret→attach).
- **L3 — state-changing probes — ✅ DONE.** Behind the **second** opt-in (`--allow-writes` /
  `live_allow_writes`), POST/PUT/PATCH are permitted for **non-destructive** confirmations only, with
  extra rails (`guardrails.assert_live_write_policy`): **DELETE is never allowed** even in write mode,
  state-changing requests are capped **separately** by `live_max_writes` (`--max-writes`, default 5),
  and each mutation's **body is recorded** in the audit log. The propose prompt (06) is hardened for
  writes (no DELETE, prefer a throwaway benign value, declare `expect`). Tests in `tests/test_live.py`
  (DELETE blocked, write cap, writes-without-opt-in blocked, body audited, run aborts on DELETE).
- **Executor hardening — ✅ DONE.** The live runner was strengthened for robustness + precision:
  a tool-identifying `User-Agent`; a **redirect guard** that never auto-follows (each `3xx` is
  re-validated in-scope before following, off-host redirects recorded not chased, writes never
  re-followed); **idempotent-only retries** with backoff honoring `Retry-After` (writes never retried);
  **response-header + redirect-chain evidence** capture; and **differential `control` probing** (a
  baseline request per probe, gated like any request, so the interpret stage judges the *difference* —
  the biggest false-positive cut for access-control findings). Config: `live_max_retries`,
  `live_max_redirects`, `live_user_agent`. Tests in `tests/test_live.py`.
- [ ] _Later:_ surface live verdicts in `REPORT.md` (as Phase-9 R4 did for runtime), and an authenticated
  live session (cookie/login step) reusing the runtime probe's auth-step shape.

## Deferred-feature backlog — feasibility & implementation plan (code-audited 2026-06-18)

### G. Gemini backend — ⬜ BACKLOG (blocked by Google's CLI migration, investigated 2026-06-26)
Adding Gemini as a 3rd provider in the `AgentRunner`/`FallbackRunner` chain (alongside Claude +
Codex). **Investigated and parked** — findings so the next attempt doesn't re-investigate:
- **The API key WORKS** — a raw `generativelanguage.googleapis.com/.../generateContent` call returns
  HTTP 200 with clean JSON + `usageMetadata` (tokens for cost). An AI-Studio key (new `AQ.Ab8…`
  format) is fine.
- **The `gemini` CLI (v0.49) is broken for us** — `gemini -p -o json` returns a persistent **503**
  across models; it routes to the deprecated Code Assist / Antigravity path (Google cut the free
  Code-Assist tier **2026-06-18** and is migrating users to **Antigravity / Antigravity CLI**).
- **Architecture implication:** the working path (raw API) is **text-only** — no agentic tools, so it
  cannot do Argo's agentic **audit/recon** (which need repo grep/read). It *could* serve the
  **text-reasoning stages** (`validate` — excerpts are already inlined; `sca`) as a fallback, which is
  exactly where session limits wall.
- **Two ways to revisit:** (A) build a raw-API `GeminiRunner` (HTTP, text-only) wired in as a
  fallback for `validate`/`sca` only — inherently safe (no tools = no network/mutation to strip);
  (B) wait for the `gemini`/Antigravity CLI to stabilize, then wrap it like `CodexRunner` (agentic).
- Either way it slots into the existing `_expand_backend`/`FallbackRunner` (e.g. `--fallback codex,gemini`).

Each item below was verified against the current code (exact files, functions, signatures, and
blockers). Effort is **S/M/L**; "paper value" rates how much it strengthens the research artifact.
**Recommended order: the evaluation block (A) first — it is what the paper's results section needs;
the chat depth block (B) next; the run-infra block (C) is low-value for a local single-user tool.**

### A. Evaluation & benchmark (paper-critical)

#### A1 — Seeded-bug benchmark corpora at scale — effort **M (mostly data)** · paper value **High** — ✅ ENGINE DONE
- **Shipped:** `Case` provenance (`corpus_id`, `cve_ids`, `seeded_from`, surfaced in `cases[].provenance`),
  optional `brief` (local-audit cases), `run_suite(..., parallel_cases=N)` + `argo bench --parallel-cases`,
  and a documented corpus recipe in `benchmarks/README.md`.
- **Reproducible commit pinning (2026-07-15):** `case.json` gains an optional `commit`; `acquire_repo`
  (and the whole `run_pipeline`/`argo pipeline --commit` path) fetches/checks out that exact revision,
  so a **URL-backed** CVE case is reproducible instead of cloning the (possibly-fixed) default head. URL
  corpora live under a **separate** suite `benchmarks/corpora/` so the default `benchmarks/` mock harness
  stays offline (ingest clones `repo` even on the mock runner). First real case shipped:
  `benchmarks/corpora/gguf-tools-oob/` (antirez/gguf-tools @ `fdfafbed766d`, 6 confirmed heap-OOB /
  integer-overflow labels, several fixed upstream). Tests: `tests/test_benchmark.py`
  (offline-default-suite, corpora commit+labels, `acquire_repo` pins a commit).
- **Remaining = data**: curate more real labeled CVE/seeded cases into `benchmarks/corpora/` (ongoing;
  the Fleece registry of confirmed findings is the natural source of labels).
- **Feasibility: high; the engine seam already exists.** `benchmark.load_suite(suite_dir)` globs every
  `<case>/case.json` + `expected_findings.json`, so the harness already runs an **unlimited** number of
  labeled cases and slices precision/recall/F1 by archetype and CWE (`run_suite`, `_aggregate`,
  `score_run`). The gap is **labeled data**, not code: only the bundled mock `acme-widgets` case exists.
- **Files:** `benchmarks/<new-case>/` (data — the bulk of the work); `argo/benchmark.py` (small
  additions); `argo/models.py` (none); `benchmarks/README.md` (document the corpus convention).
- **Implementation:**
  1. Curate real labeled cases: pinned OSS repos at a vulnerable commit (CVE checkouts) or seeded-bug
     forks, each a `case.json` (`name`, `brief`, `repo` = local path or URL, `archetype`) +
     `expected_findings.json` (`label`, `cwe`, `file`, `line`, `line_tolerance`, `aliases`, `severity`).
  2. Extend `case.json` (optional, additive) with provenance: `seeded_from`, `cve_ids`, `corpus_id` —
     `Case` is a dataclass; add fields with defaults, surface them in the report `cases[]` entries.
  3. Parallelize cases in `run_suite` (currently sequential) with a bounded pool, mirroring the
     `ThreadPoolExecutor` already used in `stages/validate.py`. Cost-gate behind `--runner mock` for
     harness CI; headless only when measuring real quality.
- **Hypotheses evaluated:** (a) "we need a corpus registry/versioning" — **not for v1**; pinning the repo
  commit in `case.json` + git-tracking the `benchmarks/` tree gives reproducibility for free. (b) "label
  quality must be measured" — worth a `kind: "safe"` negative-label convention (already honored by
  `score_run`) to catch over-reporting, but a full label-QA metric is over-engineering now.
- **Risk:** real runs cost money and are non-deterministic — report cost-per-case and run N≥3 for
  variance. Keep labels exhaustive (the scorer treats unmatched reported findings as FP).

#### A2 — Real triager accept-rate (the real-world precision signal) — effort **M** · paper value **High** — ✅ DONE
- **Shipped:** `findings_ledger` gains `triager_accepted/feedback/ts` (auto-migrated on open);
  `Ledger.record_triager_feedback()` + `Ledger.accept_rate()` (sliced by severity); `quality.py`
  pairs accept-rate with benchmark recall into `quality.json`. Channels: `argo feedback`
  (single or `--import` a Fleece export) and `argo quality`, plus `GET /quality` and a **Real-world
  quality** card on the Benchmarks page. Fleece stays the source of truth — no private data in the
  public repo.
- **Feasibility: medium; needs a new feedback channel + ledger columns.** Today `findings_ledger`
  (`argo/ledger.py`) stores `program_name, run_id, dedup_key, title, verdict, validated_severity` and
  `prior_sightings()` detects cross-run resubmissions — but there is **no accept/reject feedback** and no
  accept-rate query. This metric is the human-judged precision the paper pairs with benchmark recall.
- **Cross-repo note:** the real accept/reject data lives in **Fleece** (the private findings registry).
  The clean design is: Fleece is the source of truth for triager outcomes; Argo ingests them into the
  ledger (or reads a `quality.json` exported by Fleece) and computes the rate — **no private data in the
  public repo**.
- **Files:** `argo/ledger.py` (schema + methods), `argo/benchmark.py` (surface the metric),
  `server/app.py` (optional `POST /runs/{id}/feedback`), a new `quality.json` writer, `docs/*`.
- **Implementation:**
  1. `ALTER`/migrate `findings_ledger`: add `triager_accepted INTEGER NULL`, `triager_feedback TEXT`,
     `triager_ts TEXT` (nullable, back-compatible).
  2. `Ledger.record_triager_feedback(program_name, dedup_key, run_id, accepted, feedback=None)` and
     `Ledger.compute_accept_rate(program_name=None, run_id=None) -> {accepted, rejected, rate, by_verdict}`.
  3. Feed from Fleece (CLI importer or a small endpoint); emit `quality.json` pairing
     accept-rate (precision proxy) with benchmark recall — the paper's headline two-number result.
- **Hypotheses evaluated:** (a) "build a triager API/webhook" — **no**; for a single analyst a CLI
  importer from Fleece is simpler and keeps the boundary clean. (b) "use it as a feedback loop to retune
  audits" — out of scope for v1; record-and-report first.
- **Risk:** small-sample accept-rates are noisy; report n alongside the rate; never publish per-program
  Fleece data from the public repo.

#### A3 — Re-audit the patched copy ("is the bug actually gone?") — effort **M–L** · paper value **High** — ✅ DONE
- **Shipped:** `verify_patch(..., on_patched=hook)` runs a focused **unbiased** re-audit on the patched
  copy (`fixes._reaudit_patched`); `_still_present` matches on normalized CWE + file (line-lenient) →
  `verify.re_audit.confirmed_fixed`. Folded into `fixes_report` and the benchmark as
  `patch_quality.re_audit_confirmed_rate`. Exposed via `argo fix --re-audit`, `argo bench --fixes
  --re-audit`, and the API `re_audit` flag. Reported as a probabilistic signal *alongside* the build
  check (honest caveat in the docs), never instead of it.
- **Feasibility: medium; a real seam exists but `verify.py` is currently standalone.** `verify_patch(repo_dir,
  patch, *, docker, build_cmd, timeout_s)` copies the repo, applies the diff, and checks
  *applies + compiles + no new errors* (`_check`, `_norm_errors`). It does **not** re-run the audit, so a
  "verified" patch only means "didn't break the build", not "fixed the vuln". `fixes.generate_fixes(ctx, …)`
  already has the `RunContext` and writes `patches/<id>.diff` + `fixes_report.json`.
- **Files:** `argo/verify.py` (accept a re-audit callback or `RunContext`), `argo/fixes.py` (wire the
  re-audit after verify), `argo/stages/audit.py` (a scoped single-target audit entry), `argo/benchmark.py`
  (`re_audit_confirmed_rate`), `argo/ranking.py` (reuse `dedup_key`/matching).
- **Implementation:**
  1. Add a scoped re-audit: run Stage-3 audit on the **patched isolated copy**, restricted to the
     finding's affected file(s)/prompt, producing findings.
  2. Confirm the fix: the original finding's `dedup_key` (file+line+cwe) must be **absent** from the
     re-audit output → `re_audit_confirmed = True`. Reuse the benchmark `_matches`/`dedup_key` logic.
  3. Extend the verdict shape with `re_audit_confirmed` and aggregate `re_audit_confirmed_rate` into
     `patch_quality` in `benchmark.py`; gate behind a `--re-audit` flag (cost).
- **Hypotheses evaluated:** (a) "finding-gone ⇒ fixed" is **probabilistic** — the model could simply fail
  to re-surface the bug for unrelated reasons (false "fixed"). Mitigations: re-audit with the *same*
  generated audit prompt that found it (not a fresh recon), require the line-shift-aware match, and report
  it as a *signal* not proof. (b) "re-audit the whole repo" — too costly/noisy; scope to affected files.
  (c) the strongest version is the **Phase-9 dynamic** check (run a PoC that no longer triggers) — note A3
  as the static bridge to that.
- **Risk:** doubles audit cost per fixed finding; non-determinism — pair with the build-check, never
  replace it; keep the source mount untouched (work on the copy, as `verify.py` already does).

### B. Chat depth

#### B1 — "Why didn't you find X?" → candidate finding → re-validate — effort **S–M** · paper value **Med** — ✅ DONE
- **Shipped:** the chat analyst may write a `CANDIDATE_FINDING.json` for a concrete missed-vuln
  hypothesis; `chat.ask` re-validates it with the pipeline's `validate._validate_one` (isolated,
  read-only, refute-first) and appends the verdict (`validated_candidate` in the response, a pill in
  the UI). Non-mutating — it is an interactive probe, never added to `validated_findings.json`. The
  model (not a regex) decides when to propose a candidate. `_coerce_candidate` backfills partial
  hypotheses so they still validate.
- **Feasibility: HIGH — the hard part already exists.** `stages/validate._validate_one(ctx, scope,
  scope_json_text, finding)` validates a **single `Finding` in isolation** (builds code excerpts, runs the
  adversarial `02_adversarial_validation_prompt.md` in a fresh `work_dir`, returns a `Validation`) with **no
  dependency on the `findings/` directory**. `chat.ask(ctx, message)` already runs a read-only model turn
  and returns `{reply, generated, cost_usd}`. This directly attacks the dominant failure mode (false
  negatives) and is the most valuable chat feature.
- **Files:** `argo/chat.py` (detect the intent, synthesize the candidate, call `_validate_one`),
  `argo/models.py` (`Finding` — already importable, `extra="allow"`), no API/schema change (same
  `POST /runs/{id}/chat`), optional `webapp/js/app.js` chip wording.
- **Implementation:**
  1. In `chat.ask`, when the message matches a "why didn't you find …" intent, run one model turn that
     emits a **candidate `Finding` JSON** (the model proposes id/title/cwe/affected/flow/why/impact) for the
     hypothesis the user raised.
  2. Construct `Finding.model_validate(candidate)` and call `_validate_one(ctx, scope, scope_json_text,
     finding)`; append the resulting verdict + rationale (confirmed / refuted / needs-runtime) to the chat
     reply, and optionally write a `candidate_<id>.json` into `generated/`.
  3. Keep it **non-mutating**: nothing is added to `validated_findings.json`; it is an interactive probe.
- **Hypotheses evaluated:** (a) "append the candidate to the run's findings and re-run the whole validate
  stage" — **no**; `_validate_one` on the single candidate is cheaper, isolated, and avoids rewriting
  canonical artifacts. (b) "auto-extract the finding from the user's prose deterministically" — let the
  model synthesize the `Finding` (more robust than regex), then schema-validate.
- **Risk:** a user-led candidate can coax a false "confirmed" — keep the adversarial validator's
  refute-first framing (unchanged) and label these as **interactive probes**, not pipeline findings.

#### B2 — Streaming chat replies — effort **L** · paper value **Low (UX only)**
- **Feasibility: low-to-medium; a real architectural blocker.** Every backend uses a single **blocking**
  `subprocess.run()` and returns one complete `LLMResult`; there is **no token-callback or streaming path**
  anywhere (`runner.py` `_invoke` for Headless/Codex; `chat.ask` is one call; `POST /chat` returns a dict;
  the webapp `await api.sendChat`). The SSE machinery exists only for run status (`/runs/{id}/events`).
- **Files:** `argo/runner.py` (new streaming invoke via `subprocess.Popen` + line parsing; Claude Code
  supports `--output-format stream-json`, Codex emits JSONL on stdout — today parsed only post-exit),
  `argo/chat.py` (`ask_streaming` async generator), `server/app.py` (`GET /runs/{id}/chat/stream`
  StreamingResponse), `webapp/js/api.js` (`streamChat` via EventSource), `webapp/js/app.js` (progressive
  render in `chatPanel`).
- **Hypotheses evaluated:** (a) "add streaming to the core `run()`" — **don't**; add a *separate*
  `run_streaming()` so the blocking pipeline contract (cost logging, caps, partial recovery) is untouched.
  (b) value is purely perceived latency for one user — **defer** behind A and B1.
- **Risk:** async refactor touches the guardrail chokepoint; must preserve ledger logging + per-session
  caps that currently live in the blocking `run()`.

### C. Run infrastructure (low value for a local single-user tool)

#### C1 — Mid-stage cancellation — effort **M** · paper value **None** — ✅ DONE
- **Shipped:** the runner runs each CLI as a **cancellable subprocess** (`AgentRunner._exec`): a
  pump thread does `communicate`, the main thread polls `self.cancel_event` and, on Cancel,
  `_kill_tree` kills the whole process tree (`taskkill /T` on Windows, `killpg` on POSIX) and raises
  `RunnerCancelled`. The orchestrator wires `cancel_event` onto the runner and normalizes a mid-stage
  `RunnerCancelled` to a cancellation (status → cancelled). The UI shows "Cancelling…". Timeout path
  unchanged. So Cancel during a 20-min audit now stops it immediately, not at the next boundary.
- **Feasibility: medium.** `cancel_event` is checked only at **stage boundaries** (`orchestrator._check_cancel`),
  and the runner's `subprocess.run()` is never interrupted, so a click during a long audit takes effect only
  at the next boundary. Need to thread `cancel_event` into `runner.run`, switch to `subprocess.Popen` + poll,
  and kill the process group (Windows `CREATE_NEW_PROCESS_GROUP`/`creationflags`; Unix `preexec_fn=os.setsid`
  + `killpg`), then mark the running stage cancelled in `progress.py` and a "Cancelling…" state in the UI.
- **Verdict:** real but low priority — boundary cancellation already works for a single local user.

#### C2 — Per-run subprocess isolation — effort **M–L** · paper value **None**
- **Feasibility: medium.** Runs are in-process daemon threads (`server/jobs.py`, which itself notes
  "in-process threads are enough" for a local single-user tool). Moving to `multiprocessing.Process` (PID
  tracked in `status.json`, killable) buys crash-isolation and clean mid-run kill, but adds IPC/serialization
  complexity. **Defer** unless Argo is ever exposed multi-user (then pair with auth).

#### C3 — Repo ZIP upload from the UI — effort **M** · paper value **Low (UX)** — ✅ DONE
- **Shipped:** `POST /uploads` (multipart) extracts a repo `.zip` into a staging dir under
  `runs_dir` via `server/uploads.extract_zip` — hardened against **path traversal** (every member
  must resolve inside the dest), **zip bombs** (entry-count + uncompressed-size caps), and symlinks
  (skipped); the returned `repo` path then drives a normal `POST /runs` (ingest copies it read-only).
  The New Run form has an **⬆ Upload .zip** button. `python-multipart` added to requirements.
- **Feasibility: medium.** No multipart anywhere: `RunRequest.repo` is a string, `api.startRun` sends JSON,
  the New Run field is a text input, and `acquire_repo(source, dest, *, is_url)` only clones a URL or
  `copytree`s a local dir. Need a `multipart/form-data` endpoint (or `POST /runs/upload`), a temp-dir unzip
  with **zip-bomb / path-traversal guards** (entry count, total size, no `..`/absolute members), then pass
  the unzipped path to ingest with `is_url=False`. **Low value:** the server already resolves a typed local
  path on the same machine, so upload mainly helps a future remote deployment.

## Cross-cutting / decisions to make before Phase 0

- **UI stack.** FastAPI backend is the clear choice. Frontend: a lightweight modern SPA
  (React or Svelte + Vite) for richer live updates, **or** FastAPI + server-rendered + HTMX/Alpine
  for less JS and faster delivery. Pick based on how custom the UI must feel.
- **Single-user/local vs shared.** Assume local/personal first (no auth). Add auth only if the UI is
  ever exposed beyond localhost (it runs an agent over arbitrary repos — never expose it unauthenticated).
- **Default cost posture for UI runs.** Recommend: first run defaults to mock or a labeled cheap tier;
  real runs require an explicit budget + confirm. Prevents accidental $34 clicks.
- **Multi-backend: near-term need or "someday"?** Decides how much to generalize the runner in Phase 0
  vs. defer to Phase 5.

## Suggested first step

Phase 0 (the API + progress events) on the **mock runner** — it unblocks the whole UI, costs zero
tokens to build and test, and forces the streaming-progress design early. The UI (Phase 1) then has
a real backend to talk to from day one.
