# Roadmap — UI & advanced features on top of the pipeline

Status: planning. This document analyzes each requested feature (feasibility / utility / priority
/ needed?), proposes a phased build order, and tracks the todo list. The pipeline (CLI + stages +
`ClaudeRunner` + ledger) is the engine; everything here sits **on top** of it and must keep its
guardrails intact (no live host, no patching the target, read-only repo, no auto-submit).

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
4. **The `ClaudeRunner` is already swappable.** Multi-backend is *architecturally* prepared; the
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
- [ ] _Later:_ subprocess isolation per run, mid-stage cancellation, surface the budget abort in UI.

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
- [ ] _Later:_ repo zip upload; richer in-browser visual polish pass.

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
- [x] Chat endpoint: a `ClaudeRunner` session seeded with the run's artifacts (scope, repo_profile,
      synthesis_notes, validated_findings) + **READ-ONLY** repo; history persisted to
      `runs/<id>/chat.jsonl`; chat uses the run's runner (free for mock runs) and its cost is
      added to the run total.
- [x] Canned actions in the UI: "explain a finding", "why didn't you find…", "generate tests for a
      CWE", "what did you deprioritize?".
- [x] Test-suite generation: written to `runs/<id>/generated/` only — the target repo stays
      read-only (verified: generated files never land in `repo/`). Served via `GET .../generated`.
- [ ] _Later:_ a "why-not-found" lead → append a candidate finding and re-run validation;
      token-streaming replies (currently one call per turn).

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
- [ ] _Later:_ the real-world signal (triager-accepted rate per program), seeded-bug corpora at
      scale, and "re-audit the patched copy to confirm the bug is gone" as a stronger patch metric.

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

### Phase 9 — Dynamic / runtime analysis (future, opt-in, sandboxed) — ⬜ NOT STARTED
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
