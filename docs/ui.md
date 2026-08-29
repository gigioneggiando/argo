# Web UI (`webapp/`)

The Phase-1 interface: paste a program, point at a repo, click start, watch the audit run live,
read the results — without the CLI. It is served by the API (`server/`) and talks to the same
endpoints documented in [api.md](api.md).

## Run it

```bash
python -m argo.cli serve --open     # starts the API + UI and opens http://127.0.0.1:8000
# without --open: open http://127.0.0.1:8000 yourself (redirects to /app/)
```

> Localhost only — it runs an agent over arbitrary repos. Do not expose it unauthenticated.

## Stack choice — no build step (deliberate)

Vanilla ES modules + modern CSS, served as static files by FastAPI; a hash router; `marked`
vendored locally (`webapp/vendor/`) so there is **no runtime CDN dependency**. No npm / Node /
bundler. For a local single-user tool, reliability beats toolchain fashion — it always runs, and
"modern" is delivered through the **design and UX** (live stage timeline, artifacts that reveal as
they land, a ticking cost meter), not build complexity.

```
webapp/
  index.html        shell
  styles.css        design system (dark, token-based; Inter + JetBrains Mono)
  assets/fonts/     self-hosted Inter + JetBrains Mono variable woff2 (no CDN, offline-safe)
  js/api.js         API client + SSE wrapper
  js/ui.js          DOM helpers + components (pills, chips, hyperscript h())
  js/charts.js      dependency-free, theme-aware chart primitives (donut, bars, stat tile)
  js/icons.js       monochrome feather-style SVG icon set (currentColor) — no emoji glyphs
  js/app.js         hash router + the views
  vendor/marked.min.js   markdown renderer (vendored)
```

## Theme

Light + dark, toggled from the topbar (☀/☾). The choice is persisted (localStorage) and defaults
to the OS `prefers-color-scheme`; an inline head script applies it before paint, so there is no
flash. All colors are CSS custom properties with a `[data-theme="light"]` override.

## The views

- **Overview** (`#/`, the landing) — a dashboard over **all** runs, rendered with the `js/charts.js`
  primitives (dependency-free inline SVG, theme-aware via the CSS severity/status tokens, hover
  tooltips). Four KPI stat tiles (total runs, validated findings, total spend, avg/run) over: a
  **findings-by-severity** donut (status-colored, lazily aggregated across completed runs), a
  **findings-by-verification** donut (confirmed vs. needs-runtime-check — the "prove, don't just
  detect" ratio), a **runs-by-outcome** donut, a **top-CWEs** bar, a **spend-by-run** bar, and a
  **runs-by-archetype** bar. Cheap charts render from one `GET /runs`; the severity/verification/CWE
  charts fill in after a bounded
  (concurrency-4) fan-out over each completed run's `validated_findings`. Chart forms follow the
  dataviz method — parts-of-whole → labeled donut, magnitude → single-hue bars.
- **New run** (`#/new`) — a **mode** toggle picks the workflow: **🔍 General audit** (default — audit any
  codebase: point *Code to audit* at a local folder path or repo, **no brief**; the brief/links fields
  are hidden) or **🎯 Bug bounty** (reveals *Program description* + *Reference links* for a scoped
  program). Both feed the same engine. Plus *Code to audit* (a local folder path — resolved on the
  machine running the server; mounted read-only and never pushed, though a cloud backend sends the
  source to its API to analyze while a local/OSS model keeps it on-device — or a git URL) and an
  *Advanced* panel (runner, budget, audit model, parallel, calibration, dry-run, **web research**).
  The Code-to-audit field also has an **⬆ Upload .zip** button (C3): the zip is safely extracted
  server-side (path-traversal + zip-bomb guarded) and its path fills the field. The
  **Web research (Stage 0)** toggle (default **On**) runs the opt-out web-OSINT pass before recon
  (one of two networked steps, with corroborate; never the live in-scope hosts); **Off** keeps the run fully offline.
  The **runner** selector offers **Mock** (free) · **Claude** (with an API-key field, shown when
  Claude is picked — blank uses the server's ambient login) · **Codex** (with a Codex model +
  local/OSS provider field, plus an API-key field that makes Argo bootstrap a dedicated Codex
  profile for it) · **Gemini** (with a Gemini model + API-key field, shown when Gemini is picked —
  see [backends.md](backends.md)). All three key fields are `type="password"`, never echoed back or
  persisted in the clear. The model inputs are
  **pickers** populated from `GET /models` (Claude opus/sonnet/haiku; Codex examples + the
  **detected Codex default**, shown in the placeholder; Gemini pro/flash/flash-lite). The **Costs**
  page adds a **Model pricing & backends** card (the `$/1M token` table + which backend reports real
  vs. estimated cost). **Cost-aware**: the runner defaults to **Mock (free)**; switching to any real
  backend (Claude/Codex/Gemini) reveals a cost warning. A **"Let the pipeline choose"** card
  (Quick / Standard / Thorough) calls `POST /recommend` and fills the config for you (runner stays
  Mock). Start → navigates to the live run.
- **Settings** (`#/settings`) — persisted defaults for the New Run form: **default runner** (Mock /
  Claude / Codex / Gemini), budget, parallelism, audit model, calibration, and **per-stage Claude
  models**. Per-backend sub-fields (Codex provider/API key, Gemini model/API key, Claude API key)
  are set per-run in New Run, not persisted here — `Settings` (`server/schemas.py`) is deliberately
  a narrower shape than `RunConfig`. Saved server-side via `GET/PUT /settings`.
- **Vuln index** (`#/knowledge`) — the curated vulnerability-class index by archetype (the same
  reference injected into recon). Browsable / educational; from `GET /knowledge`.
- **Costs** (`#/costs`) — observed economics from the ledger: average cost per run, by-model
  ($/call and $/1k output tokens), by-stage (where the money goes), recent runs, and the cheapest
  model. Real per-call costs (mock runs are $0). From `GET /costs`.
- **Benchmarks** (`#/benchmark`) — findings quality (precision / recall / F1) against labeled
  suites, sliced by archetype and CWE, plus per-case missed/spurious and optional patch quality +
  A/B. A **Real-world quality (A2)** card pairs the triager **accept-rate** (from `GET /quality`,
  fed by `argo feedback`) with benchmark recall — shown only once feedback exists. Two further
  cards, shown when their report exists: **Cross-backend comparison** (cost/latency/P/R/F1 per
  backend, from `argo bench-cross` / `GET /benchmark/cross`) and **Refusal-rate probe**
  (`refusal_flag_rate`/`refusal_recovery_rate` per backend, from `argo refusal-probe` /
  `GET /refusal-probe`) — see [backends.md](backends.md) and
  [../benchmarks/README.md](../benchmarks/README.md#cross-backend-comparison-and-refusal-rate).
  Read-only throughout; reports are generated by the CLI. From `GET /benchmark` + `GET /quality`.
- **Run** (`#/run/<id>`) — the live view (no blind spinner):
  - a **stage timeline** (ingest → recon → audit → validate → report) that fills in via SSE, with a
    pulsing active stage and a live **cost** chip;
  - **artifact cards** that update as files land (scope → prompts → per-focus findings → validated
    → report → drafts);
  - a **Cancel** button while running;
  - when it finishes, results appear inline as tabs: **Report** (rendered `REPORT.md`), **Findings**
    (a **severity-mix donut** over the survivors, plus the sortable/filterable table with a detail
    drawer per finding), **Fixes** (see below), **Chat**
    (see below), **Drafts**, **Artifacts** (scope / repo profile / synthesis / validated JSON). A
    dry-run shows the prompts.
- **Fixes** (a results tab, Phase 6) — opt-in remediation. "Propose & verify fixes" generates a
  reviewable patch (unified diff) per confirmed finding and shows each with a **verify verdict**:
  ✓ *verified — compiles, no new errors*, or ⚠ with the reason (didn't apply / introduced errors).
  Patches are proposals for a maintainer — never auto-applied to the target or submitted. Uses the
  run's runner (free for mock runs). From `POST /runs/{id}/fixes` + `GET …/patches`.
- **Chat** (a results tab) — an interactive analyst with the run's full context + read-only repo.
  Ask "why didn't you find X?", "explain SQLI-001", "what did you deprioritize?", or "generate a
  test suite for CWE-89". Generated test files are shown inline and written to `runs/<id>/generated/`
  — never into the target repo. **B1 — re-validation:** when you challenge a *specific* missed
  vulnerability, the analyst can propose a candidate finding that is **re-checked independently by
  the pipeline's adversarial validator**; the verdict (✅ confirmed / ❌ refuted / ⚠️ needs-runtime)
  appears as a pill under the reply (an interactive probe — it is **not** added to the run's
  findings). Chat uses the run's runner (free for mock runs); its cost is added to the run total.
  See a **real worked transcript** in [chat-example.md](chat-example.md).
- **History** (`#/history`) — every past run (program, state, cost), click to reopen.

## How live progress works

The run view opens an `EventSource` to `GET /runs/{id}/events` (SSE). Each event is the run's
`status.json` (stage states + live cost + which artifacts exist), so the timeline and the artifact
cards update in real time and partial results are shown as soon as each stage produces them. See
[api.md](api.md) and `argo/progress.py`.

## Safety / guardrails in the UI

- Default runner is **Mock** → a click costs nothing until you explicitly choose Real.
- The UI only calls whitelisted artifact endpoints; it never receives the repo copy or arbitrary
  paths. All the engine guardrails (read-only repo, no live host, no patching, no auto-submit)
  are unchanged — the UI is a viewer/launcher, not a new execution path.

## Tested

`tests/test_api.py` covers the static serving (index + assets) and the full run lifecycle the UI
drives, on the mock runner (zero tokens). JS module syntax is validated with Node in development.
Visual rendering should be eyeballed in a browser.

## Known gap

The runner selector and Settings cover all three real backends (Claude/Codex/Gemini). The opt-in
pipeline stages added since (second-opinion, corroborate, deep-verify, runtime, live, ASan PoC —
see [roadmap.md](roadmap.md)) are **CLI-only**: `server/schemas.py`'s `RunConfig` deliberately
covers only the core-loop fields, so there is nothing to wire up in the UI yet. Revisit if/when
that server-side scope is intentionally widened — this is not an oversight, `live` in particular
carries an authorization acknowledgement that needs its own careful UI treatment, not a checkbox.
