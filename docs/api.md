# HTTP API (`server/`)

The backend that the web UI will talk to (Roadmap **Phase 0**). It wraps the pipeline so a run
can be started, watched live, and read back over HTTP. It **never weakens the engine guardrails**
(read-only repo, no live host, no patching, no auto-submit) and only serves whitelisted artifacts
— never the repo copy or arbitrary paths.

> Intended for **localhost / single user**. It runs an agent over arbitrary repos — do not expose
> it unauthenticated.

## Run it

```bash
python -m argo.cli serve --host 127.0.0.1 --port 8000 --runs-dir runs
# or:  uvicorn --factory server.app:create_app
```

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | liveness |
| GET | `/knowledge` | the curated vulnerability-class index by archetype (Phase 4) |
| GET | `/models` | available backends + selectable models (incl. the detected Codex default) + the token-cost price table — powers the UI model pickers and the Costs pricing card |
| GET | `/costs` | observed cost economics from the ledger (Phase 8): totals, by-model, by-stage, recent runs |
| GET | `/benchmark` | the latest benchmark report (Phase 7): findings P/R/F1 by archetype + CWE, or `null` |
| GET | `/benchmark/ab` | the latest A/B benchmark report, or `null` |
| POST | `/runs` | start a run (202 + `run_id`) |
| GET | `/runs` | list runs, newest first |
| GET | `/runs/{id}` | live status (stage timeline + cost + ready artifacts) |
| GET | `/runs/{id}/events` | **SSE** stream of status until terminal |
| POST | `/runs/{id}/cancel` | request cancellation (effective at the next stage boundary) |
| GET | `/runs/{id}/report` | `REPORT.md` (text/markdown) |
| GET | `/runs/{id}/artifacts/{name}` | a whitelisted single-file artifact |
| GET | `/runs/{id}/prompts` · `/findings` · `/drafts` | the multi-file artifacts |
| GET / PUT | `/settings` | persisted UI defaults (runner, budget, parallelism, per-stage models, …) |
| POST | `/recommend` | "Let the AI choose": `{repo, target}` → a recommended config + rationale (heuristic, no LLM; runner stays mock) |
| GET | `/runs/{id}/chat` | chat history for the run |
| POST | `/runs/{id}/chat` | `{message}` → one chat turn: `{reply, generated, cost_usd}` (read-only repo; test files go to `generated/`) |
| GET | `/runs/{id}/generated` | files the chat analyst produced (e.g. test suites) |
| POST | `/runs/{id}/fixes` | **Phase 6** — propose + verify a patch per confirmed finding: `{verify, docker, build_cmd, only}` → the fixes report. Target repo stays read-only; verify runs on an isolated copy |
| GET | `/runs/{id}/fixes` | the fixes report (`fixes_report.json`), or `null` if none generated |
| GET | `/runs/{id}/patches` | the proposed patches (unified diffs) under `patches/` |

Whitelisted artifact names: `scope`, `repo_profile`, `research_brief`, `threat_intel`,
`synthesis_notes`, `validated_findings`, `report`, `meta`, `status`, `brief`, `fixes_report`.

`POST /runs` accepts `"research": true|false` (default **true**) — the Stage-0 web-OSINT step that
runs before recon (the only networked stage; never the live in-scope hosts; see
[guardrails.md](guardrails.md#2a-the-one-bounded-exception-the-research-stage-osint-only)). When on,
`research` appears in the run's `stages` timeline and produces the `research_brief` / `threat_intel`
artifacts; `research: false` keeps the run fully offline.

### Remediation / fix verification (Phase 6)

`POST /runs/{id}/fixes` is **opt-in** and separate from the detection-only audit. For each
confirmed finding it asks the model (the run's own runner — free for mock runs) for a **patch as a
unified diff**, writes it to `runs/<id>/patches/<finding_id>.diff`, then **verifies** it: the patch
is applied to an **isolated copy** of the repo and the copy is built/compiled to confirm it
**(1) applies, (2) still compiles, (3) introduces no new errors** vs. a pre-patch baseline. The
verdict per finding:

```json
{ "applied": true, "compiles": true, "new_errors": [], "verified": true,
  "reason": "ok", "targets": ["src/api/search.py"], "tool": "py_compile" }
```

`verify` (default `true`) toggles the build check; `docker: "image"` runs the build in an offline
container (`--network=none`); `build_cmd` supplies an explicit build/compile command; `only` limits
to specific finding ids. The target repo is **never** modified, nothing is applied in place, and no
PR is opened.

### Benchmarks (Phase 7) — read-only

`GET /benchmark` returns the latest `benchmark_report.json` (or `null`). Benchmarks are **run from
the CLI** (`argo bench` — real runs cost money, so the API does not start them) and surfaced
read-only here and on the **Benchmarks** UI page: precision/recall/F1 overall and sliced by
archetype and CWE, plus optional patch-quality and A/B (`GET /benchmark/ab`).

## Start a run

`POST /runs`

```json
{
  "brief": "ACME CMS — Bug Bounty Program\nScope: ...",
  "repo": "https://github.com/acme/acme-cms",
  "links": "https://acme.com\nhttps://acme.com/security",
  "dry_run": false,
  "config": { "runner": "mock", "budget_usd": 20, "audit_model": null,
              "calibration": false, "parallel": 3 }
}
```

- `brief` / `links` are **pasted text** (not file paths). `repo` is a git URL **or a local folder
  path**. **`brief` is optional**: omit it (or send empty) to audit a **local/personal** codebase as a
  source-only review — the scope is synthesized from `repo` and web research is auto-disabled.
- `config.runner` defaults to **`mock`** — a request spends **zero tokens** unless the client
  explicitly sets `"headless"` (Claude Code) or `"codex"` (Codex CLI / OpenAI / OSS). This is the
  safety default; the UI adds an explicit confirm + cost preview before a real run.
- For `"codex"`: `config.codex_model` (omit to use your Codex CLI default, e.g. `"gpt-5-codex"`), `config.codex_oss` (bool), and
  `config.codex_local_provider` (`"ollama"`/`"lmstudio"`) select the model / open-source provider.
  See [backends.md](backends.md).
- `config` maps to `PipelineConfig` (budget is a hard per-run ceiling, etc. — see
  [configuration.md](configuration.md)).

Returns `202` with `{ run_id, state, status_url, events_url }`.

## Live status

`GET /runs/{id}` (and each SSE event) returns:

```json
{
  "run_id": "...",
  "state": "running",            // starting | running | completed | failed | cancelled
  "current_stage": "audit",
  "stages": [ {"name":"ingest","state":"done"}, {"name":"recon","state":"done"},
              {"name":"audit","state":"running"}, ... ],
  "artifacts": { "scope": true, "repo_profile": true, "synthesis_notes": true,
                 "prompts": 3, "findings": 1, "validated_findings": false,
                 "report": false, "drafts": 0 },
  "cost_usd": 12.34,
  "error": null
}
```

`cost_usd` is read **live from the ledger** (advances even mid-stage). `artifacts` reflects which
canonical files exist, so the UI can reveal partial results as they land (scope → prompts → each
focus's findings → validated → report) instead of a blind spinner.

## How it works (design)

- **Background jobs.** `POST /runs` writes the inputs, starts the pipeline in a daemon thread
  (`server/jobs.py`), and returns immediately. Cancellation is a `threading.Event` checked at each
  stage boundary.
- **File-based progress.** The pipeline writes `runs/<id>/status.json` at every stage boundary
  (`argo/progress.py`), updated atomically and resiliently (telemetry never crashes a run).
  The status/SSE endpoints read that file + live cost from the ledger — no in-memory coupling to
  the job.
- **Concurrency.** The ledger runs in WAL mode with a busy timeout, so the API's read connection
  and the job's write connection coexist without locking.

## Tested

`tests/test_api.py` drives the whole lifecycle on the **mock runner** (zero tokens): full pipeline,
dry-run, the SSE stream reaching a terminal state, the artifact whitelist, and 404s.

## Not yet (later roadmap phases)

Auth/multi-user, subprocess isolation per run (vs. in-process threads), mid-stage cancellation,
file-upload of a repo zip, and the frontend itself (Phase 1). See [roadmap.md](roadmap.md).
