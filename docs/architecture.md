# Architecture

The pipeline is **orchestration-only glue** around five reusable prompt assets. The security
logic lives in the prompts (`argo/prompts/`); this code ingests a program, sequences the
five stages, and produces a reviewable report. It never writes audit logic itself.

See [diagrams/pipeline_flow.svg](diagrams/pipeline_flow.svg) for the visual flow.

## Module map

```
argo/
  cli.py            Typer CLI: ingest / recon / run / validate / report / pipeline
  orchestrator.py   wiring: build a RunContext, generate run IDs, drive the stages
  config.py         PipelineConfig: per-stage models, tool allowlists, budgets, caps
  context.py        RunContext (paths + scope loading + budget guard) + artifact collection
  models.py         pydantic models mirroring the JSON Schemas (Scope, Finding, ...)
  schemas.py        Draft-07 validation against scope_schema.json / findings_schema.json
  guardrails.py     tool allowlist enforcement, prohibited-technique assertions, scope filter
  rendering.py      placeholder fill, the .j2 template, the artifact-contract epilogue
  runner.py         ClaudeRunner interface + HeadlessClaudeRunner + MockClaudeRunner
  ranking.py        severity/confidence ordering, ref parsing, dedup_key
  ledger.py         SQLite: llm_calls (cost) + findings_ledger (cross-run dedup)
  progress.py       ProgressReporter -> runs/<id>/status.json (live stage timeline + cost)
  chat.py           Phase-3 interactive analyst over a completed run (read-only repo; test-gen)
  knowledge.py      Phase-4 vuln-class index loader (data/vuln_index.yaml) injected into recon
  costs.py          Phase-8 cost analytics from the ledger (by model / stage / run / archetype)
  archetype.py      canonical software archetypes + normalizer (captured per run into meta.json)
  fixes.py          Phase-6 remediation: propose a patch per confirmed finding (opt-in)
  verify.py         Phase-6 patch verification on an ISOLATED COPY (applies? compiles? no new errors?)
  benchmark.py      Phase-7 eval: score findings P/R/F1 vs labeled suites (by archetype / CWE) + A/B
  stages/
    ingest.py   research.py   recon.py   audit.py   validate.py   report.py
  prompts/          the five assets, version-pinned (sha256 recorded per run)

server/             HTTP API on top of the pipeline (FastAPI) — see api.md
  app.py            endpoints (run lifecycle, SSE progress, whitelisted artifacts) + serves webapp/
  jobs.py           background daemon-thread runs + cancellation
  schemas.py        request/response models

webapp/             no-build web UI (vanilla ES modules + CSS) — see ui.md
```

## Stage data flow

Each stage reads the previous stage's files from `runs/<RUN_ID>/` and writes its own.

| Stage | Entry point | Reads | Writes |
|---|---|---|---|
| 1 Ingest | `stages/ingest.run` | brief (or **none** → local review), repo (folder or URL) | `scope.json`, `meta.json` (incl. pinned `repo_commit`), read-only `repo/`. No brief ⇒ a source-only scope is **synthesized** from the folder (zero-token, no LLM call). |
| 0 Research | `stages/research.run` | `scope.json` (name, brief, links) | `research_brief.md`, `threat_intel.json` — **opt-out web OSINT**, the ONLY networked stage; no repo; never the live in-scope hosts (see [guardrails.md](guardrails.md#2a-the-one-bounded-exception-the-research-stage-osint-only)) |
| 2 Recon | `stages/recon.run` | `scope.json`, `repo/`, `research_brief.md` | `repo_profile.json`, `prompts/audit_*.md`, `synthesis_notes.md` (archetype + threat-intel driven — see [prompt-synthesis.md](prompt-synthesis.md)) |
| 3 Audit | `stages/audit.run` | `prompts/`, `repo/` | `findings/<focus>.json` |
| 4 Validate | `stages/validate.run` | `findings/`, `repo/`, `scope.json` | `validated_findings.json` |
| 5 Report | `stages/report.run` | `validated_findings.json` | `REPORT.md`, `submission_drafts/`, ledger rows |

`pipeline` runs 1→5 (or 1→2 with `--dry-run`) and **stops before any submission**.

## The `ClaudeRunner` abstraction

Every LLM call goes through one interface, so guardrails and cost logging cannot be bypassed
(BUILD_SPEC: "make the runner an interface so it can be swapped").

```python
class ClaudeRunner(ABC):
    def run(self, *, prompt, run_dir, work_dir, model, stage, run_id,
            repo_dir=None, allowed_tools=ARTIFACT_TOOLS, label=None) -> LLMResult: ...
```

`run()` is the single chokepoint. It:
1. sanitizes the tool allowlist (`guardrails.enforce_session_tools`) and asserts no network tool,
2. computes the per-session budget and delegates to `_invoke()`,
3. **strictly parses** the result envelope (`parse_result_envelope`),
4. logs the call to the ledger + `llm_log.jsonl` (always, even on error),
5. surfaces API errors loudly and enforces per-session caps.

Two implementations:
- **`HeadlessClaudeRunner`** — shells out to `claude -p --output-format json`. See
  [headless-runner.md](headless-runner.md).
- **`MockClaudeRunner`** — writes fixture files into the scratch dir and returns a synthetic
  manifest. Zero tokens; used by the whole test suite.

## `RunContext`

Threaded through every stage. Holds `run_id`, `config`, `runner`, `ledger`, the loaded `scope`,
and an injectable `now` (for deterministic report output in tests). Exposes the run-dir paths
(`scope_path`, `repo_dir`, `prompts_out_dir`, `findings_dir`, `validated_findings_path`,
`drafts_dir`, `work_dir(...)`), `load_scope()` (schema-validated), and `assert_budget()`.

### Artifact collection (files are the source of truth)

`collect_output_files(result, glob)` resolves the files a session wrote: it reads the manifest's
index **and** unions a scratch-dir glob, so a missing/partial manifest or a session that died
mid-write still recovers whatever was written. The model's stdout JSON is used only for run
metadata, never to carry artifacts.

### Scratch vs. canonical artifacts (why a file appears twice)

Every stage artifact exists in **two** places, and this is by design — not a bug, not duplicated
data to merge:

| Location | What it is | Read by downstream stages? |
|---|---|---|
| `runs/<id>/work/<stage>/…` | **scratch**: the raw file the LLM session wrote in its isolated cwd | no — it is the partial-recovery source and a raw-output audit trail |
| `runs/<id>/…` (run root) | **canonical**: the orchestrator's normalized + schema-validated result | yes — every stage reads only the canonical path |

The two can legitimately **differ in content**, because promotion to canonical applies
normalization. The clearest example is `scope.json`:

- `work/ingest/scope.json` — the model's raw extraction (may contain `"rate_limits": null`, and
  may have wrongly placed the `--repo` URL into `reference_links`).
- `scope.json` (run root) — after `_strip_nulls`, the `--links` merge, and the
  repo-URL-never-a-reference-link safety rule. **This is the single source of truth**;
  `ctx.scope_path` points here and `recon`/`audit`/`validate` read only this.

So there is already exactly one authoritative copy per artifact. **Do not "merge" the scratch
copy back in** — that would re-introduce precisely the `null`s and mis-scoped links the pipeline
deliberately removed. For `repo_profile.json` / `prompts/` the two copies are usually identical
(a straight copy), which is why only `scope.json` (same filename, visibly normalized data) tends
to stand out. The `work/` tree is safe to delete after a successful run if you want leaner run
dirs; keep it when a run fails, since that is when partial recovery and raw-output debugging need
it.

## Dedup algorithm (Stage 4)

```
dedup_key = sha1(normalize(primary_file + primary_line + cwe))
```

`normalize` lowercases, unifies path separators, and strips whitespace. Findings that share a
key collapse to one: the keeper is chosen by (highest severity, then highest confidence, then
first seen); the others' `affected` and `variants` are unioned in. Implemented in
`ranking.py` (`split_ref`, `dedup_key`) and `stages/validate.py` (`_merge`).

## SQLite ledger

`argo/ledger.sqlite` (git-ignored), two tables:

```sql
llm_calls(id, ts, run_id, stage, model, prompt_sha256,
          input_tokens, output_tokens, cost_usd, num_turns, session_id, stop_reason)

findings_ledger(id, ts, program_name, run_id, dedup_key, title, verdict, validated_severity,
                UNIQUE(program_name, dedup_key, run_id))
```

- `llm_calls` powers cost control and the hard per-run `--budget` guard (`run_cost()`).
- `findings_ledger` detects cross-run/cross-program resubmission (`prior_sightings()`), which
  Stage 5 surfaces as a "possible resubmissions" section.

The connection is opened with `check_same_thread=False` + a write lock, because the audit and
validate stages log from parallel worker threads.

## Remediation & verification (Phase 6, opt-in)

The audit is **detection-only**. A separate, opt-in flow (`argo fix`, `POST /runs/{id}/fixes`)
turns confirmed findings into **proposed patches for a human** — never auto-applied, never
submitted. `fixes.py` runs one model session per confirmed finding (read-only repo, artifact tools)
that writes a unified diff; the diff is saved to `runs/<id>/patches/<id>.diff`.

`verify.py` then enforces the safety- and quality-bar on an **isolated copy** (`copytree`, write
bits restored — the source mount is never touched):

1. **baseline** build/compile check on the copy → error set *B*;
2. apply the patch (`git apply -p1`, strict; falls back to `patch --fuzz=0`);
3. **patched** build/compile check → error set *A*;
4. `new_errors = A − B` (error signatures normalized to drop path + line/col, so a patch that only
   shifts line numbers isn't mistaken for a regression). `verified = applied ∧ compiles ∧ no
   new_errors`.

Pre-existing breakage therefore never fails a patch — only errors it *introduces* do. The build
runs **locally** (auto-detected dependency-free checks: `py_compile`, `node --check`, `go build`,
`cargo check`) or **in Docker** (`--network=none`, offline) / via an explicit `--build-cmd`. The
verdict is written to `runs/<id>/fixes_report.json`.

## Benchmarks & evaluation (Phase 7)

`benchmark.py` scores findings quality against a **suite** of labeled cases
(`benchmarks/<case>/case.json` + `expected_findings.json`). For each case it runs the pipeline,
then matches validated findings to labels: a reported finding matches when the **normalized CWE**
agrees (or is in the label's `aliases`) and the **file** matches (path-suffix), optionally within a
`line_tolerance`. Labels are treated as exhaustive — unmatched reported = FP, unmatched label = FN —
yielding **precision / recall / F1** overall and sliced **by archetype** and **by CWE**. `--fixes`
folds in Phase-6 patch-verified rate; `ab_compare` runs the suite under two configs and reports the
metric delta. Reports land in `<runs_dir>/benchmark_report.json` (read-only `GET /benchmark`). The
whole harness runs on the mock runner at zero tokens; headless measures real model quality.
