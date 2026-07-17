# Architecture

The pipeline is **orchestration-only glue** around five reusable prompt assets. The security
logic lives in the prompts (`argo/prompts/`); this code ingests a program, sequences the
stages, and produces a reviewable report. It never writes audit logic itself.

See [diagrams/pipeline_flow.svg](diagrams/pipeline_flow.svg) for the visual flow.

## Module map

```
argo/
  cli.py            Typer CLI: ingest / recon / run / validate / corroborate / verify / report / pipeline
  orchestrator.py   wiring: build a RunContext, generate run IDs, drive the stages
  config.py         PipelineConfig: per-stage models, tool allowlists, budgets, caps
  context.py        RunContext (paths + scope loading + budget guard) + artifact collection
  models.py         pydantic models mirroring the JSON Schemas (Scope, Finding, ...)
  schemas.py        Draft-07 validation against scope_schema.json / findings_schema.json
  guardrails.py     tool allowlist enforcement, prohibited-technique assertions, scope filter
  rendering.py      placeholder fill, the .j2 template, the artifact-contract epilogue
  runner.py         AgentRunner interface + HeadlessClaudeRunner · CodexRunner · MockClaudeRunner
  ranking.py        severity/confidence ordering, ref parsing, dedup_key
  ledger.py         SQLite: llm_calls (cost) + findings_ledger (cross-run dedup)
  progress.py       ProgressReporter -> runs/<id>/status.json (live stage timeline + cost)
  chat.py           Phase-3 interactive analyst over a completed run (read-only repo; test-gen;
                    B1: re-validates a user-proposed candidate finding via validate._validate_one)
  knowledge.py      Phase-4 vuln-class index loader (data/vuln_index.yaml) injected into recon
  checklists.py     Phase-4 mandatory coverage checklist injected into every audit prompt (memory-
                    safety / resource-exhaustion / crypto lenses, gated on repo signals) + P1 rule
  census.py         Phase-4 cross-file variant-census worksheet: pre-scan defect families (free/copy/
                    alloc sinks, panic points) and inject their concrete site+file extent per prompt
  costs.py          Phase-8 cost analytics from the ledger (by model / stage / run / archetype)
  quality.py        A2 quality report: triager accept-rate (ledger) paired with benchmark recall
  archetype.py      canonical software archetypes + normalizer (captured per run into meta.json)
  fixes.py          Phase-6 remediation: propose a patch per confirmed finding (opt-in)
  verify.py         Phase-6 patch verification on an ISOLATED COPY (applies? compiles? no new errors?)
  benchmark.py      Phase-7 eval: score findings P/R/F1 vs labeled suites (by archetype / CWE) + A/B
  stages/
    ingest.py  research.py  recon.py  audit.py  sca.py  validate.py  corroborate.py  deep_verify.py
    runtime.py  report.py
  verify.py         Phase-6 isolated-copy build/compile check (reused by the runtime sandbox)
  prompts/          the assets, version-pinned (sha256 recorded per run)

server/             HTTP API on top of the pipeline (FastAPI) — see api.md
  app.py            endpoints (run lifecycle, SSE progress, whitelisted artifacts) + serves webapp/
  jobs.py           background daemon-thread runs + cancellation
  schemas.py        request/response models
  uploads.py        C3: safe repo .zip extraction (path-traversal / zip-bomb guarded)

webapp/             no-build web UI (vanilla ES modules + CSS) — see ui.md
```

## Stage data flow

Each stage reads the previous stage's files from `runs/<RUN_ID>/` and writes its own.

| Stage | Entry point | Reads | Writes |
|---|---|---|---|
| 1 Ingest | `stages/ingest.run` | brief (or **none** → local review), repo (folder or URL), optional `--links` / `--accepted-risks` | `scope.json` (incl. `accepted_risks` design context if given), `meta.json` (incl. pinned `repo_commit`), read-only `repo/`. No brief ⇒ a source-only scope is **synthesized** from the folder (zero-token, no LLM call). |
| 0 Research | `stages/research.run` | `scope.json` (name, brief, links) | `research_brief.md`, `threat_intel.json` — **opt-out web OSINT**, one of two networked stages (with corroborate); no repo; never the live in-scope hosts (see [guardrails.md](guardrails.md#2a-the-one-bounded-exception-the-research-stage-osint-only)) |
| 2 Recon | `stages/recon.run` | `scope.json`, `repo/`, `research_brief.md` | `repo_profile.json`, `prompts/audit_*.md`, `synthesis_notes.md`, **`ground_truth.json`** (archetype + threat-intel driven — see [prompt-synthesis.md](prompt-synthesis.md)) |
| 3 Audit | `stages/audit.run` | `prompts/`, `repo/` | `findings/<focus>.json`, **`variant_logs/<focus>.md`** (+ a completeness-critic re-pass per focus) |
| SCA | `stages/sca.run` | `repo/` dependency manifests, `scope.json` | `findings/dependencies.json` — **opt-out** software-composition analysis (known-vuln pinned deps); a no-op if no manifests |
| 4 Validate | `stages/validate.run` | `findings/`, `repo/`, `scope.json`, **`ground_truth.json`** | `validated_findings.json` — a **cross-focus semantic dedup** then a deterministic **citation-grounding** pass run first (below), then findings are **batched** (`validate_batch_size`, default 8) into shared sessions that judge each independently, collapsing the old one-session-per-finding fan-out |
| CORROBORATE | `stages/corroborate.run` | `validated_findings.json` (+ optional `--docs-url`, scope links, repo URL) | `validated_findings.json` rewritten with a per-finding `corroboration` block + a `fixed_upstream` appendix — **opt-out web OSINT** (the 2nd networked stage, with research). Cross-checks each finding against the project's **docs** and the repo's **VCS history** to downgrade documented-by-design findings and exclude already-patched ones. Best-effort; never the live in-scope hosts |
| VERIFY | `stages/deep_verify.run` | `validated_findings.json`, full `repo/` (no excerpt budget) | `validated_findings.json` rewritten with a per-finding `verification` block, plus `split_originals`/`merged_findings` appendices — **opt-in**, offline, one full session per finding (never batched). Independently RE-DERIVES each surviving finding from the actual source and reasons ACROSS the whole survivor set, catching what validate/corroborate's per-finding isolation cannot: a finding that is actually several distinct bugs (`split`), two findings sharing one root cause (`merged`), or a real finding with a wrong factual detail (`corrected`). Best-effort; never touches a live host |
| RUNTIME | `stages/runtime.run` | `validated_findings.json`, `repo/` (+ optional hand-written `runtime_probe_plan.json`) | `runtime_results.json` + per-finding `runtime` verdict — **opt-in**, sandboxed. **R2:** an LLM proposes the probe plan (gated by the loopback/anti-DoS validators) and interprets the observations into confirmed/refuted/inconclusive. No-op unless enabled + Docker + recipe |
| 5 Report | `stages/report.run` | `validated_findings.json` | `REPORT.md`, `submission_drafts/`, ledger rows |

`pipeline` runs 1→5 (SCA between audit and validate, corroborate after validate — both on by
default; verify after corroborate — opt-in, off by default; or 1→2 with `--dry-run`) and **stops
before any submission**.

**Why an "unknown"/uncertain verdict happened, not just that it did.** Both validate and corroborate
are best-effort against session/backend failure: a validate session that dies leaves its findings
`needs_runtime_verification`, and a corroborate session that dies leaves its findings `unknown` —
survivors either way, never silently dropped. But that verdict looks IDENTICAL whether the model
genuinely examined the finding and couldn't tell (a real quality signal) or the session never ran at
all (a session-limit 429, every fallback backend exhausted — a pure tooling gap, not a finding-quality
one). Both stages tag the latter with a specific rationale prefix and split the counts in their final
summary line and in `validated_findings.json`'s `stats` (`survivors_not_actually_validated`,
`unknown_due_to_infra_failure` / `unknown_genuine`), so a reader — or the paper-dataset export — isn't
left guessing which one happened, and knows to just re-run `argo validate`/`argo corroborate <run_id>`
once the session limit resets rather than distrust the audit.

**Design context + impact discipline (cross-cutting).** `rendering.design_context_block` is injected
into every audit prompt (deterministically, via `recon.ensure_design_context_present`, alongside the
prohibited-technique repair) and into the validate + corroborate + verify prompts. It (a) enforces **impact
discipline** — report *proven* impact, not reflexive escalation (no asserting IMDS/cloud-metadata
reachability for an SSRF without evidence; "an admin can do an admin thing" is by design) — and (b),
when `--accepted-risks` supplied `scope.accepted_risks`, lists the vendor's intended behaviors so
they are not raised as bugs. It also enforces **severity symmetry** — a finding that defeats a
security mechanism the project itself ships (auth/MAC/crypto/security-RNG/replay/access-control) is
rated by the property it breaks, not downgraded to "informational hardening" — **qualified by three
by-design priors** learned from real vendor replies: (a) a defect in a *deprecated / legacy / vestigial*
mechanism is a low-value hardening note, not a vuln; (b) *purpose-is-the-feature* — a component whose
documented purpose IS the flagged behavior (a memory peek/poke primitive, an eval surface behind an
intended privilege) is by design; (c) on *trusted-bus / embedded* threat models the absence of
authentication on management functions is typically by design, so lead with memory-safety/stability.
Corroborate additionally mines the issue tracker for prior "by design / wontfix" verdicts. This suppresses the two
hardest false-positive modes at the source, complementing corroborate (which catches the
documented/already-fixed cases after the fact).

**Deep verify: why a separate stage from validate.** Validate is adversarial but structurally
*isolates* each finding — its prompt explicitly forbids one finding's verdict from influencing
another's, so it can never notice that finding A and finding B are the same bug reached two ways,
or that finding C is quietly bundling two independently-triggerable bugs under one description.
It's also batched and excerpt-budgeted (`validate_batch_size`, `excerpt_context_lines`/
`excerpt_max_bytes`) for throughput across every raw candidate. Deep-verify inverts every one of
those trade-offs on purpose: it runs on the much smaller SURVIVING set (already thinned by
validate + corroborate), one full agentic session per finding with no excerpt budget (the model
opens the real file, follows calls into siblings, reads a comparable known-correct path), and is
handed a compact summary of every OTHER surviving finding so it can reason across the set. Its
verdict space also has a middle ground validate's binary confirmed/refuted lacks: `corrected` (the
mechanism is real, a stated fact was wrong — folded in via `verification.corrections`, finding
kept), `split` (one finding replaced by N independently-verified children, original kept in the
`split_originals` appendix), and `merged` (folded into a sibling finding by root cause, kept in the
`merged_findings` appendix) — downgrade-don't-delete applies here too: only `refuted` removes a
finding outright, into the normal `dropped` list. See `argo/prompts/09_deep_verify_prompt.md`.

**Mandatory coverage checklist (cross-cutting, recall).** `checklists.ensure_coverage_checklist_present`
is injected right after the design-context block into every audit prompt. Gated on `detect_native` /
`detect_crypto` / `detect_free_then_reparse` over the repo, it guarantees a variant-family census
(always), memory-safety (native) or panic/abort census (memory-safe), secrets-in-sinks + SSRF lenses,
resource-exhaustion (always), a substitute-then-parse dual census (always), an **insecure-defaults /
fail-open** lens (always — a configured-but-failed auth/policy component that silently falls back to
permissive, or a default-open control API / metrics / pprof), and crypto-primitive (crypto present)
sweep plus the one-finding-per-root-cause rule — so those lenses can't be dropped by the recon model's
focus choices. The native memory-safety lens additionally calls out the **free-then-reparse /
free-then-reuse-without-nulling** double-free idiom (`free(obj->field)` then `parse_into(&obj->field)`
where the re-parse can fail and leave a stale freed pointer); when a deterministic pre-scan
(`detect_free_then_reparse` — a `free(x)` shortly followed by `&x` with no intervening `x = NULL`)
actually hits in the target, that idiom is escalated to a HIGH-SIGNAL callout so the auditor can't skim
past it. See [prompt-synthesis.md](prompt-synthesis.md).

**Variant census worksheet (cross-file recall).** `census.ensure_variant_census_present` is injected
right after the coverage checklist. The checklist's variant-census lens is open-ended ("enumerate every
sibling"), and an open-ended instruction is exactly what a model under-executes — the #1 recall miss
across the libcsp / halloy / ds4 cross-checks was reporting one member of an enumerable class and moving
on. This module turns it into a **closed-ended worksheet**: a deterministic pre-scan (`census.scan_families`)
enumerates the concrete extent of a few cheaply-detectable defect families — native `free`/copy/alloc
sinks and memory-safe panic/abort points — and bakes the site count + file list of each into the prompt,
so the auditor clears an enumerated checklist ("N `free()` sites across these 7 files; you reported 1 —
account for the rest") instead of rediscovering the family's spread. Self-gating by what's in the tree
(native families only on native files, panic only on `.rs`/`.go`), emitted only for families with ≥2
members, and file-list-capped so a large tree can't bloat the prompt.

## Precision + depth uplift (ground-truth recon → enumerate → downgrade-don't-delete)

The single biggest quality lever is **how much ground truth recon bakes into the audit prompts**.
Recon (`stages/recon.py`, `prompts/00_recon_synthesis_meta_prompt.md`) now performs a deep
ground-truth extraction (METHOD step 8) and emits, per focus, into both the audit prompt prose and
`ground_truth.json`:

- **Invariants** — `location → expected → how-to-check` triples (a PASS/FAIL checklist).
- **Baseline-correct references** — the one place a systemic pattern is done right; every sibling is
  diffed against it (the most precise variant technique).
- **Variant families** — the concrete, enumerated member list of each repeated shape
  (controller-per-operation, converter-per-type…), so the audit verifies *each*, not just the first.
- **False-positive carve-outs** — target-specific "do not flag" rules (with justifications), which
  are **also handed to the validator** so it stops re-deriving and wrongly refuting real findings.

The audit template (`prompts/01_audit_prompt_template.md.j2`) carries these as required sections and
mandates a `VARIANT_HUNT_LOG` (one row per family member, verdict 🟢/🟡/🔴) — a coverage
forcing-function. A **completeness-critic** re-pass (`audit._run_critic_for_focus`,
`--critic-passes`, default 1) then re-audits each focus for what was missed, looping until a pass
adds nothing new. Validate (`stages/validate.py`, `prompts/02_adversarial_validation_prompt.md`)
switches from binary confirm/refute to **downgrade-don't-delete**: `refuted` is reserved for findings
**provably contradicted by code** (or matching a carve-out); anything merely uncertain is **kept** as
`needs_runtime_verification` with a concrete question. Drift-repaired audit findings (see below) and
SCA findings bypass adversarial refutation and are kept for human review.

**Cross-focus semantic dedup** (`validate._semantic_dedup`) runs right after the structural
`_merge()` and before the (much more expensive) adversarial fan-out. Structural dedup only collapses
EXACT `(file, line, cwe)` matches, so the same root-cause bug independently reported by two different
audit foci at two different call sites survives as two separate findings — seen in practice on a real
run, where one "unvalidated config value reaches a division with no zero-guard" bug was reported
**three times** by three different foci, each citing a different exact line. One extra cheap batched
session (`prompts/02c_semantic_dedup_prompt.md`, summaries only — id/title/CWE/affected, no source
excerpts) asks the model to cluster findings that describe the same underlying bug from different
angles, conservatively (a missed duplicate just costs a little extra validation later; a wrong merge
silently drops a real, distinct finding). Gated on `semantic_dedup_min_findings` (default 6 — skip the
extra session for a small finding set) and `semantic_dedup_enabled` (default on); fails open (keeps
every finding separate) on any session failure or malformed output. Folded-away duplicates are
recorded in `validated_findings.json`'s `dropped` list with `reason: "duplicate_of:<primary_id>
(semantic dedup)"`, never silently deleted.

**Citation grounding** (`validate._ground_citations`, `argo/grounding.py`) runs immediately after
semantic dedup and before the adversarial fan-out — a **deterministic, zero-LLM** check that a
finding's cited code actually exists in *this* repo. Motivated by a real precision miss: a ds4 report
draft carried a `gguf_get_tensor` / `general.alignment=0` divide-by-zero that belongs to the SEPARATE
`gguf-tools` repo (`gguf_get_tensor` exists nowhere in the ds4 tree) — nothing verified the citation
before spending a validation session on it. One cheap repo pass builds a `RepoIndex` of every basename
and every project-specific symbol any finding cites (a call `foo_bar(` or a backticked `` `foo_bar` ``,
filtered to underscore/interior-capital identifiers ≥ 6 chars so stdlib calls like `read`/`len` are
never mistaken for hallucinations). Then, per finding: if the **primary `affected` file** exists
nowhere in the repo (a hallucinated location), it is **dropped** pre-validation (`reason:
"ungrounded_citation ..."`) — the one unambiguous auto-drop; if a cited **symbol** is absent, the
finding is **kept** but its confidence is downgraded one notch and a `grounding` block + a prominent
`!!! CITATION GROUNDING WARNING !!!` are surfaced in the validator's excerpts, so the adversarial pass
makes the final call with the evidence in hand. Conservative throughout: a symbol the index was not
built to search is given the benefit of the doubt, and the whole pass fails open (every finding kept)
on any error. Stats land in `validated_findings.json` (`grounding_dropped`, `after_grounding`).

## The `AgentRunner` abstraction

Every LLM call goes through one interface, so guardrails and cost logging cannot be bypassed
(BUILD_SPEC: "make the runner an interface so it can be swapped"). The abstract base is
`AgentRunner`; `ClaudeRunner` is kept as a backward-compatible alias.

```python
class AgentRunner(ABC):
    def run(self, *, prompt, run_dir, work_dir, model, stage, run_id,
            repo_dir=None, allowed_tools=ARTIFACT_TOOLS, label=None) -> LLMResult: ...
```

`run()` is the single chokepoint. It:
1. sanitizes the tool allowlist (`guardrails.enforce_session_tools`) and asserts no network tool,
2. computes the per-session budget and delegates to `_invoke()`,
3. **strictly parses** the result envelope (`parse_result_envelope`),
4. logs the call to the ledger + `llm_log.jsonl` (always, even on error),
5. surfaces API errors loudly and enforces per-session caps.

Concrete backends (all subclasses of `AgentRunner`, dispatched by `build_runner`):
- **`HeadlessClaudeRunner`** — shells out to `claude -p --output-format json` (Claude Code). See
  [headless-runner.md](headless-runner.md).
- **`CodexRunner`** — shells out to the Codex CLI for OpenAI models or, with `--codex-oss`, a local
  open-source model (Ollama / LM Studio). See [backends.md](backends.md).
- **`MockClaudeRunner`** — writes fixture files into the scratch dir and returns a synthetic
  manifest. Zero tokens; used by the whole test suite.
- **`FallbackRunner`** (resilience, `--fallback codex`) — wraps an ordered chain of the above. When
  the primary backend hits a **retryable** session/rate-limit (429), the same call is transparently
  retried on the next backend (each picking its own per-stage model), so a long Opus run that walls
  on the Claude session limit mid-`validate` self-heals onto Codex instead of degrading. A walled
  backend is disabled for the rest of the run (circuit breaker); a non-retryable error propagates.
  When a session-limit error's detail text carries a human-readable reset time (e.g. "You've hit your
  session limit · resets 12:50am (Europe/Rome)"), `_extract_session_reset_hint` pulls it out into the
  `RunnerError` message and the `llm_log.jsonl` row (`session_limit_reset_hint`) — so a human (or a
  future resume script) can `grep` a run log for exactly when it is safe to retry, instead of hunting
  down and re-reading the raw API error text.
  The chain can mix backends **and accounts** (`_expand_backend`): `--claude-accounts dirA,dirB`
  builds one `HeadlessClaudeRunner` per `CLAUDE_CONFIG_DIR` and `--codex-accounts` one `CodexRunner`
  per `CODEX_HOME` (limits are per-account), so e.g. `Claude-A → Claude-B → Codex-A → Codex-B`. The
  runner injects the per-account env var (`CLAUDE_CONFIG_DIR` / `CODEX_HOME`, normalized) per call.

The real backends launch the CLI through `AgentRunner._exec`, a **cancellable** subprocess: a pump
thread runs `communicate` while the main thread polls `self.cancel_event` (set by the orchestrator
for the run). On Cancel it kills the whole process **tree** (`_kill_tree`: `taskkill /T` on Windows,
`killpg` on POSIX) and raises `RunnerCancelled`, which the orchestrator turns into a cancellation —
so a long audit stops mid-stage, not at the next boundary (C1). Timeouts use the same path.

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

**Recon retry-on-partial (resilience).** A transient cutoff of the recon-synthesis session (the machine
sleeping, a network blip, a model `stop_sequence`) can write `ground_truth.json` + `repo_profile.json`
but not the per-focus `audit_*.md` prompts — which used to abort the whole run with "no audit prompts".
Because the synthesis is read-only and idempotent, `stages/recon.run` now retries it (`_RECON_MAX_ATTEMPTS`)
when the attempt produced no audit prompt, so a lost synthesis recovers automatically instead of needing
a manual finisher.

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

**Drift-repair (no whole-focus loss).** The audit normalizer (`audit._normalize_findings_doc`)
coerces a real model's findings to the schema. A finding that still fails after coercion is no
longer dropped — `audit._repair_finding` backfills the missing required fields, flags it
`schema_repair_failed`, and keeps it for review (only a genuinely unparseable object is dropped).
This prevents an entire focus from vanishing to a formatting mismatch.

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
                triager_accepted, triager_feedback, triager_ts,
                UNIQUE(program_name, dedup_key, run_id))
```

- `llm_calls` powers cost control and the hard per-run `--budget` guard (`run_cost()`).
- `findings_ledger` detects cross-run/cross-program resubmission (`prior_sightings()`), which
  Stage 5 surfaces as a "possible resubmissions" section.
- The `triager_*` columns hold **real-world feedback** (A2): `record_triager_feedback()` ingests
  accept/reject outcomes (sourced from the **Fleece** registry — never stored in the public repo)
  and `accept_rate()` computes the human-precision proxy. `quality.py` pairs it with benchmark
  recall into `quality.json` (`argo quality`, `GET /quality`). Columns are added to pre-existing DBs
  by `Ledger._migrate()` at open. Neither number alone is the result; the pair is.

The connection is opened with `check_same_thread=False` + a write lock, because the audit and
validate stages log from parallel worker threads.

## Remediation & verification (Phase 6, opt-in)

The audit is **detection-only**. A separate, opt-in flow (`argo fix`, `POST /runs/{id}/fixes`)
turns confirmed findings into **proposed patches for a human** — never auto-applied, never
submitted. `fixes.py` runs one model session per confirmed finding (read-only repo, artifact tools)
that describes the change in `FIX.json` — either a **full rewrite** of each affected file
(`new_content`) or, for **large files**, a list of search/replace **`edits`** (each `search` must
match the file exactly once) so the whole file need not be re-emitted. Argo applies the edits and
computes the unified diff **mechanically** (`difflib`), saving it to `runs/<id>/patches/<id>.diff`.
The model never authors hunk headers, which removes the miscounted-`@@` "corrupt patch" failure mode
seen on large, multi-hunk diffs. (A model that still emits a raw `*.diff` is accepted as a legacy
fallback.)

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

**Optional re-audit (A3 — "is the bug actually gone?").** With `--re-audit` (`argo fix`, `argo bench
--fixes`, or `re_audit` on the API/`generate_fixes`), `verify.py` exposes an `on_patched(workspace)`
hook that runs a focused, **unbiased** audit session on the patched copy — scoped to the finding's
affected file(s), and deliberately **not** told which bug to look for. If the re-audit no longer
reports the original vuln class in that file (`fixes.py:_still_present`, matched on normalized CWE +
file, lenient on line), the verdict carries `re_audit.confirmed_fixed`. It is a **probabilistic
signal** (the model could miss the bug for unrelated reasons), so it is reported *alongside* the
build check, never instead of it; the benchmark folds it in as `patch_quality.re_audit_confirmed_rate`.

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
