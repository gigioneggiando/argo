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
  runner.py         AgentRunner interface + HeadlessClaudeRunner · CodexRunner · GeminiRunner ·
                    MockClaudeRunner (+ FallbackRunner chaining any of them)
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
                    (same-backend) + compare_backends (N-way, cross-backend cost/latency/P/R/F1)
  refusal_probe.py  cross-backend refusal-rate probe: how often each backend's own safety
                    classifier false-positives on a legitimate, authorized audit prompt
  stages/
    ingest.py  research.py  recon.py  audit.py  sca.py  second_opinion.py  validate.py
    corroborate.py  deep_verify.py  runtime.py  report.py
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
| SECOND-OPINION | `stages/second_opinion.run` | already-ingested `scope.json` + `repo/` (reused, not re-parsed/re-cloned) | N additional `findings/second-opinion-<N>-*.json`, each from its own fully independent recon+audit pass in an isolated sub-`run_dir` — **opt-in**, offline. Encodes the manual "blind second opinion" methodology (fastjson2, open62541): a fresh recon+audit cycle over the same scope/repo, optionally on a different backend (`second_opinion_backend`), recovers findings the primary pass missed and — via the SAME structural/semantic dedup validate already does — surfaces which findings were independently rediscovered by >1 pass (`Finding.corroborating_passes`) |
| 4 Validate | `stages/validate.run` | `findings/`, `repo/`, `scope.json`, **`ground_truth.json`** | `validated_findings.json` — a **cross-focus semantic dedup** then a deterministic **citation-grounding** pass run first (below), then findings are **batched** (`validate_batch_size`, default 8) into shared sessions that judge each independently, collapsing the old one-session-per-finding fan-out |
| CORROBORATE | `stages/corroborate.run` | `validated_findings.json` (+ optional `--docs-url`, scope links, repo URL) | `validated_findings.json` rewritten with a per-finding `corroboration` block + a `fixed_upstream` appendix — two isolated passes: offline repo-mounted docs/VCS analysis, then **web OSINT with no repo mount or source excerpts** (the 2nd networked stage, with research). Their results are merged to downgrade documented-by-design findings and exclude already-patched ones. Best-effort; never the live in-scope hosts |
| VERIFY | `stages/deep_verify.run` | `validated_findings.json`, full `repo/` (no excerpt budget) | `validated_findings.json` rewritten with a per-finding `verification` block, plus `split_originals`/`merged_findings` appendices — **opt-in**, offline, one full session per finding (never batched). Independently RE-DERIVES each surviving finding from the actual source and reasons ACROSS the whole survivor set, catching what validate/corroborate's per-finding isolation cannot: a finding that is actually several distinct bugs (`split`), two findings sharing one root cause (`merged`), or a real finding with a wrong factual detail (`corrected`). Best-effort; never touches a live host |
| ASAN_POC | `stages/asan_poc.run` | `validated_findings.json`, `repo/` (C/C++ memory-safety survivors only) | `validated_findings.json` rewritten with a per-finding `validation.asan_poc` block (`confirmed`/`not_reproduced`/`crashed_no_sanitizer_output`/`not_attempted`) + `runs/<id>/asan_poc/<finding_id>/{harness.c, NOTES.md, outcome.json}` — **opt-in**, sandboxed, C/C++ only. An offline LLM writes a minimal single-translation-unit harness (`#include`s the real vulnerable source directly); a FIXED, non-model step then compiles it with `clang -fsanitize=address,undefined` and runs it in an egress-blocked container. Best-effort per finding; a clean/failed attempt never refutes the finding. No-op unless enabled + Docker |
| RUNTIME | `stages/runtime.run` | `validated_findings.json`, `repo/` (+ optional hand-written `runtime_probe_plan.json`) | `runtime_results.json` + per-finding `runtime` verdict — **opt-in**, sandboxed. **R2:** an LLM proposes the probe plan (gated by the loopback/anti-DoS validators) and interprets the observations into confirmed/refuted/inconclusive. No-op unless enabled + Docker + recipe |
| 5 Report | `stages/report.run` | `validated_findings.json` | `REPORT.md`, `submission_drafts/`, ledger rows |

`pipeline` runs 1→5 (SCA between audit and validate, corroborate after validate — both on by
default; second-opinion between SCA and validate, verify after corroborate, asan_poc after verify
(C/C++ memory-safety survivors only) — all three opt-in, off by default; or 1→2 with `--dry-run`)
and **stops before any submission**.

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

**Corroborate's own verdict/rationale self-consistency backstop.** The model corroborating a
finding occasionally writes a `rationale` that itself asserts vendor-confirmed/documented intent
while the structured `verdict` it outputs alongside that same rationale still says `corroborated` —
a genuine contradiction between what the model wrote and what it selected, observed in production
(2/27 findings on one target nearly shipped as new vulnerabilities before a human caught the
mismatch by hand). The prompt now explicitly instructs the model to keep verdict and rationale
consistent; a deterministic, high-precision phrase check (`corroborate._reconcile_verdict_with_rationale`)
is a backstop for when that instruction alone isn't enough — it corrects the verdict to
`design_accepted` when the rationale clearly asserts it, and preserves the model's original call in
`corroboration.verdict_overridden_from` so nothing is silently substituted (surfaced in `REPORT.md`
with an explicit "auto-corrected" note for human review).

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

**Deep verify also checks reachability against sibling consumers of the same untrusted input**
(added 2026-07-19, after a live PoC on a real target caught this the hard way: an allocation with no
upfront bound was correctly identified in isolation, but an unrelated earlier pass over the exact
same untrusted bytes — a dependency-scan pre-pass with no upfront allocation of its own — happened
to fail first on the simplest malicious construction and incidentally gated the flagged code out of
reach; the code defect was real, the "tiny input reliably crashes everything" claim was not, for
that construction). Deep-verify's prompt now requires grepping the whole repo for every other reader
of the same field/bytes, checking whether one plausibly runs earlier and could incidentally block
reachability, and downgrading to `corrected` (not silently `reconfirmed`) when it does — the kind of
cross-call-site reasoning validate/corroborate cannot do from an excerpt in isolation.

**Deep verify is resumable by default** (added 2026-08-17, after a real run needed two manual
re-invocations mid-campaign — a backend ran out of credits partway through, and the fallback
backend then hit its own session limit). Each session is expensive enough (no excerpt budget, real
runs have seen 1-4M input tokens / $1-4 per finding) that re-running `argo verify` on the same run
after an interruption must not re-spend on findings that already got a real answer. A finding whose
`verification` is either unset or an infra-failure `inconclusive` (a session crash, no output, a
budget/cap cutoff — see `_is_infra_failure`) is treated as needing a session; anything else (
`reconfirmed`/`corrected`/`split`/`merged`/`refuted`, or a genuine — not infra — `inconclusive`) is
left completely untouched. `--only ID,ID` overrides this to force specific findings regardless of
their state, mirroring `fix --only`.

**ASan PoC generation: why V1 is deliberately narrow.** Across every C/C++ disclosure so far
(nanomq, open62541, coturn) the single most time-consuming manual step has been hand-writing a
minimal AddressSanitizer harness to turn a static finding into a real crash trace — the most
credibility-boosting artifact a report can carry. A fully general version of this (auto-detect and
drive an arbitrary third-party CMake/Autotools/Meson build) is high engineering risk — it would
mostly produce build failures unless heavily engineered per-target. `stages/asan_poc.py` instead
targets only the case that is actually tractable: a **single-translation-unit** harness that
`#include`s the real vulnerable source file(s) directly (never reimplements the function) and
compiles standalone with one flat `clang -fsanitize=address,undefined harness.c -o poc` — the
common shape of a parser/decoder/buffer-handling memory-safety bug, and the shape every hand-written
PoC in this project's own history has actually taken. A finding whose function can't be isolated
this way, isn't C/C++, or has no CWE a sanitizer can observe (`asan_poc._MEMORY_SAFETY_CWES`) is
skipped at zero cost before any session runs. The compile-and-run step is a **fixed, non-model
executor** (same principle as the runtime/live probe runners below): the model only ever writes
source text into `harness.c`/`NOTES.md`; a plain `subprocess` call compiles and runs it inside an
`--network=none` Docker container (reusing `verify._copy_repo` for isolation, the same
cross-stage-shared helper `runtime.py` already relies on), and a plain regex
(`ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer): ...` / `SUMMARY: ...`) reads the result —
never an LLM judgment call. A clean exit does **not** refute the finding (a failed harness attempt
says nothing definitive about the underlying bug); only a genuine sanitizer match yields
`confirmed`. Runs only on findings that already survived the full triage chain (`verify` if
enabled, else `validate`) — spending a harness-authoring session is only worth it on findings
already trusted to be real. The harness-authoring session passes a `neutral_prompt` (the
`10_asan_harness_prompt.neutral.md` companion) into `AgentRunner.run()` like every other
Codex-sensitive stage — found necessary the hard way: a real comparison run against two
already-disclosed findings (nanomq's SCRAM salt overflow, open62541's TPM CTR truncation) hit a
genuine Claude-side safety refusal on the very first attempt (see `runner._CLAUDE_REFUSAL_SIGNATURE`
above) — asking a model to write a harness that deliberately overflows a buffer reads as exactly
the kind of request this stage exists to make routine, so it needed the same recovery path
validate/deep_verify already have, not a new one.

**Second opinion: an LLM audit is one noisy sample, not the answer.** A single recon+audit pass
depends on that session's own sampling — the SAME model over the SAME repo can genuinely find a
different subset of real bugs on a different run, and a single pass has no way to tell "I looked and
there's nothing here" from "I didn't happen to look there." The manual fix used on fastjson2 and
open62541 was a **blind second opinion**: an independent audit pass with no knowledge of the first
pass's findings, ideally on a different backend for real diversity rather than a bare re-roll of the
same model. `stages/second_opinion.py` makes this a pipeline mode instead of a hand-run side quest,
and does it with almost no new matching logic: each pass gets its own isolated `run_dir` (so it's
genuinely blind — it never reads the primary's `findings/`), reuses the primary's already-parsed
`scope.json` and already-fetched `repo/` (no extra LLM call or re-clone to get a second pass
started), then runs recon+audit fresh — sampling variance alone gives different audit foci even on
the identical model/config. Its raw findings are merged into the primary's `findings/` tagged with
a document-level `source_pass`; validate's EXISTING structural (`_merge`, exact `dedup_key` match)
and semantic (`_semantic_dedup`, LLM-clustered near-duplicates) collapsing already does the "is this
the same bug as another pass found" work — the only new code is the bookkeeping that notices when a
collapsed group spans more than one distinct `source_pass` and records it as
`Finding.corroborating_passes`, surfaced in the report as an explicit "independently confirmed by N
blind passes" signal. Deliberately NOT fed into validate/corroborate/verify's own prompts — how many
passes agree is evidence for a human reader, not something the adversarial stages should anchor on.

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
- **`GeminiRunner`** — shells out to the `gemini` CLI (stdin-only prompt delivery, `--skip-trust`,
  `--include-directories`, `--approval-mode yolo`), tiered per stage like Claude. Guardrails map
  onto Gemini's **Policy Engine** (a named-tool denylist, not `--sandbox`, which needs Docker/
  Podman). See [backends.md](backends.md#gemini-specifics-runner--gemini).
- **`MockClaudeRunner`** — writes fixture files into the scratch dir and returns a synthetic
  manifest. Zero tokens; used by the whole test suite.
- **`FallbackRunner`** (resilience, `--fallback codex,gemini`) — wraps an ordered chain of the above. When
  the primary backend hits a **retryable** session/rate-limit (429), the same call is transparently
  retried on the next backend (each picking its own per-stage model), so a long Opus run that walls
  on the Claude session limit mid-`validate` self-heals onto Codex instead of degrading. A walled
  backend is disabled (circuit breaker) until its reset hint elapses; a non-retryable error
  propagates. When a session-limit error's detail text carries a human-readable reset time (e.g.
  "You've hit your session limit · resets 12:50am (Europe/Rome)"), `_extract_session_reset_hint`
  pulls it out into the `RunnerError` message and the `llm_log.jsonl` row
  (`session_limit_reset_hint`) — so a human (or a future resume script) can `grep` a run log for
  exactly when it is safe to retry, instead of hunting down and re-reading the raw API error text.
  The chain can mix backends **and accounts** (`_expand_backend`): `--claude-accounts dirA,dirB`
  builds one `HeadlessClaudeRunner` per `CLAUDE_CONFIG_DIR`, `--codex-accounts` one `CodexRunner`
  per `CODEX_HOME`, and `--gemini-accounts` one `GeminiRunner` per Gemini API key (limits are
  per-account), so e.g. `Claude-A → Claude-B → Codex-A → Codex-B → Gemini-A`. The runner injects the
  per-account env var/key (`CLAUDE_CONFIG_DIR` / `CODEX_HOME` / Gemini API key, normalized) per call.
  `--claude-api-keys`/`--codex-api-keys` are a SEPARATE, key-based chaining mechanism (mirrors
  `--gemini-accounts`' shape) — directory-based `--claude-accounts`/`--codex-accounts` win if both
  are configured for the same backend, avoiding an unrequested Cartesian-product expansion. Codex's
  key-based runners resolve lazily to a bootstrapped `CODEX_HOME` (see
  `runner._ensure_codex_api_key_home`, cached under `~/.argo/codex_homes/<hash>`) rather than an
  env var — Codex is the one backend where a bare API key alone does not authenticate a call.

  **Failure-kind classification and kind-aware backoff.** Every `RunnerError` carries an optional
  `failure_kind` (`"moderation_flagged"`, `"credits_exhausted"`, `"rate_limited"`, `"timeout"`,
  `"unknown_retryable"`, or `None`), set by `_classify_failure_text` matching the actual, confirmed-
  live error text a backend produced — not just its exit code, which is structurally identical for
  very different underlying causes. Concretely, Codex's exit_1/0-token crash signature (no
  `api_error_status`, no last-message file, no stdout) is produced by BOTH an immediate moderation
  flag ("flagged for possible cybersecurity risk...") AND genuine credit exhaustion ("...out of
  credits...") — only the actual stderr text tells them apart. **`moderation_flagged` is not
  Codex-specific**: Claude's own API can refuse a legitimate, authorized request with its own
  safety-classifier wording ("...safeguards flagged this message... can sometimes flag legitimate
  cybersecurity work...", confirmed live on a real `asan_poc` harness-authoring session) — matched
  by a second signature and classified identically, since it's the same category of failure just
  on the other backend. This matters because the right recovery differs by kind:
  - `credits_exhausted` — no amount of waiting fixes an empty account, so the backend is benched for
    a **longer** cooldown (30 minutes) than the generic hint-less default, so the run spends that
    time productively on a different backend instead of re-checking a dead one every few minutes.
  - `moderation_flagged` — reflects operational history that immediate same-classifier retries keep
    flagging even when a spaced-out one-off call with the identical prompt succeeds. Gets its own
    10-minute bench, **and** — the direct fix for that observed pattern — if the *next* chain entry
    is the *same* backend provider as the one that just flagged (e.g. a
    `runner_fallbacks=["codex","codex"]` chain), `FallbackRunner` sleeps `_MODERATION_RETRY_DELAY`
    (90s) before firing that attempt, since an immediate retry does not escape a short-lived
    classifier cooldown. A genuinely different backend (Codex → Claude) shares no such cooldown and
    still fires immediately. The sleep happens **outside** the per-instance lock, so other threads
    sharing the same `FallbackRunner` (validate/corroborate's batched sessions) keep making progress.
  - Anything else retryable with no specific reset hint keeps the original bounded cooldown
    (`_NO_HINT_RETRY_COOLDOWN`, 5 minutes) — permanently benching a backend on one hiccup would
    silently cascade the entire rest of a run onto the fallback, exhausting its own real quota
    instead of giving the walled backend a real second chance.

  A genuine subprocess **timeout** (hang → tree-kill, see below) and Codex's "produced no output at
  all" path are now both explicitly `retryable=True` — previously neither was, so a single hang or
  an immediate moderation flag/credit failure killed the whole run without ever trying a configured
  fallback backend, on exactly the failure shape fallback exists for.

  **Same-backend retry with a neutral-register prompt variant.** `AgentRunner.run()` itself (the
  base class, so it applies to every backend and every fallback-chain configuration — including a
  single backend with no chain at all) accepts an optional `neutral_prompt` alongside `prompt`. On a
  `moderation_flagged` failure it retries **once**, on the **same backend**, with `neutral_prompt` in
  place of `prompt`, after a short `_NEUTRAL_RETRY_DELAY_S` pause — deliberately much shorter than
  `FallbackRunner`'s 90s same-provider cooldown above, since that duration exists because *identical*
  back-to-back retries of the same prompt kept flagging; a differently-worded prompt is a materially
  different input to the classifier, so the same justification doesn't hold at full strength. Internally
  `run()` is a thin wrapper around `_run_attempt()` (the renamed original single-attempt body), so
  both attempts flow through the normal ledger/`llm_log.jsonl` logging independently — the audit
  trail shows the flag and the recovery. A caller that never passes `neutral_prompt` sees
  byte-identical behavior to a plain single attempt; `FallbackRunner` and the orchestrator need no
  changes at all, since they only ever see `run()`'s final outcome. This is the third of three
  independent, non-overlapping resilience layers — prompt variant (this), backend
  (`FallbackRunner`, above), whole stage (orchestrator, below) — each solving a different question
  ("wrong wording?", "wrong provider?", "needs more real time to pass?") with zero interaction risk
  between them.

  Stages build a `neutral_prompt` two different ways, matching how their prompt is built in the
  first place: **static-template stages** (`validate`, `deep_verify`) use `rendering.render_prompt_pair`,
  which renders the normal template plus a hand-authored `<name>.neutral.md` companion file if one
  exists (e.g. `02_adversarial_validation_prompt.neutral.md`) — a one-time authoring cost, zero
  runtime cost, `None` if no companion exists. The **audit stage** has no static per-focus template
  to pair (its prompts are prose the recon-synthesis model writes itself, matching
  `01_audit_prompt_template.md.j2` as a reference — see [prompt-synthesis.md](prompt-synthesis.md)),
  so it instead calls `rendering.neutralize_audit_prompt`: a deterministic, zero-LLM-cost,
  case-preserving word-substitution pass over the already-rendered text (`attacker` → "an untrusted
  caller", `exploit(able)` → "trigger(able)", etc.), which skips the PROHIBITED TECHNIQUES block
  entirely so the scope's verbatim constraints survive, and is re-checked against
  `guardrails.assert_prohibited_present` before use (falling back to no neutral variant, not a
  weakened prompt, if the rewrite ever trips that guardrail).

The real backends launch the CLI through `AgentRunner._exec`, a **cancellable** subprocess: a pump
thread runs `communicate` while the main thread polls `self.cancel_event` (set by the orchestrator
for the run). On Cancel it kills the whole process **tree** (`_kill_tree`: `taskkill /T` on Windows,
`killpg` on POSIX) and raises `RunnerCancelled`, which the orchestrator turns into a cancellation —
so a long audit stops mid-stage, not at the next boundary (C1). Timeouts use the same path.

**Orchestrator-level auto-retry.** A stage exception reaching `_run_stage_sequence`
(`orchestrator.py`) already means every backend `FallbackRunner` had configured just failed (or a
single-backend config's only option did) — so `_run_stage_sequence` gives the failure a little real
time and retries the *exact same stage call* in place, bounded to `_MAX_STAGE_AUTO_RETRIES` (2)
attempts, before giving up. `_auto_retry_wait_seconds` decides per attempt: not retryable, or the
failure's `failure_kind` is `credits_exhausted` (waiting doesn't fix an empty account — see above)
→ don't retry at all; a specific reset hint that's further out than `_AUTO_RETRY_MAX_SLEEP` (10
minutes) → also don't retry (an unattended run must not silently sleep for hours inside the
process) — surface the failure normally instead, same as before this existed, which is where
`cli._run_with_resume_hint`'s "run `argo resume <run_id>`" message takes over. Otherwise: honor the
specific reset hint if there is one (via the same `parse_retry_after` `argo resume --wait` already
uses), or take a short 20-second pause if there isn't. This relies on — and doesn't duplicate —
`FallbackRunner`'s own `_disabled` circuit-breaker bookkeeping, which persists on `ctx.runner`
across the whole run: when the retried stage call re-invokes `ctx.runner.run(...)`, any backend
still on cooldown from the same underlying failure is skipped automatically, same as any other call.
In practice this means many transient failures (a rate limit, a moderation-flag cooldown, a
sandbox flake) now resolve themselves without a human needing to notice the run stopped and run
`argo resume` by hand — that command remains the answer for anything auto-retry gives up on.

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

**Every canonical write is atomic (resilience).** Each stage's canonical output —
`validated_findings.json` in particular, which is read and rewritten in turn by `validate`,
`corroborate`, `verify`, `freshness_check`, `runtime`, and `live` — is written via
`context.atomic_write_json` (temp file + `os.replace`, the same pattern `progress.py` already used
for `status.json`), not a plain `write_text`. A hard kill (Ctrl+C, OOM, a process kill) mid-write
now always leaves the LAST GOOD version on disk rather than a truncated one, so a subsequent `argo
resume` (see below and [cli-reference.md](cli-reference.md#recovering-a-stopped-run)) always has a
valid file to read instead of occasionally inheriting corruption from the exact moment it was
trying to recover from.

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
          input_tokens, output_tokens, cost_usd, num_turns, session_id, stop_reason,
          duration_ms, failure_kind, label)

findings_ledger(id, ts, program_name, run_id, dedup_key, title, verdict, validated_severity,
                triager_accepted, triager_feedback, triager_ts,
                UNIQUE(program_name, dedup_key, run_id))
```

- `duration_ms`/`failure_kind`/`label` (added v0.5.0, via `_MIGRATIONS`) persist per-call
  wall-clock latency and the same failure classification a `RunnerError` already carried
  (`moderation_flagged`, `rate_limited`, ...) — previously only visible inside a raised exception's
  message, never queryable after the fact. This is what `bench-cross`'s latency numbers and
  `refusal-probe`'s `refusal_flag_rate`/`refusal_recovery_rate` are computed from.
- `llm_calls` powers cost control and the hard per-run `--budget` guard (`run_cost()`). A
  second-opinion blind pass (`--second-opinion N`) runs under its own child run_id
  (`f"{run_id}-so{N}"`, its own isolated `run_dir`) but the **same** ledger file — `run_cost()`/
  `run_call_count()` combine a run_id with any `-soN` children by design, so the `--budget` ceiling
  and the reported `cost_usd` reflect the run's TRUE total spend, not just the primary pass's own
  rows. (Found the hard way: before this, a second-opinion pass got a full fresh budget allowance
  independent of what the primary had already spent, since its rows lived under a different run_id.)
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
folds in Phase-6 patch-verified rate; `ab_compare` runs the suite under two configs (same backend,
two audit models) and reports the metric delta. Reports land in `<runs_dir>/benchmark_report.json`
(read-only `GET /benchmark`). The whole harness runs on the mock runner at zero tokens; headless
measures real model quality.

`compare_backends()` / `argo bench-cross` answers a different question: the **same** suite run once
per **backend** (Claude/Codex/Gemini), reporting cost/latency/precision/recall/F1 side by side — an
N-way comparison, not a 2-way delta. `argo/refusal_probe.py` / `argo refusal-probe` measures a
separate axis entirely — how often each backend's own safety classifier false-positives on a
legitimate, authorized security-audit prompt (`refusal_flag_rate`), and how often a same-backend
neutral-register retry recovers it (`refusal_recovery_rate`) — using a small curated,
non-adversarial prompt set (`tests/fixtures/refusal_prompts.json`), deliberately not jailbreak/
adversarial testing. Both land under `<runs_dir>/benchmark_crossbackend_report.json` /
`refusal_probe_report.json`. See [backends.md](backends.md) and
[../benchmarks/README.md](../benchmarks/README.md#cross-backend-comparison-and-refusal-rate).
