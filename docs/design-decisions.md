# Design decisions & limitations

The deliberate choices that define what Argo *is* — and, just as importantly, what it is **not**.
Written to be citable from a paper's "Design" / "Threats to validity" sections.

## 0. Where Argo sits: LLM-native SAST (the category)

Argo is a **static** vulnerability detector for source code, in the same family as CodeQL and
Semgrep — but where those match **hand-written rules/queries against a code graph**, Argo has an
**LLM read the source semantically**. The trade is explicit: no rules or queries to author, and it
surfaces logic/authorization bugs that fixed patterns miss, but it is **probabilistic** (recall and
precision vary by model and run) rather than deterministic and exhaustive. It is therefore a
**complement** to rule-based SAST, not a drop-in replacement — and a different tool from **dynamic**
analyzers: Argo **never executes the target** (§3), so it is not a DAST, fuzzer, or symbolic
executor (e.g. Mythril for EVM). It can review Solidity or any language *as source*, but it does not
do symbolic execution. Dynamic confirmation is a deliberately-deferred, opt-in, sandboxed future mode
(roadmap Phase 9), kept separate so the default tool stays static-only and safe to point at any repo.

**Bug bounty is one mode, not the identity.** The same engine runs as a general code auditor
(point it at a folder, no brief) or as bug-bounty triage (a program brief adds scope/RoE parsing,
submission drafts, and cross-run resubmission tracking). The detection core is identical.

## 1. Orchestration-only glue; the security logic lives in the prompts

Argo is a sequencer, not an analyzer. It ingests a program, drives five LLM stages
(ingest → recon → audit → validate → report), and produces a reviewable report. It writes **no
audit logic of its own** — the detection knowledge is in the version-pinned prompt assets
(`argo/prompts/`, sha256-recorded per run). This keeps the system small, auditable, and lets the
"intelligence" be improved by editing prompts rather than code.

## 2. The model reads source directly — **no code-property-graph / AST engine** (the key decision)

**Decision: Argo does NOT use tree-sitter AST metadata, a code-property graph (CPG), PDG/CFG, or a
taint engine such as Joern. Code understanding is done by the LLM reading the source semantically,
with `Read`/`Grep`/`Glob`.** This was an explicit choice, not an omission, and it is **gated on
evidence** rather than closed forever.

Why we did *not* add it:

1. **Source code is in-distribution for the model; a serialized CPG/AST is not.** LLMs are pretrained
   overwhelmingly on **source code** (public repositories, issues, reviews, docs), not on serialized
   code-property graphs, AST dumps, or Joern query output — those are a negligible fraction of any
   pretraining corpus. So an LLM reasons most fluently over the representation it was trained on:
   raw source. Feeding it a graph IR means handing it an **out-of-distribution** artifact it would
   largely have to translate back into mental source anyway — adding noise that can *confuse* rather
   than signal that *helps*. This is the most likely reason these models already localize
   vulnerabilities well from source alone, and a principled reason not to bury that signal under an
   unfamiliar IR. (Stated as a training-grounded hypothesis — the benchmark is how we'd test it, not
   assume it.)
2. **Unproven ROI on top of a strong model.** A capable LLM (Opus/Sonnet) reading the source already
   performs cross-file, semantic reasoning that subsumes much of what an AST or call-graph provides.
   We have no evidence yet that it misses flows a graph would catch — adding a graph now is
   speculative complexity.
3. **Guardrail tension (the decisive one for CPG).** Build-based tools (Joern and most CPG builders)
   must **compile the target**, i.e. execute its build scripts. That directly violates Argo's core
   invariant — *no code execution, repository mounted read-only, source-static only*. Honoring it
   would require sandboxing an arbitrary build, a real cost and attack surface for an uncertain gain.
4. **Complexity & maintenance.** A useful static-analysis layer is **per-language** (grammars,
   queries, build adapters). That is a large, ongoing surface that changes Argo's character from
   "prompt-orchestration glue" to "static-analysis framework".
5. **Methodological clarity for the study (the decisive one for the paper).** Bolting a graph engine
   on top **confounds the contribution**: a confirmed finding could come from the LLM *or* from the
   graph, and the two can't be separated post-hoc. Keeping the pipeline **LLM-pure isolates the
   variable under study** — "how well does an LLM-driven, source-static pipeline find real bugs?" —
   which is exactly the claim the paper makes. A graph is a *confound* to that claim, not a free win.

What we use **instead** (cheap, safe, additive — no build, no new runtime):

- **Ground-truth extraction (Stage 2)**: before any hunting starts, recon extracts named security
  invariants (`location → expected property → how to check it`) and the correct baseline-implementation
  pattern to diff variants against. This is the concrete mechanism behind "reads for intent, not just
  syntax" in the README: it turns the audit from open-ended pattern search into **closed-ended
  verification** against the software's actual intended behavior, which is what keeps the model from
  mistaking ordinary business logic for a vulnerability.
- **Per-focus recon split**: Stage 2 partitions the target into focused audit prompts so each audit
  session reasons about a bounded surface (a poor-man's "slice").
- **Vulnerability-class index** (`argo/data/vuln_index.yaml`): archetype → likely CWE classes,
  injected into recon as *additive* reference.
- **Stage-0 web research** (OSINT threat intel: CVEs, advisories, security history) → injected into
  recon so the audit is threat-targeted.
- **Adversarial validation** (Stage 4): a second model tries to *refute* each finding's data flow,
  plus a code-side scope filter — the precision mechanism that a taint engine would otherwise serve.

**When we would revisit this.** The benchmark harness (`argo bench`, Phase 7) measures **recall**
against labeled corpora. If, once enough data is collected, recall losses are **attributable to
missed inter-procedural / multi-file data flows that a graph would recover**, we add the *parse-only*
path first — tree-sitter AST + call-graph as a sidecar `metadata.json` fed to recon (no build, so it
respects "no code execution"). Build-based CPG/Joern would come only after that, and only as a
**data-flow validation aid** (confirm/refute a finding's source→sink path), never as raw context,
and only inside a sandbox. The trigger is **measured evidence, not intuition.**

## 3. Detection-only, read-only, never live (recap)

The pipeline stops at DRAFT bundles — there is no submission code path. The repo is mounted
read-only to every session; mutation tools are always disallowed; the program's live hosts are never
contacted. The one bounded network exception is the opt-out `research` stage (public OSINT only,
never the live in-scope hosts). All of this is **enforced in code**, not just prompted — see
[guardrails.md](guardrails.md) (§2a for the research carve-out).

## 4. Opt-in remediation, kept off the detection path

Fixes (Phase 6) are a separate, opt-in flow that proposes patches as reviewable diffs and **verifies
them on an isolated copy** (applies? compiles? no new errors?) — the target repo is never modified.
Detection and remediation are deliberately decoupled so the audit's read-only guarantee is absolute.

## 5. Threats to validity (for the paper)

- **LLM-centric recall.** Findings are bounded by what the model reasons about across the codebase.
  Mitigations: focused recon split, the vuln-class index, web threat-intel, and adversarial
  validation. We **measure** this directly: benchmark **recall** vs. labeled corpora, paired with the
  registry's real-world **accept rate** (human-judged precision) — see the data pipeline's
  `quality.json`. The two together are the headline result; neither alone is.
- **Model-dependence (and how the multi-backend design turns it into a result).** Quality depends on
  the model. Because Argo is backend-swappable (Claude Code, the Codex CLI / OpenAI, Gemini CLI, or
  local/OSS — see [backends.md](backends.md)) with the *same* prompts, pipeline, and guardrails,
  "model" is the only variable that changes between backends. That makes a **cross-model
  comparison** a clean experiment rather than a confound — and reinforces the no-CPG decision (§2):
  the thing under study is the LLM's source reasoning, isolated. `argo bench-cross` and `argo
  refusal-probe` operationalize this directly (cost/latency/precision/recall/F1 and refusal-rate
  side by side across backends).
- **Non-determinism & cost.** LLM runs vary; we pin prompt-asset sha256 + the analyzed commit per
  run, log every call's cost, and report cost-per-accepted-finding. Reproducibility is "same inputs,
  same config, comparable (not identical) output" — a known property of LLM pipelines.
- **No dynamic confirmation.** Source-static by design: a finding's runtime exploitability is a
  *plan a human runs*, not something the tool verifies. `needs_runtime_verification` is a first-class
  verdict precisely so this gap is explicit in the data, not hidden.
- **Scope honesty.** A code-side scope filter drops out-of-scope findings independently of the LLM
  verdict; conservative ingest defaults (automation/prohibited-techniques) bias toward staying inside
  the authorized envelope.

The honest one-line summary: **Argo is a deliberately lean, LLM-driven, source-static pipeline. Its
power and its limits both come from that choice — and the choice is measured, not assumed.**
