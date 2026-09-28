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

## 2. The model discovers findings from source directly; static metadata is validation-only

**Decision: Argo does not use a code-property graph (CPG), PDG/CFG, or taint engine to discover
findings. Recon/audit remain LLM-driven over raw source with `Read`/`Grep`/`Glob`. Stage 4 may attach
a bounded, parse-only tree-sitter sidecar as deterministic evidence for an already-existing finding.**
The sidecar is intentionally weaker than a semantic call graph: it reports enclosing symbols,
syntactically present calls, name-matched possible callers, and a local definition/use slice. It
never builds or executes the target, never originates findings, and prompts explicitly prohibit
treating it as proof of reachability, data flow, exploitability, or vulnerability.

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
4. **Complexity & maintenance.** Static analysis is per-language. The implemented sidecar keeps
   that surface deliberately small: parse-only grammars for Python, JavaScript/TypeScript and C#,
   bounded output, no build adapters, no semantic resolution, and fail-open behavior when parsing is
   unavailable. Anything deeper still risks changing Argo from prompt-orchestration glue into a
   static-analysis framework.
5. **Methodological clarity for the study (still decisive).** A graph engine that *discovers*
   findings would confound the contribution: a finding could come from the LLM or the graph. The
   validation-only sidecar avoids that confound because candidate generation is unchanged; its data
   is attached only after a finding already exists, and can be ablated independently. Deep graph
   analysis remains outside the default detection path.

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

**What changed, and what is still deferred.** The lightweight parse-only step is now implemented
narrowly in **validation**, not recon: it enriches already-proposed findings without changing what
the audit discovers. The next decision is empirical — benchmark whether this raises validation
precision/recall enough to justify its dependency and per-language surface. Build-based CPG/Joern
remains deferred and would require measured evidence plus sandboxing because it can require compiling
the target. Any future use for discovery/recon must be evaluated separately because that would change
the methodology and reintroduce the confound described above.

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
