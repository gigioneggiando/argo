# 👁️ Argo — LLM-native static vulnerability detection

[![Tests](https://github.com/gigioneggiando/argo/actions/workflows/tests.yml/badge.svg)](https://github.com/gigioneggiando/argo/actions/workflows/tests.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/gigioneggiando/argo)](https://github.com/gigioneggiando/argo/releases)

> *Argus Panoptes, the all-seeing watchman — a hundred eyes on your code.*

🌐 **Live findings:** [gigioneggiando.github.io/argo](https://gigioneggiando.github.io/argo/) · 📖 [Wiki](https://github.com/gigioneggiando/argo/wiki) · 💬 [Discussions](https://github.com/gigioneggiando/argo/discussions) · 📋 [Changelog](CHANGELOG.md)

## Real, disclosed, independently verified

Not a benchmark score — pull requests, published advisories, and a CVE, on real open-source projects.

**31** projects audited and disclosed · **35** public PRs · **65** already resolved · **93% real-world accuracy**\*

| Project | Stars | Severity | Result |
|---|---:|---|---|
| [ds4](https://github.com/antirez/ds4) — antirez, Redis's original author | 21k★ | Critical | Pre-auth double-free, fixed |
| [moquette](https://github.com/moquette-io/moquette) | 2.4k★ | Critical | Authz bypass, [advisory published](https://github.com/moquette-io/moquette/security/advisories/GHSA-5f42-97gr-vfhq) |
| [PocketBase](https://github.com/pocketbase/pocketbase) | 61k★ | High (8.7) | [Advisory published](https://github.com/pocketbase/pocketbase/security/advisories/GHSA-84vh-m24q-wjjx), reporter credited |
| [LiveKit](https://github.com/livekit/livekit) | 20k★ | Critical + High | 13 of 24 findings fixed, credited on their [Security Hall of Fame](https://livekit.com/security/hall-of-fame) |
| [coturn](https://github.com/coturn/coturn) | 14k★ | Medium | Real CVE assigned: [CVE-2026-73213](https://github.com/coturn/coturn/security/advisories/GHSA-4v97-rxjj-4f99) |

**[See every disclosed finding →](https://gigioneggiando.github.io/argo/)**

<sub>\* Measured across the 134 findings that reached an independent maintainer verdict — excludes
findings still in triage, duplicates of already-known issues, and out-of-scope rejections, since
none of those reflect whether the underlying security claim was correct. 124 were confirmed
genuine, 10 were rejected as false positives.</sub>

---

Argo finds security vulnerabilities in **source code** by driving an LLM as the analyst — it reads
the code the way a human auditor would, rather than matching rules against a graph. Point it at any
codebase — a **local folder**, a private repo, or a public one — and it produces a reviewable
vulnerability report. It runs **for free** if you point it at a local model (Ollama, LM Studio)
instead of a paid backend.

**Where it sits.** Argo is an **LLM-native SAST** — a complement and alternative to rule-based
static analyzers (CodeQL, Semgrep): nothing to write (no queries, no rule packs), and it catches
logic/authorization bugs that fixed patterns miss — at the cost of being *probabilistic* rather than
exhaustive (see [design-decisions](docs/design-decisions.md)). It is **static by design** — it never
executes the target (a hard guardrail), so it is *not* a DAST, fuzzer, or symbolic executor.
**Bug-bounty triage is one specialized mode**, not the whole tool — see
[Two modes](#-two-modes-general-audit-and-bug-bounty).

- 🩹 **Finds it, then proves it** — opt-in remediation proposes a patch per finding and **verifies it
  compiles** on an isolated copy; opt-in runtime/live verification and ASan PoC generation back a
  finding with a real, reproducible crash trace or HTTP proof, not just a claim.
- 🛡️ **Built not to lie to you** — a second model tries to *refute* every finding, it's cross-checked
  against the project's own docs and commit history, and one independent session re-derives each
  survivor from source before anything reaches you. Uncertain stays flagged, never silently dropped.
- 🧭 **Reads for intent, not just syntax** — recon extracts the security invariants the code is
  *supposed* to hold before the audit starts, turning the hunt into closed-ended verification
  instead of pattern-guessing that mistakes business logic for a bug.
- 🔎 **Threat-informed** — opt-out web OSINT (CVEs, advisories, history) feeds every audit.
- 🔌 **Multi-backend, including fully free** — Claude Code, Codex, Gemini, or a **local open-source
  model** (Qwen, DeepSeek via Ollama/LM Studio) — same pipeline, your choice of cost.
- 💬 **Interrogation chat** — ask *"why didn't you find X?"* and get a real re-validation, not a
  chatty answer ([worked example](docs/chat-example.md)).
- 🚫 **Detection-only, read-only, never live by default** — guardrails enforced in code, not just
  prompts.

![End-to-end pipeline flow](docs/diagrams/pipeline_flow.svg)

---

## 🕵️ It works like an expert reviewer, not a linter

This is easy to oversell, so here's the honest version: Argo isn't a claim that expert judgment is
unnecessary — every practice below is borrowed from how a careful human security researcher
actually works, and a human still decides what gets reported. What it claims is narrower: it
follows that discipline **consistently, on every run**, so what reaches you has already been
through a first pass of the scrutiny an experienced reviewer would apply, not raw model output.

It works out what the code is *supposed* to do before it looks for what's wrong, classifies the
software and threat-informs itself before writing a single audit prompt, re-audits each area for
what a first read missed, then actively tries to break every finding before it's allowed to
survive. A genuinely uncertain finding says so — kept with a concrete open question attached, never
force-labeled "confirmed" just to look complete. See a
[real, unedited transcript](docs/chat-example.md) of it correcting its own false positive and
admitting a false negative, mid-conversation.

None of this makes Argo infallible — it's a probabilistic tool, and says so throughout these docs
(see [design-decisions.md](docs/design-decisions.md)). See it working on real, unmodified
open-source code, not a curated demo: **[live findings](https://gigioneggiando.github.io/argo/)**.

---

## 🪪 Two modes: general audit and bug bounty

Argo runs in two modes over the **same** multi-stage engine:

| | **General code audit** (default) | **Bug-bounty triage** |
|---|---|---|
| **Input** | a folder or repo — **no brief** | a program brief (`--brief`) + links + repo |
| **Scope** | source-only, synthesized from the code (zero-token ingest) | parsed from the brief (assets, RoE, exclusions) |
| **For** | your own / private / personal code, OSS review, CTFs, research | scoped programs with safe harbor |
| **Extras** | — | submission drafts, scope filtering, cross-run resubmission tracking |

Auditing your own code is the common case: omit `--brief`, point `--repo` at a **local folder**, and
the repo is mounted read-only and never pushed anywhere (a local / OSS model keeps the source
fully on-device; a cloud backend sends it to its API to analyze). Bug-bounty mode adds the
program-specific scaffolding on top.

---

## 🔒 Principles and limits (read this first)

Argo is for **authorized** security review — your own code, bug-bounty programs with safe harbor,
CTFs, or research. Three constraints are enforced in the orchestrator, not left to the prompts:

1. **Never auto-submit.** The pipeline stops at drafts; submission is always a human action.
2. **Never contact live hosts by default**, even for `source_and_live` targets — analysis is static,
   on the source, and live verification steps are emitted as a text plan you run yourself inside the
   program rules (no DoS, no scanning). The **one** opt-in exception is the gated `argo live` stage
   (default **off**, requires `--i-have-authorization`): for **authorized** engagements it makes
   bounded, **in-scope-only**, read-only, capped, audit-logged requests to confirm findings — every
   request scope-locked to a registered in-scope asset (out-of-scope/unknown hosts hard-blocked).
   See [guardrails §2c](docs/guardrails.md#2c-the-opt-in-live-exception-the-live-stage-in-scope-hosts-only).
3. **Read-only repo** in every session: the pipeline never patches anything.

Additionally, prohibited techniques declared in scope (e.g. "no DoS") are propagated into every
generated prompt, and prompt rendering fails if they are missing (re-inserted verbatim if a model
paraphrases them — see [guardrails](docs/guardrails.md)).

---

## 🗂️ Project layout

```
argo/
  cli.py
  models.py            # pydantic models for scope + findings
  runner.py            # AgentRunner interface (Claude headless · Codex · Gemini · mock)
  stages/{ingest,research,recon,audit,sca,second_opinion,validate,corroborate,deep_verify,asan_poc,runtime,live,report}.py
  research.py·fixes.py·verify.py·benchmark.py·chat.py·costs.py·archetype.py
  prompts/             # the assets, version-controlled in git
  ledger.py            # SQLite findings + cost ledger
server/ · webapp/      # HTTP API + no-build web UI
runs/<RUN_ID>/         # scope.json, repo/, repo_profile.json, prompts/, findings/, REPORT.md
```

---

## 📥 Inputs: how to set up a program (bug-bounty mode)

> For a **general code audit** you need none of this — just `argo pipeline --repo ./your-code`
> (see [Two modes](#-two-modes-general-audit-and-bug-bounty)). The inputs below apply to **bug-bounty
> mode**, where a program brief defines the scope and rules.

Per program, three separate things land in three different places.

- **Program description** -> a text file passed with `--brief`. Paste the whole program page
  from the platform (scope, rules, rewards, exclusions, "no DoS").
- **Useful links** (site, docs, security page, advisory history) -> a text file, **one per
  line**, passed with `--links`. These are NOT the code.
- **Code repository** (e.g. the official GitHub) -> **not a link**, it is the codebase to
  analyze, passed with `--repo`.

Mnemonic: if it is something the agent must **read to understand** (site, docs, advisories) ->
`links.txt`. If it is the thing it must **analyze** (the code) -> `--repo`.

Example. Program folder:

`brief.md`
```
ACME CMS — Bug Bounty Program
Scope: app.acme.com, api.acme.com, the acme/acme-cms repository
Out of scope: *.staging.acme.com, third-party plugins
Rules: no DoS / volumetric testing, no social engineering, max 10 req/s on live
Rewards: Critical $$$, High $$, ...
```

`links.txt`
```
https://acme.com
https://docs.acme.com
https://acme.com/security
https://acme.com/security/advisories
```

Run:
```
argo ingest --brief brief.md --links links.txt --repo https://github.com/acme/acme-cms
```

Stage 2 takes the links from scope and injects them at the top of every custom prompt, so the
prompts start out already knowing where to read docs and advisories. Full `scope.json` shape and
every field: [docs/architecture.md](docs/architecture.md).

---

## ⚡ Usage

```
argo pipeline --brief ... --links ... --repo ...               # 1-5, stops before submission
argo pipeline --brief ... --repo ... --verify                  # + deep-verify before reporting
argo pipeline --brief ... --repo ... --verify --asan-poc        # + real ASan crash traces for C/C++ survivors
argo pipeline --brief ... --repo ... --second-opinion 1         # + one independent blind re-audit merged in
argo pipeline --repo ./my-code                                 # 🔐 local/personal review — NO brief, NO URL
```

**Auditing your own / private local code?** Omit `--brief` and point `--repo` at a **local folder**
(it does not need to be a git repo, and is **never pushed anywhere**). Argo synthesizes a minimal
**source-only** scope from the folder and audits it. A **cloud backend** (Claude / Codex / Gemini)
sends the source to that provider's API to analyze it — only a **local / OSS model** (`--codex-oss`)
keeps everything **fully on-device**.

Pick a backend (default `headless` = Claude Code):
```
argo pipeline ... --runner codex                                  # Codex CLI / OpenAI
argo pipeline ... --runner codex --codex-oss --codex-local-provider ollama --codex-model qwen2.5-coder:32b
argo pipeline ... --runner gemini                                 # Gemini CLI / Google
```

Low-cost modes:
```
argo pipeline ... --runner mock   # exercises the whole glue with fixtures, zero tokens
argo pipeline ... --dry-run       # runs ingest+recon, shows generated prompts, then STOPS
```

Every command, every flag, with more examples: **[docs/cli-reference.md](docs/cli-reference.md)**.

---

## 🖥️ Web UI

A no-build web interface (paste the program, point at the repo, watch the argo run live, read the
results, then chat with the analysis) ships in `webapp/` and is served by the API:

```
python -m argo.cli serve --open    # starts + opens http://127.0.0.1:8000
```

It defaults to the free **mock** runner; switch to a real run (with a budget) from the Advanced
panel. See [docs/ui.md](docs/ui.md) and [docs/api.md](docs/api.md).

---

## 🔬 The pipeline, stage by stage

Each stage reads the previous one's output and writes its own — full detail, data flow, and the
`AgentRunner` abstraction in **[docs/architecture.md](docs/architecture.md)**.

| Stage | What it does |
|---|---|
| 0 Research *(opt-out)* | Web OSINT — CVEs, advisories, project history — feeds recon before audit starts. |
| 1 Ingest | Parses the brief into `scope.json`; clones the repo read-only. |
| 2 Recon + synthesis | Classifies the software, extracts security invariants + baseline-correct references, writes custom audit prompts. |
| 3 Audit | Per-prompt agent sessions emit findings; a completeness-critic re-pass catches what a first read missed. |
| SCA *(opt-out)* | Flags dependency-pinned versions with known advisories. |
| Second opinion *(opt-in)* | N independent blind recon+audit passes, merged in before validate. |
| 4 Validate | Dedup, then adversarial validation — a fresh session tries to refute each survivor. Downgrade-don't-delete: only provable contradictions get dropped. |
| Corroborate *(opt-out)* | Cross-checks survivors against the project's own docs and VCS history — catches "already fixed" and "documented by design". |
| Verify *(opt-in, deep)* | One full independent session per survivor re-derives it from source and reasons across the whole set — split / merge / correct. |
| ASan PoC *(opt-in, C/C++)* | Model writes a harness; a **fixed, non-model** step compiles and runs it under AddressSanitizer in an isolated container — a real sanitizer crash trace, not a judgment call. |
| Runtime *(opt-in, sandboxed)* | Builds the target into an egress-blocked container and confirms findings with a real HTTP PoC — never the program's live hosts. |
| 5 Report | `REPORT.md`, sorted by verified severity, plus one DRAFT submission per confirmed finding. |

---

## 🔌 Backends & model strategy

Same pipeline, swappable engine — pick what you have: `--runner headless` (Claude Code) ·
`--runner codex` (Codex CLI → OpenAI, or `--codex-oss --codex-local-provider ollama|lmstudio` for
**local open-source models** like Qwen/DeepSeek, fully free and on-device) · `--runner gemini`
(Gemini CLI → Google, tiered pro/flash/flash-lite per stage like Claude) · `--runner mock` (free
fixtures). Backends and accounts chain transparently on a rate limit or transient failure, so a long
run self-heals instead of stalling. Full model-per-stage defaults, the resilience/fallback design,
and the cross-model study: **[docs/backends.md](docs/backends.md)**.

---

## 💡 Operational tips

- **A run that stops (crash, Ctrl+C, a rate limit) is not lost.** Every stage writes its output
  atomically, so `argo resume RUN_ID` continues from the first unfinished stage. Details:
  [cli-reference.md § Recovering a stopped run](docs/cli-reference.md#recovering-a-stopped-run).
- Keep prompts under git and record which version each run used: you can A/B test them and see
  which produce accepted findings.
- The SQLite ledger avoids re-reporting the same bug across runs/programs and tracks your hit rate.
- The most useful metric to watch is the ratio of validation-confirmed findings to triager-accepted
  findings: if they diverge, tune the validation prompt.
- Always check whether a given program permits automated/AI tooling before running it.

Development setup, the mock-runner-first testing approach, and what the suite covers:
**[docs/testing.md](docs/testing.md)** and **[CONTRIBUTING.md](CONTRIBUTING.md)**.

---

## 📚 Further documentation

This README is the conceptual overview. Deeper, implementation-level docs live in [`docs/`](docs/):

| Doc | What's in it |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Module map, data flow, the `AgentRunner` abstraction, `RunContext`, ledger schema, dedup algorithm |
| [docs/prompt-synthesis.md](docs/prompt-synthesis.md) | The archetype-driven prompt maker (Stage 2), the specificity self-check, reuse from the legacy generator, safe meta-prompt changes |
| [docs/cli-reference.md](docs/cli-reference.md) | Every command and flag, with examples (`--smoke`, `--budget`, caps, `--calibration`, …) |
| [docs/guardrails.md](docs/guardrails.md) | The non-negotiable guardrails and **exactly where each is enforced in code** |
| [docs/determinism-and-guardrails.md](docs/determinism-and-guardrails.md) | **Anti-hallucination**: every deterministic gate and hard physical limit that constrains the LLM — mechanical diffs, ground-truth verification, budget/timeout/request caps, scope-lock asserts, commit-pin reproducibility |
| [docs/design-decisions.md](docs/design-decisions.md) | **Why** Argo is LLM-direct with **no CPG/AST engine**, what it uses instead, when we'd revisit, and threats to validity (paper-facing) |
| [docs/backends.md](docs/backends.md) | **Multi-backend**: run on Claude Code, the Codex CLI (OpenAI), the Gemini CLI (Google), or local/open-source models — the abstraction, per-backend guardrail mapping, cost, cross-model study |
| [docs/headless-runner.md](docs/headless-runner.md) | Real Claude Code integration: flags used, the JSON envelope, caps, error handling, partial recovery, the `--smoke` run |
| [docs/runtime-verification-study.md](docs/runtime-verification-study.md) | The **opt-in, sandboxed runtime verification** design: the loopback-only sealed-container safety model, the propose→validate→execute→interpret flow, and the R1–R4 plan |
| [docs/api.md](docs/api.md) | The HTTP API (`server/`) — backend for the web UI: endpoints, run lifecycle, live status/SSE, artifact whitelist |
| [docs/ui.md](docs/ui.md) | The web UI (`webapp/`) — `python -m argo.cli serve`, the no-build stack, the views |
| [docs/chat-example.md](docs/chat-example.md) | 💬 The interrogation chat — a real worked transcript (grounded explanation, false-positive self-correction, honest false negatives) |
| [docs/roadmap.md](docs/roadmap.md) | Planned UI + advanced features: per-feature analysis, phased build order, todo list |
| [docs/configuration.md](docs/configuration.md) | `PipelineConfig` reference, per-stage models, budgets/caps |
| [docs/testing.md](docs/testing.md) | How to run the suite, what it covers, mock vs. headless |
| [docs/releasing.md](docs/releasing.md) | The versioning convention and how a release is cut |

## 📄 License

Apache License 2.0 — see [LICENSE](LICENSE). Argo is **detection-only** and intended for
**authorized** security testing (bug-bounty programs with safe harbor, your own code, CTFs, or
research). You are responsible for staying within the scope and rules of engagement of any program
you point it at.
