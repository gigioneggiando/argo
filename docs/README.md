# Documentation

Implementation-level documentation for Argo — an **LLM-native static vulnerability detector** for
source code (general code audit by default; bug-bounty triage as one mode). For the **conceptual
overview** (what the pipeline is, why prompt enrichment matters, model strategy, operational tips),
see the [top-level README](../README.md).

## Contents

| Doc | Audience | What's in it |
|---|---|---|
| [architecture.md](architecture.md) | developers | Module map, stage data flow, the `AgentRunner` interface, `RunContext`, the SQLite ledger schema, the dedup algorithm |
| [prompt-synthesis.md](prompt-synthesis.md) | prompt authors | How Stage 2 generates target-specific audit prompts: the archetype-driven meta-prompt, the specificity self-check, reuse from the legacy generator, and how to change the meta-prompt safely |
| [cli-reference.md](cli-reference.md) | operators | Every command and every flag, with worked examples |
| [guardrails.md](guardrails.md) | reviewers / security | The hard guardrails and the exact code location that enforces each (incl. the research-stage OSINT carve-out and the per-backend mapping) |
| [design-decisions.md](design-decisions.md) | reviewers / paper | Why Argo is LLM-direct with **no CPG/AST engine**, what it uses instead, and threats to validity |
| [backends.md](backends.md) | everyone | **Multi-backend**: Claude Code · Codex (OpenAI) · local open-source — the abstraction, per-backend guardrails, cost, cross-model study |
| [chat-example.md](chat-example.md) | everyone | 💬 The interrogation chat — a real worked transcript |
| [headless-runner.md](headless-runner.md) | developers / operators | How the orchestrator drives the real `claude` CLI: flags, the JSON envelope, per-session/per-run caps, error handling, partial recovery, and the `--smoke` validation run |
| [api.md](api.md) | developers / UI | The HTTP API (`server/`): endpoints, run lifecycle, live status/SSE, artifact whitelist — the backend for the web UI |
| [ui.md](ui.md) | everyone | The web UI (`webapp/`): how to run it, the no-build stack, the three views (New run / live Run / History) |
| [configuration.md](configuration.md) | operators | `PipelineConfig` fields, per-stage model assignment, budgets and safety caps |
| [testing.md](testing.md) | developers | Running the suite, coverage map, mock vs. headless, fixtures |
| [runtime-verification-study.md](runtime-verification-study.md) | reviewers / security | The **opt-in, sandboxed runtime verification** design: the loopback-only sealed-container safety model, the propose→validate→execute→interpret flow, provisioning, and the R1–R4 plan |
| [roadmap.md](roadmap.md) | everyone | Planned UI + advanced features: per-feature analysis (feasibility/utility/priority), phased build order, and the todo list |

## Diagrams

- [diagrams/pipeline_flow.svg](diagrams/pipeline_flow.svg) — the end-to-end 5-stage flow
- [diagrams/prompt_enrichment.svg](diagrams/prompt_enrichment.svg) — how Stage 2 turns the
  reusable assets + scope + repo recon into custom audit prompts

## Quick map of the repo

```
README.md                 conceptual overview (entry point)
BUILD_SPEC.md             the spec the orchestrator was built against
00_/01_/02_*.md, *.json   the five reusable prompt assets + JSON Schemas
argo/                 the orchestrator (see architecture.md)
server/                   the HTTP API on top of the pipeline (see api.md)
webapp/                   the no-build web UI (see ui.md)
tests/                    168 tests, zero-token by default (see testing.md)
docs/                     you are here
docs/legacy/              archived reference artifacts (e.g. the original META_PROMPT_generator)
runs/<RUN_ID>/            per-run artifacts (git-ignored)
```
