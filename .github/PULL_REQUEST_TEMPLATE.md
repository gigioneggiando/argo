<!--
Thanks for contributing! Keep PRs small and focused on one thing.
See CONTRIBUTING.md for the full workflow.
-->

## What & why

<!-- What does this change, and why? Link any related issue/Discussion (e.g. "Closes #12"). -->

## Type of change

- [ ] Bug fix (Argo itself)
- [ ] New feature
- [ ] Prompt-asset change (`argo/prompts/`)
- [ ] Backend / runner
- [ ] Docs / wiki
- [ ] Tests / benchmark

## Testing

- [ ] `python -m pytest tests/ -q` is green (runs on the mock runner, zero tokens)
- [ ] Added/updated tests for the new behavior
- [ ] Ran `--smoke` (only needed if this touches the runner, its flags, or envelope parsing)
- [ ] For a quality change: attached a `--dry-run` or benchmark before/after diff

## Guardrails

Confirm this change does **not** weaken any non-negotiable guardrail (see `docs/guardrails.md`):

- [ ] Detection-only — no submission path, no `submit` command
- [ ] Repo stays read-only; no mutation tools; nothing writes into `repo/`
- [ ] No live-host contact outside the gated, opt-in `runtime` / `live` stages
- [ ] No network outside the `research` / `corroborate` OSINT stages
- [ ] Prohibited-techniques propagation into rendered prompts is intact
- [ ] This PR touches a guardrail on purpose, and I've explained why above

## Checklist

- [ ] Code matches the surrounding style (typed, thin orchestrator, all LLM calls via `AgentRunner.run()`)
- [ ] Updated the relevant docs (`docs/` and/or the wiki) if behavior changed
