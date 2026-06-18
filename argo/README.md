# `argo/` — the orchestrator

Orchestration-only glue around the five reusable prompt assets in `argo/prompts/`. The
security logic lives in the prompts; this package ingests a program, runs the five stages, and
produces a human-review bundle. **It never submits and never touches a live host.**

## Documentation

Full documentation lives in [`../docs/`](../docs/):

- [architecture.md](../docs/architecture.md) — module map, data flow, the `ClaudeRunner`
  interface, `RunContext`, the SQLite ledger, the dedup algorithm
- [cli-reference.md](../docs/cli-reference.md) — every command and flag
- [guardrails.md](../docs/guardrails.md) — the hard guardrails and where each is enforced here
- [headless-runner.md](../docs/headless-runner.md) — how `runner.py` drives the real `claude` CLI
- [configuration.md](../docs/configuration.md) — `config.PipelineConfig`
- [testing.md](../docs/testing.md) — the test suite

The conceptual overview is in the [top-level README](../README.md).

## Quick start

```bash
pip install -r ../requirements.txt
python -m argo.cli pipeline --runner mock \
  --brief ../tests/fixtures/brief.txt --repo ../tests/fixtures/repo   # zero tokens
python -m argo.cli pipeline --smoke                               # ≈ $1, real claude
```
