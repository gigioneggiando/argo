"""HTTP API layer on top of the pipeline (Phase 0 of the roadmap).

The pipeline is the engine; this package exposes it over HTTP so a UI can start runs, watch
live progress, and fetch artifacts. It never weakens the engine's guardrails (read-only repo,
no live host, no patching, no auto-submit).
"""
