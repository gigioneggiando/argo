"""Bug-Bounty Source-Argo Orchestrator.

Orchestration-only glue around the five reusable prompt assets in ``pipeline/prompts``.
The security logic lives in the prompts; this package ingests a program, runs the five
stages, and produces a human-reviewable report.

Hard guardrails are enforced in code (not just in prompts):
  * never auto-submit (Stage 5 stops at DRAFT bundles),
  * never contact / scan / exercise any live host from any stage,
  * the target repo is mounted read-only to every LLM session,
  * ``prohibited_techniques`` from scope.json are propagated into every rendered prompt
    and the run fails if a prompt renders without them,
  * scope.json / findings JSON are validated against their JSON Schemas,
  * every LLM call is logged (prompt hash, model, token cost).
"""

__version__ = "0.2.0"
