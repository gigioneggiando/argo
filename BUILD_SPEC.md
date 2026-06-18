# BUILD SPEC — Bug-Bounty Source-Audit Pipeline Orchestrator

You are building the orchestration layer for an authorized bug-bounty security-audit pipeline.
The reusable prompt assets already exist (see "Provided assets"). Your job is the glue that
ingests a program, runs the stages, and produces a reviewable report. **You implement the
orchestration only — you do not write the audit logic; that lives in the prompts.**

## Provided assets (do not regenerate; load them at runtime)
- `00_recon_synthesis_meta_prompt.md` — Stage 2 recon + prompt synthesis.
- `01_audit_prompt_template.md.j2` — Jinja2 skeleton the synthesis stage fills.
- `02_adversarial_validation_prompt.md` — Stage 4 per-finding confutation.
- `scope_schema.json` — structured scope/RoE object.
- `findings_schema.json` — normalized findings output.

## Tech
- Python 3.11+, `jinja2`, `jsonschema`, `pydantic` (models), `typer` or `click` (CLI).
- LLM execution via **Claude Code in headless mode** (`claude -p` / non-interactive) or the
  Claude Agent SDK for programmatic tool/working-dir control. Make the runner an interface so
  it can be swapped.
- No DB needed initially; use a filesystem run directory + a small SQLite "ledger".

## CLI
```
audit ingest   --brief BRIEF.txt --repo PATH_OR_URL  -> writes scope.json (Stage 1)
audit recon    --run RUN_ID                            -> repo_profile.json + custom prompts (Stage 2)
audit run      --run RUN_ID                            -> per-focus findings JSON (Stage 3)
audit validate --run RUN_ID                            -> validated findings (Stage 4)
audit report   --run RUN_ID                            -> merged report + submission drafts (Stage 5)
audit pipeline --brief ... --repo ...                  -> runs 1-5, STOPS before any submission
```

## Stages

**Stage 1 — Ingest.** Parse the program brief into `scope.json` validated against
`scope_schema.json`. Use an LLM call for extraction, then validate. If `automation_allowed`
is false or absent, set a flag that forbids any live interaction for the whole run. Clone/copy
the repo into the run dir read-only.

**Stage 2 — Recon + synthesis.** Render `00_recon_synthesis_meta_prompt.md` with the scope and
repo path; run it via Claude Code with read access to the repo. Persist `repo_profile.json`,
the generated custom audit prompts (each conforming to the template), and `synthesis_notes.md`.

**Stage 3 — Audit.** For each generated prompt, run a separate Claude Code session in an
isolated working dir with **read-only** repo access. Each emits a findings JSON validated
against `findings_schema.json`. Run focuses in parallel if budget allows; cap context per run.

**Stage 4 — Validate.** Merge all findings. Compute `dedup_key = sha1(normalize(primary_file +
primary_line + cwe))` and collapse duplicates (keep highest severity, union the `variants`/
`affected`). For each surviving finding, run `02_adversarial_validation_prompt.md` in a **fresh
context** with the finding + cited code excerpts. Attach the `validation` block. Drop
`out_of_scope` and `refuted`; keep `confirmed` and `needs_runtime_verification`.

**Stage 5 — Report.** Produce a human-review bundle:
- `REPORT.md` — executive summary, findings sorted by validated severity then confidence,
  a "fix first" ordering, and residual unknowns.
- `submission_drafts/` — one markdown draft per confirmed finding, formatted for the target
  platform, **marked DRAFT**.
- Append every finding to the SQLite ledger (program, dedup_key, verdict, date) to avoid
  cross-program/cross-run resubmission and to track hit rate.

## Guardrails (enforce in code, not just prompts)
- **Never auto-submit.** Stage 5 stops at drafts. Submission is a manual human action.
- **Never touch live hosts from any stage.** Even for `source_and_live`, the pipeline is
  source-static-only; live steps exist solely as text plans for a human to run within RoE.
- Propagate `prohibited_techniques` from `scope.json` into every rendered prompt; fail the run
  if a template renders without them.
- Repo is mounted read-only to all LLM sessions; the pipeline never patches.
- Log all LLM calls (prompt hash, model, cost) for cost control on a Max plan.
- Version the prompt assets in git; record which asset versions a run used.

## Repo layout to create
```
pipeline/
  cli.py
  models.py            # pydantic models for scope + findings
  runner.py            # ClaudeRunner interface (headless / SDK impls)
  stages/{ingest,recon,audit,validate,report}.py
  prompts/             # the provided assets, version-controlled
  ledger.py            # SQLite findings ledger
runs/<RUN_ID>/         # scope.json, repo/, repo_profile.json, prompts/, findings/, REPORT.md
```

## Definition of done
A single `audit pipeline --brief b.txt --repo URL` produces a `runs/<id>/REPORT.md` plus
per-finding drafts, with every finding carrying a validation verdict, nothing out-of-scope
surviving, no live interaction performed, and no auto-submission.
