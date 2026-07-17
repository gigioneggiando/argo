# CLI reference

## Invocation

The CLI is a Typer app. Two equivalent ways to run it, on any OS:

```bash
python -m argo.cli <command> [options]      # works from the repo, no install
# or, after `pip install -e .` (declares the entry point in pyproject.toml):
argo <command> [options]
```

Everywhere below, `argo` ≡ `python -m argo.cli`.

## Commands

| Command | Stage(s) | Purpose |
|---|---|---|
| `ingest` | 1 | brief + repo → `scope.json` (+ read-only repo copy) |
| `recon` | 2 | `scope.json` + repo → `repo_profile.json` + custom prompts |
| `run` | 3 | per-focus findings JSON |
| `sca` | SCA | dependency manifests → known-vuln pins as a `dependencies` focus (opt-out; no-op without manifests) |
| `validate` | 4 | dedup + adversarial validation (downgrade-don't-delete) → `validated_findings.json` |
| `corroborate` | CORROBORATE | **opt-out**, networked: cross-check each finding against the project's **docs** + the repo's **VCS history** (commits/releases/advisories) over public web OSINT → downgrade documented-by-design, move already-fixed to a `fixed_upstream` appendix. Rewrites `validated_findings.json`. `--docs-url` to pin docs; never the live hosts |
| `verify` | VERIFY | **opt-in**, offline: independently re-derive each surviving finding from the actual source (full repo access, one full session per finding, no batching, no excerpt budget) and reason across the whole survivor set → `corrected`/`split`/`merged`/`reconfirmed`/`refuted`/`inconclusive`. Rewrites `validated_findings.json`. `--max-findings` to cap cost; see [architecture.md](architecture.md#deep-verify-why-a-separate-stage-from-validate) |
| `runtime` | RUNTIME | **opt-in** sandboxed runtime verification: build the target in an egress-blocked, loopback-only container and probe ONLY the local instance (never live hosts) → `runtime_results.json`. See [runtime-verification-study.md](runtime-verification-study.md) |
| `live` | LIVE | ⚠️ **opt-in, default off, AUTHORIZED USE ONLY.** Bounded **read-only** requests to the program's **in-scope** hosts to confirm findings. Requires `--i-have-authorization`; RoE-gated (automation/safe-harbor/prohibited), in-scope-only (out-of-scope/unknown blocked), capped + audit-logged. Uses a hand-written `runs/<id>/live_probe_plan.json` if present, else (L2) an **offline** LLM generates one from the validated findings (same gates apply) and interprets the results → `live_results.json` + `live_audit_log.jsonl` (+ a `validation.live` block on findings). See [guardrails §2c](guardrails.md#2c-the-opt-in-live-exception-the-live-stage-in-scope-hosts-only) |
| `report` | 5 | `REPORT.md` + DRAFT submissions |
| `pipeline` | 1–5 | the whole chain; **stops before any submission** |
| `fix` | 6 (opt-in) | propose + **verify** a patch per confirmed finding (applies? compiles? no new errors?); never touches the target |
| `bench` | 7 | score a labeled suite — findings precision/recall/F1 by archetype + CWE (+ optional A/B and patch quality) |
| `serve` | — | run the HTTP API + web UI |

There is intentionally **no `submit` command** — submission is a manual human action.

## Per-command inputs

```bash
argo ingest   --repo PATH_OR_URL [--brief BRIEF.txt] [--links LINKS.txt] [--run RUN_ID]
argo recon    --run RUN_ID
argo run      --run RUN_ID
argo sca      --run RUN_ID
argo validate --run RUN_ID
argo report   --run RUN_ID
argo pipeline --repo PATH_OR_URL [--brief BRIEF.txt] [--links LINKS.txt] [--commit SHA] [--dry-run] [--smoke]
argo fix      --run RUN_ID [--no-verify] [--re-audit] [--docker IMAGE] [--build-cmd "CMD"] [--only ID,ID]
argo bench    --suite DIR [--fixes] [--re-audit] [--parallel-cases N] [--ab-audit-model MODEL]
argo feedback [--program P --dedup K --accepted/--rejected [--run R] [--note ...]] | [--import FILE]
argo quality  [--program P] [--runs-dir DIR]
```

- `argo fix --re-audit` — after verifying a patch, re-audit the patched copy and report whether the
  vuln is still detected (`verify.re_audit.confirmed_fixed`; one extra model session per patch).
- `argo bench --parallel-cases N` — run N labeled cases concurrently (corpora at scale);
  `--re-audit` folds the re-audit rate into `patch_quality`.
- **`argo feedback`** (A2) — record real-world triager outcomes for reported findings (feeds the
  accept-rate). Either one finding (`--program`/`--dedup`/`--accepted`|`--rejected`, optional
  `--run`/`--note`) or bulk `--import FILE` (a JSON list of
  `{program_name, dedup_key, accepted, run_id?, feedback?}`). The source of truth is the **Fleece**
  registry; this only ingests it into the local ledger. `--ledger PATH` targets a specific DB.
- **`argo quality`** (A2) — emit `<runs_dir>/quality.json`: the accept-rate (human precision proxy)
  paired with the latest benchmark recall. `--program` scopes to one program.

- `--brief` — program brief text file (paste the whole program page). **Optional**: omit it to audit
  a **local/personal codebase** as a source-only review — Argo synthesizes a minimal scope from
  `--repo` (zero-token ingest, web research auto-off, no live hosts). e.g. `argo pipeline --repo ./my-code`.
- `--repo` — the **codebase to analyze**: a **local folder path** (need not be a git repo; never
  pushed anywhere) **or** a git URL (cloned `--depth 1`).
- `--commit` — pin `--repo` at a **specific git revision** (reproducible / known-CVE checkout): a URL
  is fetched at that SHA, a local git path is checked out at it. Omit for the default head.
- `--links` — a curated reference-links file, one `http(s)` URL per line (`#` comments and blank
  lines ignored). **Additive** to links the model extracts from the brief; the `--repo` URL is
  never allowed into `reference_links`. See `--links` semantics in
  [the root README](../README.md#inputs-how-to-set-up-a-program).
- `--run` — reuse an existing run id (generated automatically if omitted).

## Shared options (all commands)

| Flag | Default | Meaning |
|---|---|---|
| `--runner {headless\|codex\|mock}` | `headless` | `headless` = Claude Code · `codex` = Codex CLI (OpenAI / OSS) · `mock` = zero-token fixtures. See [backends.md](backends.md). |
| `--codex-model MODEL` | — | (runner=codex) model id (e.g. `gpt-5-codex`); **omit to use the Codex CLI default** (recommended) |
| `--codex-oss` | off | (runner=codex) use the open-source provider (`--oss`) |
| `--codex-local-provider {ollama\|lmstudio}` | — | (runner=codex --codex-oss) which local provider |
| `--audit-model MODEL` | — | override only the Stage-3 audit model |
| `--calibration` | off | run audit on Opus (effectively all-Opus) |
| `--budget USD` | none | **HARD** per-run ceiling; aborts remaining sessions once hit |
| `--parallel N` | 3 | max concurrent audit/validate sessions |
| `--runs-dir DIR` | `runs` | root dir for run artifacts |
| `--scenario NAME` | `happy` | mock fixtures scenario (only with `--runner mock`) |
| `--timeout SECONDS` | 1800 | per-session wall-clock cap |
| `--max-turns N` | none | per-session turn tripwire (orchestrator-side; this CLI has no native `--max-turns`) |
| `--session-budget USD` | none | per-session cost cap (mapped to the CLI's native `--max-budget-usd`) |

## `pipeline`-only options

| Flag | Meaning |
|---|---|
| `--research / --no-research` | Stage-0 **web OSINT/threat-intel** before recon (CVEs, advisories, project security history → injected into recon). **On by default.** One of two networked stages (with corroborate); never the live in-scope hosts (see [guardrails.md](guardrails.md#2a-the-one-bounded-exception-the-research-stage-osint-only)). `--no-research` → fully offline. |
| `--sca / --no-sca` | software-composition analysis of dependency manifests (known-vuln pins) between audit and validate. **On by default**; emits a `dependencies` focus. No-op when the repo has no manifests. |
| `--corroborate / --no-corroborate` | after validate, cross-check each finding against the project's **docs** + the repo's **VCS history** (commits/releases/advisories) over public web OSINT → downgrade documented-by-design, exclude already-fixed. **On by default** (networked, best-effort); `--no-corroborate` skips it. Forced off for `--smoke` and brief-less local reviews. |
| `--docs-url URL` | documentation URL to ground corroboration (repeatable). If omitted, the stage web-searches for the project's official docs. |
| `--verify / --no-verify` | after corroborate, independently re-derive each surviving finding from the actual source (full repo access, one full session per finding, no batching, no excerpt budget) and reason across the whole survivor set — catches splits/merges/corrections that per-finding-isolated stages cannot. **Off by default** (offline, but the most expensive annotation stage). |
| `--verify-max-findings N` | (`--verify`) hard cap on how many survivors get a deep-verify session (cost control); omit to deep-verify every survivor. |
| `--accepted-risks FILE` | file of the vendor's **intended / accepted-by-design behaviors** (threat model / known-limitations). Injected into audit + validate + corroborate + verify so those behaviors are not reported as bugs. Additive, never inferred from the brief. Also available on `argo ingest`. |
| `--runtime` (+ `--runtime-image` / `--runtime-run-cmd`) | **opt-in, default off.** Sandboxed runtime verification after validate: builds the target into an egress-blocked, loopback-only container and probes ONLY the local instance to confirm/refute findings. Needs Docker + a launcher recipe + a `runs/<id>/runtime_probe_plan.json`; gracefully skips otherwise. Never touches the program's live hosts. |
| `--critic-passes N` | completeness-critic re-passes per audit focus (the depth lever — re-audits each focus for missed variant-family members / unverified invariants, looping until dry). **Default 1**; `0` disables. |
| `--dry-run` | run ingest + recon, then **stop before any audit**. The prompt-quality feedback loop: inspect the generated prompts (incl. the ground-truth sections) before paying to run them. |
| `--smoke` | de-risked **real** end-to-end check: cheapest models, one audit focus, low budget + short timeout + tight caps. Defaults `--brief`/`--repo` to the bundled fixtures (and forces `--no-research`). See [headless-runner.md](headless-runner.md#the---smoke-run). |

## `fix`-only options (Phase 6 remediation)

| Flag | Meaning |
|---|---|
| `--no-verify` | skip the build/compile + no-new-errors check (just emit the proposed diffs) |
| `--docker IMAGE` | run the verify build inside this Docker image (offline, `--network=none`) |
| `--build-cmd "CMD"` | explicit build/compile command to verify the patch on the isolated copy |
| `--only ID,ID` | only fix these confirmed finding ids (default: all confirmed) |

> Like every CLI command, `fix` defaults to `--runner headless` (**real** model calls cost money).
> Add `--runner mock` for a zero-token dry run. The target repo is never modified — patches go to
> `runs/<id>/patches/` and verification runs on an isolated copy.

## `bench`-only options (Phase 7 evaluation)

| Flag | Meaning |
|---|---|
| `--suite DIR` | suite directory; each `<case>/` has `case.json` + `expected_findings.json` (see [benchmarks/README.md](../benchmarks/README.md)) |
| `--fixes` | also generate + verify Phase-6 patches per case and report the verified rate |
| `--ab-audit-model MODEL` | run the suite a second time with this audit model; report the precision/recall/F1 delta (B − A) |

Scores **precision / recall / F1** (overall + by archetype + by CWE) into
`<runs_dir>/benchmark_report.json`. Use `--runner mock` to exercise the harness for free; headless
measures real quality (and costs money). The bundled `benchmarks/acme-widgets` case is a mock case.

## Examples

```bash
# Zero-token full-glue test (no API calls):
python -m argo.cli pipeline --runner mock \
  --brief tests/fixtures/brief.txt --repo tests/fixtures/repo

# Inspect the generated prompts before spending on audits:
python -m argo.cli pipeline --dry-run --brief brief.md --repo https://github.com/acme/cms

# Real, cheap end-to-end seam check (≈ $1, one focus):
python -m argo.cli pipeline --smoke

# Real run on a high-value target: audit on Opus, hard $20 ceiling, 2 sessions at a time:
python -m argo.cli pipeline --brief brief.md --links links.txt \
  --repo https://github.com/acme/cms --calibration --budget 20 --parallel 2

# Stage by stage (reuse the run id printed by ingest):
python -m argo.cli ingest --brief brief.md --repo https://github.com/acme/cms
python -m argo.cli recon    --run 20260616-...
python -m argo.cli run       --run 20260616-...
python -m argo.cli validate  --run 20260616-...
python -m argo.cli report    --run 20260616-...
```

## Output

Each command prints a small JSON summary to stdout (run id, artifact paths, cost). Progress and
warnings go to **stderr** (`[ingest]`, `[recon]`, `[audit]`, `[validate]`, `[report]`,
`[runner]` prefixes). Every run also writes `runs/<RUN_ID>/llm_log.jsonl` (one line per LLM call).
