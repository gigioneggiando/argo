# Contributing to Argo

Thanks for taking the time to help. Argo is a personal open-source project, so responses are
best-effort — but contributions, bug reports, and especially **false-positive / false-negative
reports** are genuinely valuable and very welcome.

Before anything else: this project has a [Code of Conduct](CODE_OF_CONDUCT.md) — by participating you
agree to uphold it. Questions and ideas are best raised in
[Discussions](https://github.com/gigioneggiando/argo/discussions); use issues for concrete bugs and
actionable feature requests.

## The most useful things you can contribute

Argo is an LLM-native SAST — its quality is measured by **precision and recall**, not by feature
count. So the highest-leverage contributions are:

- **A false positive** — a finding Argo reported that is wrong, with the file/CWE and a one-line
  reason it's not a real bug. This is the single most useful report for a tool like this.
- **A false negative** — a real bug Argo *missed* on a target you can share (or a synthetic repro).
  Recall is the failure mode that matters most.
- **A labeled benchmark case** — a small repo (or a pinned vulnerable commit) with an
  `expected_findings.json`, so quality changes become measurable rather than anecdotal. See
  [`benchmarks/README.md`](benchmarks/README.md).
- **Prompt-asset improvements** — the security logic lives in `argo/prompts/`, not in the
  orchestrator. A sharper recon meta-prompt or audit template is a real contribution (see the safety
  note below).
- **A backend** — a new `AgentRunner` (model provider) that keeps the guardrails intact.
- **Docs** — the [`docs/`](docs/) tree and the [wiki](https://github.com/gigioneggiando/argo/wiki).

## Development setup

```bash
git clone https://github.com/gigioneggiando/argo.git
cd argo
pip install -r requirements.txt
pip install -e .          # optional: enables the `argo` entry point
```

Run the test suite — it runs **entirely on the mock runner, zero tokens, no API calls**:

```bash
python -m pytest tests/ -q
```

`pytest.ini` pins `--basetemp=.pytest_tmp` so the read-only repo copies the pipeline creates don't
trip Windows' temp rotation. On any OS, `argo` ≡ `python -m argo.cli`.

## The zero-cost dev loop

You almost never need to spend money to develop Argo. Most orchestration bugs live in the glue, not
the model call — debug them for free:

```bash
# Full pipeline end-to-end on deterministic fixtures (zero tokens):
python -m argo.cli pipeline --runner mock --brief tests/fixtures/brief.txt --repo tests/fixtures/repo

# Real ingest + recon, then STOP before any audit — inspect the generated prompts:
python -m argo.cli pipeline --dry-run --brief brief.md --repo <path>
```

Only run a **real** model when you're specifically testing the real backend seam. The cheapest way to
do that is the bundled smoke (~$1, one focus, tight caps):

```bash
python -m argo.cli pipeline --smoke
```

Run `--smoke` after changing anything in the runner, its flags, or the envelope parsing.

## Testing expectations for a PR

- **All existing tests stay green on the mock runner.** No exceptions.
- **New behavior ships with a test.** The suite is the contract — schema conformance at stage
  boundaries, dedup/validation filtering, the golden `REPORT.md`, guardrail enforcement.
- **Exercise failure paths, not just the happy path.** The mock fixtures deliberately cover an
  out-of-scope finding (scope filter), a duplicate (dedup), a refuted finding (drop), a missing
  manifest (glob fallback), a session that died mid-write (partial recovery), and an oversized
  findings file (no truncation). New features should extend that discipline. See
  [`docs/testing.md`](docs/testing.md).

## The guardrails are non-negotiable

A PR that weakens any of these will not be merged — they are enforced in **code and tests**, not just
prompts (see [`docs/guardrails.md`](docs/guardrails.md) and `tests/test_guardrails.py`):

1. **Detection-only.** No submission code path, no `submit` command; the pipeline stops at drafts.
2. **Read-only repo.** Every session gets the repo read-only; mutation tools are always disallowed;
   nothing ever writes into `repo/`.
3. **No live host by default.** Every default-pipeline stage is offline against the program's hosts.
   The only exceptions are the opt-in, gated `runtime` (loopback-only, egress-blocked) and `live`
   (authorized, in-scope-only, capped, audit-logged) stages — and they stay behind their gates.
4. **No network except the two OSINT stages** (`research`, `corroborate`), which get web search/fetch
   but no repo access, and never the program's live hosts.
5. **Prohibited techniques** from the scope (e.g. "no DoS") are propagated into every rendered
   prompt; rendering fails if any is missing.

If a change *needs* to touch a guardrail, open a Discussion first so we can talk through the design.

## Changing prompt assets safely

The prompts (`argo/prompts/`) are version-pinned (sha256 recorded per run), and the Stage-2 output is
already near-professional on the Opus path — so the main risk of any prompt edit is **regression**.
Validate every meta-prompt change against a baseline before trusting it:

1. Keep a known-good run as the baseline.
2. Re-sync your edited asset into `argo/prompts/` (the pipeline loads it from there).
3. Run `pipeline --dry-run` on the same target (ingest + recon only — a few dollars of recon, no
   audit spend) and **diff** the new `repo_profile.json` / `prompts/audit_*.md` / `synthesis_notes.md`
   against the baseline.
4. Keep the change only if quality holds or improves. See
   [`docs/prompt-synthesis.md`](docs/prompt-synthesis.md#changing-the-meta-prompt-safely-validation-methodology).

Two Opus recon runs on the same repo differ (model nondeterminism), so judge by **structural** signals
(archetype classified, split fit, file:line citation density), not exact per-term coverage.

## Code style & conventions

- **Match the surrounding code** — its naming, typing, comment density, and idioms. The codebase uses
  type hints throughout; keep new code typed.
- **Keep the orchestrator thin.** Argo is glue around prompt assets; security logic belongs in the
  prompts, not in Python. New audit heuristics usually mean a prompt change, not a code change.
- **Every LLM call goes through `AgentRunner.run()`** — the one chokepoint where guardrails and cost
  logging are enforced. Don't add a second path around it.
- The module map in [`docs/architecture.md`](docs/architecture.md) shows where things live.

## Submitting a change

1. **Fork** and branch from `main`; keep each PR small and focused on one thing.
2. Make sure `python -m pytest tests/ -q` is green.
3. Open a PR that says **what** changed and **why** (link any related issue/Discussion). If it changes
   findings quality, include before/after from a `--dry-run` or benchmark diff.
4. For anything touching backends, the runner, or flags, mention whether you ran `--smoke`.

Small, well-scoped PRs get reviewed faster than large ones.

## Reporting a security issue

Please **don't** open a public issue for a vulnerability in Argo itself — follow
[`SECURITY.md`](SECURITY.md) (private email or a GitHub security advisory) instead.

Note the distinction: a vulnerability Argo *produces* about some third-party target is **not** an Argo
security issue — disclose it to that project through its own process.

## License

By contributing, you agree that your contributions are licensed under the project's
[Apache License 2.0](LICENSE).
