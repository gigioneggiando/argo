# Argo in CI: SARIF and a severity gate

Two post-run commands turn a finished run into CI signals. Neither calls a model, executes target
code or touches the network; they only read `runs/<id>/validated_findings.json`.

| Command | Output | Use |
|---|---|---|
| `argo sarif --run ID [--out FILE] [--include-unverified]` | SARIF 2.1.0 (default `runs/<id>/argo.sarif`) | upload to GitHub code scanning; alerts appear on the PR diff |
| `argo gate --run ID [--fail-on High] [--include-unverified]` | JSON summary; **exit 1** if a reportable finding is at or above the threshold | fail the build |

Both count exactly what `REPORT.md` presents as reportable: validation verdict `confirmed`
(`--include-unverified` adds `needs_runtime_verification`), the report's effective severity
(validator-adjusted when present), and never a finding that corroboration marked
`design_accepted` / `fixed_upstream` or that is refuted, conflicted or stale after a context answer.

SARIF details: one rule per CWE (help link to MITRE), `level` error / warning / note for
Critical-High / Medium / Low-Info, a `security-severity` GitHub uses for its own severity
(9.5 / 8.0 / 5.5 / 3.0), and `partialFingerprints.argoDedupKey/v1` from the finding's dedup key so an
alert keeps its identity across runs. Only explicit file citations become locations; symbol-style
citations (`pkg.Class.method()`) stay in the message. The output validates against the official
OASIS SARIF 2.1.0 schema.

Exit codes of `gate`: `0` pass, `1` blocking findings, `2` bad arguments or missing run.

## GitHub Actions example

Example only: it audits the repository's own code with the Claude Code backend, reviews only the PR
diff (`--incremental-base`), caps spend, then uploads SARIF and gates on High. **A real run spends
tokens on every PR**: keep the budget explicit and prefer the cheap profile. Repository source is
sent to the selected model provider.

```yaml
name: argo
on:
  pull_request:
permissions:
  contents: read
  security-events: write          # upload-sarif
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }   # the incremental base must be an ancestor
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - uses: actions/setup-node@v4
        with: { node-version: "22" }
      - run: npm install -g @anthropic-ai/claude-code
      - run: pip install "argo-audit @ git+https://github.com/gigioneggiando/argo@v0.13.0"
      - name: Audit the PR diff
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: >
          argo pipeline --repo . --runner headless --profile cost-saver
          --incremental-base "origin/${{ github.base_ref }}"
          --budget 5 --run "pr-${{ github.event.number }}-${{ github.run_attempt }}" --yes
      - name: SARIF
        if: always()
        run: argo sarif --run "pr-${{ github.event.number }}-${{ github.run_attempt }}" --out argo.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: argo.sarif, category: argo }
      - name: Gate
        run: argo gate --run "pr-${{ github.event.number }}-${{ github.run_attempt }}" --fail-on High
```

Notes:

- `cost-saver` is the CI profile: cheap per-stage models, no web research, no networked
  corroboration. Use `--runner codex` / `gemini` with their own credentials instead of Claude if
  preferred; `mock` gives a zero-token dry wiring test.
- If the pipeline stops before validation (budget, backend limit) there is no
  `validated_findings.json`; `sarif` and `gate` then exit 2, which fails the job visibly instead of
  passing silently. Check the `pipeline` step's own exit status too: a run that stopped after
  validation still gates on what was validated.
- Findings are model claims that passed Argo's validation, not proof. Treat a failing gate as a
  review request, and keep disclosure decisions human.
