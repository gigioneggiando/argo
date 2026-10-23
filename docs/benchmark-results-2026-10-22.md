# Codex cheap-tier benchmark wave (2026-10-22)

This is the first completed repeated wave for the real Argo corpus after the routing/planning
tranche. It is a Codex-only measurement, not a cross-provider comparison: Claude was not
authenticated and Gemini was not included in this wave.

## Reproduction

```powershell
python -m argo.cli bench-cross `
  --suite benchmarks/corpora `
  --backends codex `
  --tier cheap `
  --repeats 3 `
  --parallel-cases 1 `
  --parallel 2 `
  --budget 10 `
  --runs-dir runs/bench-codex-20261021 `
  --codex-accounts C:/Users/gigi/.codex-b,C:/Users/gigi/.codex
```

The matrix contains five pinned, independently verified cases and three trials per case (15 valid
trials). The cheap Codex tier resolves to `gpt-6-luna`; account B was tried before the normal Codex
account. The raw report is kept in the local ignored run directory at
`runs/bench-codex-20261021/benchmark_crossbackend_report.json`.

## Aggregate result

| Metric | Result |
| --- | ---: |
| Valid / invalid trials | 15 / 0 |
| True positives / false positives / false negatives | 20 / 238 / 10 |
| Precision | 7.75% |
| Recall | 66.67% |
| F1 | 13.89% |
| Total model cost | $67.61 |
| Mean cost per trial | $4.51 |
| Median cost per trial | $3.56 |
| Mean latency per LLM call | 327,497 ms |

By archetype, `cli_desktop` reached 100% recall and 23.68% precision, while `library_sdk` reached
22.22% recall and 1.40% precision; the `other` slice reached 0% recall. The result is useful as a
regression signal, but it does not support changing Argo's defaults or claiming general quality
improvement.

### What the 238 unmatched candidates mean

The benchmark harness treats each case's expected labels as exhaustive, so its `FP` count means
"reported but unmatched to this case's labels". It is **not** a maintainer-adjudicated count of
actually false vulnerabilities. A read-only review of the 15 trial artifacts found that those 238
unmatched candidates were retained as active: 177 had a `confirmed` validation verdict and 61 were
marked `needs_runtime_verification`; 167 were `source_supported` and 71 were `hypothesis`. All 238
still had at least one unmet precondition, and 236 had three or more open proof obligations.

This is a genuine review/uncertainty burden, but it does not justify suppressing every unmatched
candidate: some may be conditional or novel findings that the five seeded labels do not cover.
Initial recurring patterns include optional build/platform paths, deployment-dependent
preconditions, hardening claims without a demonstrated security boundary, and overlapping variants
of one root cause. These categories have not been individually adjudicated. The next precision work
should review a bounded sample against source and maintainer outcomes, then add reviewed safe or valid
labels before tuning prompts or filters. Treat 7.75% as **label precision under this corpus's
exhaustiveness assumption**, not real-world accepted-finding precision.

## Registry pairing

Fleece's `registry/exports/quality.json` pairs this benchmark's Codex recall/precision with the
human-triaged registry accept rate. For cross-backend reports, use
`python registry/scripts/metrics.py --benchmark <path> --benchmark-backend codex`; the selected
backend is recorded explicitly in the export.

## Later model-access attempts (not benchmark results)

On 2026-10-23, an Astra attempt failed before ingest with `Daybreak is unavailable for model
gpt-6-astra` and no model spend. This is an access/configuration failure, not evidence about Astra's
quality. A Codex B smoke call using GPT-6 Sol with Daybreak Blue succeeded. Pipeline run
A separate one-off pipeline used the pre-correction model catalog. It is exploratory and excluded
from the aggregate above; it supports no provider-quality or default-model claim.

A separate one-turn Codex B canary later succeeded with `gpt-6-astra` only when the per-call
`-c daybreak=false` override was set, using standard safeguards. Explicit Daybreak requests still
fail through this Codex CLI path. Argo has no per-run Daybreak override yet; this canary was not a
pipeline or benchmark trial, and no persistent account setting was changed.
