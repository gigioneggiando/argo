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
22.22% recall and 1.40% precision; the `other` slice reached 0% recall. The result is therefore
useful as a regression signal, but it does not support changing Argo's defaults or claiming general
quality improvement. The high false-positive count is itself a quality finding and should guide the
next work on scope, prioritisation, and validation before a larger provider comparison.

## Registry pairing

Fleece's `registry/exports/quality.json` pairs this benchmark's Codex recall/precision with the
human-triaged registry accept rate. For cross-backend reports, use
`python registry/scripts/metrics.py --benchmark <path> --benchmark-backend codex`; the selected
backend is recorded explicitly in the export.
