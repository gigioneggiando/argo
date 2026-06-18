# Benchmarks (Phase 7)

A **suite** is a folder of labeled cases. Each case is a directory with:

```
<case>/
  case.json                 # name, brief, repo, archetype, (optional) scenario
  expected_findings.json    # the ground-truth labels
```

`case.json`:

| field | meaning |
|---|---|
| `name` | case label |
| `brief` | path to the program brief (relative to the case dir, then the repo root) |
| `repo` | path or URL of the codebase to audit |
| `archetype` | canonical archetype (used to slice scores) |
| `scenario` | **mock only** — which fixtures scenario this case maps to |
| `expected` | filename of the labels (default `expected_findings.json`) |

`expected_findings.json` is a list of labels:

```json
{ "label": "SQLi in search", "cwe": "CWE-89", "file": "src/api/search.py",
  "line": 42, "line_tolerance": 25, "aliases": ["CWE-943"], "severity": "High" }
```

A reported finding **matches** a label when the normalized CWE agrees (or is in `aliases`) and the
file matches (path-suffix), optionally within `line_tolerance`. Labels are treated as exhaustive:
an unmatched reported finding is a **false positive**, an unmatched label a **false negative**.

## Run it

```bash
argo bench --suite benchmarks --runner mock        # zero-token: scores the fixtures harness
argo bench --suite benchmarks                       # REAL run — measures model quality (costs $)
argo bench --suite benchmarks --fixes               # also score Phase-6 patch quality
argo bench --suite benchmarks --ab-audit-model claude-opus-4-8   # A/B vs the default audit model
```

Output: `precision / recall / F1` overall and by **archetype** and **CWE**, written to
`<runs_dir>/benchmark_report.json` (A/B → `benchmark_ab_report.json`) and shown on the **Benchmarks**
page of the web UI.

> The bundled `acme-widgets/` case is a **mock** case (scenario `happy`) so the harness can be
> exercised for free. Add real labeled repos (known-CVE checkouts, seeded-bug forks) as new case
> dirs to measure real quality.
