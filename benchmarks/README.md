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
| `brief` | path to the program brief (relative to the case dir, then the repo root). **Optional** — omit it for a general/local-audit case (scope is synthesized from the repo, mirroring `argo pipeline --repo …`) |
| `repo` | path or URL of the codebase to audit |
| `archetype` | canonical archetype (used to slice scores) |
| `scenario` | **mock only** — which fixtures scenario this case maps to |
| `expected` | filename of the labels (default `expected_findings.json`) |
| `corpus_id` | *(provenance, optional)* which labeled corpus this case belongs to |
| `cve_ids` | *(provenance, optional)* list of associated CVE ids |
| `seeded_from` | *(provenance, optional)* source `repo@commit` the bug was seeded from |

Provenance fields are surfaced per-case in the report (`cases[].provenance`) so a corpus can be
sliced/traced; they don't affect scoring.

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
argo bench --suite benchmarks --parallel-cases 4    # corpora at scale: run 4 cases concurrently
```

`--parallel-cases N` runs N cases at once (the report stays in case order). It speeds up a large
corpus, but on a **real** runner the cost adds up and each case still fans out its own audit
sessions — keep N modest.

Output: `precision / recall / F1` overall and by **archetype** and **CWE**, written to
`<runs_dir>/benchmark_report.json` (A/B → `benchmark_ab_report.json`) and shown on the **Benchmarks**
page of the web UI.

## Seeded-bug corpora at scale

The harness already runs an **unlimited** number of cases — `argo bench` globs every
`<case>/case.json` under the suite — so growing a corpus is **adding case dirs**, not code. To add a
real labeled case:

1. Pin a repo at a **vulnerable commit** (a known-CVE checkout) or a **seeded-bug fork**, as a local
   path or a git URL in `repo`.
2. Write `expected_findings.json` labels (one per planted/known bug). Add `kind: "safe"` entries for
   spots that must **not** be flagged — they're excluded from recall but catch over-reporting.
3. Record provenance: `corpus_id`, `cve_ids`, `seeded_from` (so results are traceable in the paper).
4. Pin reproducibility by committing the case (and the repo commit hash) under `benchmarks/`.

```json
// benchmarks/<corpus>/<case>/case.json
{ "name": "flask-cve-2024-1234", "repo": "https://github.com/example/app",
  "archetype": "web_api_cms", "corpus_id": "web-cve-2024", "cve_ids": ["CVE-2024-1234"],
  "seeded_from": "example/app@a1b2c3d", "expected": "expected_findings.json" }
```

> The bundled `acme-widgets/` case is a **mock** case (scenario `happy`) so the harness can be
> exercised for free. Real cases run on `--runner headless` (the mock returns fixtures regardless of
> the repo). Pin the repo commit so the corpus is reproducible for the paper.
