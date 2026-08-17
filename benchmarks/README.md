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
| `commit` | *(optional)* pin the repo at this git revision — **required for a reproducible URL case** (without it a URL clones the default head, where the bug may already be fixed). For a URL it is fetched; for a local path the copy is checked out at it |
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
page of the web UI. Since this session, each case's report also carries `cost_usd` and
`latency_ms` (`{total, calls, mean}` — per-LLM-call wall-clock, not just per-stage), rolled up into
`totals.cost_usd_total` / `totals.latency_ms_mean_per_call`.

## Cross-backend comparison and refusal rate

`argo bench` compares **models within one backend** (`--ab-audit-model`). Two further commands
compare **backends themselves** (Claude Code vs Codex vs Gemini — see
[docs/backends.md](../docs/backends.md)):

```bash
# Same corpus, once per backend, comparable model tier -- cost/latency/precision/recall/F1 side by side
argo bench-cross --suite benchmarks/corpora --backends headless,codex,gemini --tier cheap
argo bench-cross --suite benchmarks/corpora --backends headless,codex,gemini --tier top   # real paper numbers -- $$$

# How often each backend's OWN safety classifier false-positives on a legitimate, authorized
# security-audit prompt (refusal_flag_rate), and how often a same-backend neutral-register retry
# recovers it (refusal_recovery_rate). NOT jailbreak-resistance testing -- see
# argo/refusal_probe.py and tests/fixtures/refusal_prompts.json's own notes on that scope boundary.
argo refusal-probe --backends headless,codex,gemini --trials 3 --tier top
```

`--tier cheap` (default, both commands) uses each backend's cheapest tier (Haiku / `o4-mini` /
Flash-Lite) — a full 3-backend sweep costs cents. `--tier top` uses each backend's own top-tier
model (Opus / `gpt-5-codex` / Gemini Pro) for real, publishable numbers — real, non-trivial spend
across three paid APIs; run the `--tier cheap` sweep first to confirm everything's wired up before
spending on `--tier top`. Output: `benchmark_crossbackend_report.json` /
`refusal_probe_report.json` under `<runs_dir>`.

## Suite layout — keep the mock harness offline

`argo bench --suite <dir>` globs the **direct children** `<dir>/*/case.json`, so suites don't nest.
The default `benchmarks/` suite holds **only offline mock cases** (`acme-widgets`, a local fixture
repo) so `argo bench --runner mock --suite benchmarks` never touches the network — note that even on
the mock runner **ingest still clones `repo`** (only the LLM calls are mocked), so a URL case would
hit the network. Real, URL-backed corpora therefore live under a **separate** suite dir,
`benchmarks/corpora/` (not reached by the `benchmarks/*/case.json` glob), run explicitly:

```bash
argo bench --suite benchmarks/corpora            # REAL run over the labeled corpora (costs $)
```

Bundled real cases (`corpus_id: "argo-confirmed-2026"`) — every label is a REAL, independently
verified finding from Argo's own disclosure campaigns (not synthetic/seeded), pinned at the
audited commit, spanning 3 languages and 2 archetypes:

| case | repo | language | CWE | ground truth |
|---|---|---|---|---|
| `gguf-tools-oob` | antirez/gguf-tools | C | CWE-787/125/190 (×6) | several fixed upstream |
| `libcsp-csp-ps-uaf` | libcsp/libcsp | C | CWE-416 (use-after-free) | **fixed** — merged PR libcsp/libcsp#992 |
| `coturn-ipv6-acl-bypass` | coturn/coturn | C | CWE-863 (authz bypass) | maintainer-acknowledged, **CVE-2026-73213** / GHSA-4v97-rxjj-4f99 |
| `bonjour-service-takeover` | watson/bonjour | JavaScript | CWE-345 (spoofing) | runtime-verified, disclosed |
| `jsoup-redirect-header-leak` | jhy/jsoup | Java | CWE-200 (credential leak) | runtime-verified, disclosed |

Each case's single-file/single-line reference was independently re-verified against the real
pinned commit (not just copied from the Fleece registry) before being added here.

## Seeded-bug corpora at scale

The harness already runs an **unlimited** number of cases — `argo bench` globs every
`<case>/case.json` under the suite — so growing a corpus is **adding case dirs**, not code. To add a
real labeled case:

1. Pin a repo at a **vulnerable commit** (set `commit` for a known-CVE checkout) or a **seeded-bug
   fork**, as a local path or a git URL in `repo`.
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
