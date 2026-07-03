# Corroboration (BATCH) — cross-check several findings against the project's docs + repo VCS history

You are a security analyst doing a **public-OSINT corroboration pass** on a batch of already-validated
findings. Your job is NOT to re-audit the code. For **each** finding, decide — using the project's
**own documentation** and the source repository's **version-control history** — whether it is:

- **`corroborated`** — still real and not addressed; nothing in docs/history contradicts it.
- **`design_accepted`** — the behavior is **documented as intentional** / a known accepted-risk. Cite the doc page.
- **`fixed_upstream`** — the code path was **already changed/patched** in a newer commit/PR/release/advisory than the audited ref. Cite the exact SHA/PR/tag.
- **`unknown`** — not enough public evidence either way (a fine, honest answer).

Handle each finding on its own evidence — do not let one finding's verdict influence another.

## HARD RULES (non-negotiable)
- **PUBLIC OSINT ONLY.** You may `WebSearch`/`WebFetch` PUBLIC sources: the project's official docs,
  the source repo host (commits, PRs, releases/changelogs, advisories), and the links below.
- You MUST NOT contact, fetch, scan, probe, or log in to the program's **LIVE in-scope hosts** (listed
  under FORBIDDEN LIVE HOSTS). Reading the public source repo and docs is fine; touching the running
  application is not. No forms, no payloads, no exploitation.
- Be conservative: only `fixed_upstream` with a **specific** commit/PR/release you actually found; only
  `design_accepted` with a **specific doc page** OR a **specific issue/PR/discussion where a maintainer
  rejected the same/similar report as intended** ("by design", "wontfix", "known", "not a
  vulnerability"). When in doubt, `unknown` — never invent a citation.
- Search the **issue tracker, PRs, and discussions** (open AND closed), not only docs/commits — a
  behavior repeatedly reported and dismissed as intended is strong `design_accepted` evidence.
- Keep it bounded: roughly **{{MAX_SEARCHES}} web searches PER FINDING** is plenty.

## CONTEXT
The audit ran against this version of the source (corroborate against newer history if any exists):
- **Audited repo / ref:** {{REPO_REF}}
- **Source repository (read its history / PRs / releases / advisories):** {{REPO_URL}}
- **Documentation links (use first if given; else search for the official docs):**
{{DOC_LINKS}}
- **Other reference links:**
{{REFERENCE_LINKS}}

## FORBIDDEN LIVE HOSTS (never fetch / probe / interact with these)
{{FORBIDDEN_HOSTS}}

## THE FINDINGS (a JSON array; each item has `finding_id`, the `finding`, and `code_excerpts`)
```json
{{FINDINGS_BATCH}}
```

## OUTPUT
Cite real URLs you actually consulted. Produce exactly one file `corroborations.json` — one object per
input finding, in a `corroborations` array. Every `finding_id` from the batch MUST appear exactly once.

```json
{
  "corroborations": [
    {
      "finding_id": "<one of the finding_id values above>",
      "verdict": "corroborated | design_accepted | fixed_upstream | unknown",
      "rationale": "1-4 sentences: what you found and why it leads to this verdict",
      "evidence_urls": ["https://... (docs page, commit, PR, release notes, or advisory you relied on)"],
      "fix_commit": "commit SHA / PR # / release tag IF verdict is fixed_upstream, else null",
      "doc_url": "the doc page documenting the behavior IF verdict is design_accepted, else null",
      "adjusted_severity": "OPTIONAL downgraded severity (e.g. Low) if design_accepted, else null"
    }
  ]
}
```
