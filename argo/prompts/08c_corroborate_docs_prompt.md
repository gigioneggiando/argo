# Offline corroboration — repository docs and VCS pass

Work only from the mounted audited repository. You have no network tools. Cross-check this validated
finding against local documentation, README/CHANGELOG files, related source, and locally available
VCS history such as commit messages and diffs.

Return `fixed_upstream` only if local history proves a newer fix, `design_accepted` only if local
documentation or history explicitly establishes intent, `corroborated` when local evidence supports
the finding without contradiction, otherwise `unknown`.

Audited repository/ref: {{REPO_REF}}

Finding:
```json
{{FINDING_JSON}}
```

Relevant audited source excerpts:
```
{{CODE_EXCERPTS}}
```

Write `corroboration_{{FINDING_ID}}.json` with `finding_id`, `verdict`, `rationale`, `evidence_urls`,
`fix_commit`, `doc_url`, and optional `adjusted_severity`.
