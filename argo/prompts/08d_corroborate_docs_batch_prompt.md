# Offline corroboration — repository docs and VCS batch pass

Work only from the mounted audited repository. You have no network tools. For every finding, inspect
local documentation, README/CHANGELOG files, related source, and locally available VCS history.
Return `fixed_upstream` only when local history proves a newer fix, `design_accepted` only when local
evidence explicitly establishes intent, `corroborated` when local evidence supports the finding
without contradiction, otherwise `unknown`.

Audited repository/ref: {{REPO_REF}}

Findings and audited excerpts:
```json
{{FINDINGS_BATCH}}
```

Write `corroborations.json` as `{ "corroborations": [...] }`, with exactly one row per `finding_id`.
