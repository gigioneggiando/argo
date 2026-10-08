# Private architecture context and review questions

Argo can use a bounded, connector-neutral JSON context pack when source alone cannot establish the
deployed architecture, intended roles, IAM policy, or a business invariant:

```json
{
  "schema_version": 1,
  "target": "payments-api",
  "architecture_notes": [
    {
      "id": "edge-auth",
      "statement": "The production gateway authenticates every /api route.",
      "provenance": "architecture review AR-17",
      "confidence": "claimed"
    }
  ],
  "roles": [
    {"name": "tenant owner", "trust": "May administer only its own tenant.",
     "provenance": "role catalogue v2"}
  ],
  "services": [],
  "business_invariants": [],
  "iam_facts": [],
  "artifacts": []
}
```

Use it with `argo pipeline --context-pack context.json`. The schema forbids unknown fields, bounds
file and section size, requires provenance for every claim, and rejects common credential/private-key
shapes. Artifact entries are references with optional SHA-256 values; Argo never dereferences or
copies their contents. The normalized pack stays in `runs/<id>/context_pack.json`. Its contents are
added to in-memory offline model prompts, but not to generated audit prompts, reports, drafts,
public corroboration searches, or the artifact API allowlist. Treat the run directory itself as
private.

`--questions` enables a deterministic post-evidence stage. It writes private
`review_questions.json` only for architecture, deployment, policy, role, tenant, or business-context
uncertainties already present in findings/recon; it does not invent questions with another model and
never pauses an unattended run. The report shows IDs and counts only, not question or answer text.

Record a provenance-bearing answer locally:

```console
argo answer-question --run RUN_ID --question rq:0123456789abcdef \
  --answer "The gateway enforces this in every hosted deployment." \
  --provenance "owner reply 2026-10-05"
```

The answer becomes a `claimed` context item and a same-revision F2 target-memory fact. It is not
technical proof. Affected validation blocks are marked `context_revalidation_required`, and their
stale submission drafts are removed when the report is rebuilt. Re-run validation (and then
`argo questions --run RUN_ID`) before relying on those findings again; the queue then marks an
answer `resolved` only after the stale validation marker is gone.
