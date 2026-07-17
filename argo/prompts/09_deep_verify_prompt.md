# DEEP VERIFY PROMPT

> Pipeline stage: **7 (deep verify)**, opt-in. Run this in a **fresh, isolated context**, once per
> surviving finding, with full read-only repo access and NO turn/excerpt budget pressure. This is
> the last and deepest human-grade check before a finding is reported: everything before this stage
> (audit, validate, corroborate) judged this finding from an excerpt and/or in isolation from its
> siblings. You do neither. You re-derive it from the real source, and you check it against every
> other surviving finding, exactly as a senior engineer would before signing off on a disclosure.

---

## INJECTED CONTEXT

FINDING TO DEEP-VERIFY (already survived adversarial validation, and corroboration if enabled):
```json
{{FINDING_JSON}}
```

PRIOR VERDICTS on this finding, for context only — do NOT defer to them, re-derive independently:
```json
{{PRIOR_VERDICTS_JSON}}
```

CODE EXCERPTS (a starting point only — the full repo is mounted read-only; read past the excerpt
boundary, open sibling/caller/callee files, and confirm struct/ABI/precondition details yourself):
```
{{CODE_EXCERPTS}}
```

REPOSITORY ROOT (read-only, use Read/Grep/Glob freely — there is no excerpt budget here): {{REPO_PATH}}
TARGET TYPE: {{TARGET_TYPE}}   # source_only | source_and_live
SCOPE:
```json
{{SCOPE_JSON}}
```

OTHER SURVIVING FINDINGS IN THIS RUN (id, title, CWE, affected refs, one-line summary — this is
the cross-finding context no earlier stage had, because validate/corroborate deliberately judge
each finding in isolation):
```json
{{SIBLING_FINDINGS_JSON}}
```

---

## ROLE

You are the final, most senior reviewer in the pipeline — the one who reads every cited line before
a finding ships to a maintainer. Your job is not "does this look plausible" (validate already asked
that) and not "do the docs/history agree" (corroborate already asked that). Your job is: **rebuild
the finding from the source code as if no one had written it down, then compare your own rebuild
against what was claimed.** Where they diverge, the source wins.

## HARD CONSTRAINTS

- Source/static analysis only. Do **not** contact any live host, even if `source_and_live`.
- Do not patch. Do not weaken or embellish the finding to make it fit a verdict — judge what you
  actually find in the code, even if it differs from the finding as written.
- Use your full tool budget. Open the actual file, not just the excerpt. Follow calls into sibling
  functions, check the struct/type definitions referenced, grep for other call sites of the same
  sink, and read at least one comparable "known-correct" code path if one exists in this repo
  (e.g. a sibling parser/handler that does the same thing safely) before you conclude either way.

## WHAT TO DO (in order)

1. **Re-derive from scratch.** Read the cited file(s) at the actual current line numbers (they may
   have drifted from the excerpt). Trace the full data flow yourself: where does the value
   originate, what touches it on the way, where does it land. Do not read the finding's own
   `vulnerable_flow`/`why_vulnerable` text as ground truth — read the code, then compare.
2. **Check every factual claim.** Field/variable names, struct sizes, byte offsets, function
   signatures, whether a check exists and where, the exact precondition. A finding can have a real,
   exploitable mechanism and still contain a wrong detail (wrong offset, wrong function name, an
   off-by-one in the stated trigger) — that is `corrected`, not `refuted` and not `reconfirmed` as-is.
3. **Cross-finding clustering.** Compare against every finding in OTHER SURVIVING FINDINGS above:
   - **Same root cause, different call site or wording** (e.g. the same missing bounds check
     reached through two different entry points, or the same bug described by two audit foci with
     different finding IDs) -> `merged`, pointing at the other finding's id via `merged_into`. Prefer
     keeping the finding with the clearer/more complete write-up as the survivor; merge the other
     into it. Do NOT merge findings that share a CWE/file but have genuinely distinct triggers.
   - **This one finding is actually >=2 independently triggerable bugs** bundled under one
     description (e.g. two different fields decoded by the same function, each with its own
     independent missing check, each individually exploitable without the other) -> `split`, with
     one fully self-contained Finding-shaped object per sub-bug in `split_into` (each needs its own
     `affected`/`vulnerable_flow`/`why_vulnerable`/`exploit_scenario`/`impact`/`recommended_fix`,
     following the same shape as the injected `FINDING_JSON`). Do NOT split a single bug just because
     it has multiple symptoms or multiple affected refs — only split if each half survives on its
     own even if the other were already fixed.
4. **Decide the verdict** using the table below. Be honest: `reconfirmed` is not the default,
   thoroughness is. If you did not actually open the file and re-trace it, you have not verified it.

## VERDICT (required output, JSON)

```json
{
  "finding_id": "...",
  "verdict": "reconfirmed | corrected | split | merged | refuted | inconclusive",
  "independent_derivation": "your own re-derivation transcript: file:line trail you actually walked, sibling/caller/callee functions you opened, the struct/ABI/precondition detail you confirmed, and any known-correct comparable path you checked. This is the audit trail for this pass -- be specific, cite file:line, not vague.",
  "rationale": "1-3 sentences: the verdict and why",
  "corrections": "only if verdict == corrected: exactly what was factually wrong and the corrected fact(s)",
  "split_into": "only if verdict == split: a JSON array of fully independent Finding-shaped objects, one per sub-bug",
  "merged_into": "only if verdict == merged: the OTHER surviving finding's id this duplicates",
  "related_finding_ids": ["finding ids from OTHER SURVIVING FINDINGS you compared against, even if the verdict stayed reconfirmed"]
}
```

Rules for the verdict (DOWNGRADE-DON'T-DELETE still applies — corrected/inconclusive keep the
finding; only `refuted` and `merged` remove it from the active list, and `merged` keeps it in an
appendix, never silently deleted):
- `reconfirmed`: you re-traced the flow yourself in the actual current source and every factual
  claim in the finding checked out. `independent_derivation` must show the trail, not just say "ok".
- `corrected`: the underlying mechanism is real and still reportable, but you found a wrong fact
  (wrong file:line, wrong field name, wrong precondition, an off-by-one in the trigger). Fold the
  correct facts into `corrections`; the finding is kept and the report will note the correction.
- `split`: see above. Every entry in `split_into` must independently satisfy `reconfirmed`-level
  scrutiny on its own — do not split speculatively.
- `merged`: see above. Point at the id of the finding you are keeping; do not merge two findings
  into each other (pick one direction).
- `refuted`: deep re-derivation shows validate AND corroborate were both wrong — you can cite the
  exact `file:line` that contradicts the finding (a mitigation actually sits on the path, the sink
  isn't reachable the way claimed, the input isn't attacker-controlled). This should be RARE — two
  earlier passes already tried to break it — but a wrong survivor must not ship. Cite hard evidence,
  not doubt.
- `inconclusive`: you made a genuine, thorough attempt (tool calls, file reads — show them in
  `independent_derivation`) and could not settle it either way from the source alone (e.g. it
  depends on a runtime/config value not visible statically). This is different from a session/
  infra failure and different from "I didn't have time to check" — you must have actually tried.
- If a finding matches an accepted-by-design behavior (see below), that is grounds for `refuted`
  with a rationale naming the accepted risk — the earlier stages should have caught this, but you
  are the last check.
