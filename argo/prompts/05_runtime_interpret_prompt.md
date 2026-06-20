# RUNTIME RESULT INTERPRETATION PROMPT (R2)

> Pipeline stage: **runtime (interpret)**. The findings were probed against a **local sandboxed
> instance**. Judge, from the observed HTTP responses, whether each finding is **confirmed,
> refuted, or inconclusive** at runtime. You judge evidence only — you run nothing.

---

## INJECTED CONTEXT

FINDINGS + THEIR PROBE OBSERVATIONS (status codes + body snippets from the local instance):
```json
{{PROBE_FINDINGS_JSON}}
```

Note: a probe's `expect_met` is a crude string/status match — do not trust it blindly; re-judge
from the actual `status` + `body_snippet`. `booted` indicates whether the app came up at all
(if false, everything is inconclusive — the instance never started).

BOOTED: {{BOOTED}}

---

## WHAT TO DECIDE (per finding)

- **runtime_confirmed** — the responses positively demonstrate the vulnerable behavior (e.g. an
  endpoint that should require auth returned `200` with sensitive data to an anonymous caller).
- **runtime_refuted** — the responses show the issue does NOT occur at runtime (e.g. the endpoint
  returned `401`/`403`/`404`, or the dangerous value was rejected/clamped). A clean negative is a
  real signal — report it; it correctly downgrades a static hypothesis.
- **runtime_inconclusive** — the probe didn't isolate the behavior (wrong route, the app needs an
  authenticated session you couldn't set up, a 500/error masks the answer, or `booted` is false).

Be honest and conservative: a 500 or an unexpected route is **inconclusive**, not confirmed.

## OUTPUT — `runtime_verdicts.json`

```json
{
  "verdicts": [
    {"finding_id": "<id>", "runtime_verdict": "runtime_confirmed | runtime_refuted | runtime_inconclusive",
     "evidence": "<the decisive status/body observation, quoted>", "rationale": "1-2 sentences"}
  ]
}
```
Emit ONLY this file. Include one entry per finding that had probes.
