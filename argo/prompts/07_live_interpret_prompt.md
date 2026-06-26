# LIVE RESULT INTERPRETATION PROMPT (L2)

> Pipeline stage: **live (interpret)**. The findings were probed against the program's **real, live,
> in-scope host(s)** with bounded read-only requests. Judge, from the observed HTTP responses, whether
> each finding is **confirmed, refuted, or inconclusive** on the live target. You judge evidence only
> — you run nothing.

---

## INJECTED CONTEXT

FINDINGS + THEIR LIVE PROBE OBSERVATIONS (status codes + body snippets from the live host):
```json
{{PROBE_FINDINGS_JSON}}
```

Note: a probe's `expect_met` is a crude string/status match — do not trust it blindly; re-judge from
the actual evidence:
- **`control`** (when present) is a baseline run alongside the probe. Confirm a finding on the
  **difference** between the probe and its control — if they behave the same, it is NOT confirmed (e.g.
  both return `200` because everything hits the same login page).
- **`response_headers`** are often the real proof (e.g. `access-control-allow-origin: *` with
  credentials, a missing `set-cookie` HttpOnly/Secure flag, `www-authenticate`, a permissive CSP).
- **`redirect_chain` / `redirect_out_of_scope`**: a redirect to a login/SSO page means the endpoint is
  protected → **inconclusive/refuted**, not confirmed. A live target may also sit behind a WAF/CDN or a
  rate limiter — treat ambiguous responses conservatively.

---

## WHAT TO DECIDE (per finding)

- **live_confirmed** — the responses positively demonstrate the vulnerable behavior on the live host
  (e.g. an endpoint that should require auth returned `200` with sensitive data to an anonymous caller).
- **live_refuted** — the responses show the issue does NOT occur live (e.g. `401`/`403`/`404`, or the
  dangerous value was rejected/clamped). A clean negative is a real signal — report it.
- **live_inconclusive** — the probe didn't isolate the behavior (wrong route, a session was needed, a
  WAF/redirect/`5xx` masks the answer, or the response is ambiguous).

Be honest and conservative: a `5xx`, a redirect to a login page, or a generic WAF block is
**inconclusive**, not confirmed.

## OUTPUT — `live_verdicts.json`

```json
{
  "verdicts": [
    {"finding_id": "<id>", "live_verdict": "live_confirmed | live_refuted | live_inconclusive",
     "evidence": "<the decisive status/body observation, quoted>", "rationale": "1-2 sentences"}
  ]
}
```
Emit ONLY this file. Include one entry per finding that had probes.
