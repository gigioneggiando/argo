# LIVE PROBE-PLAN PROPOSAL PROMPT (L2) — ⚠️ authorized live testing

> Pipeline stage: **live (propose)**. You design **safe HTTP probes** that confirm or refute the
> findings below against the program's **real, live, IN-SCOPE host(s)**. This is authorized live
> testing for a bug-bounty engagement whose rules permit it. You do NOT run anything — you only emit
> a probe plan. A deterministic validator gates your plan (in-scope-only, read-only, capped) and a
> fixed runner executes it. Stay strictly inside the authorized envelope.

---

## INJECTED CONTEXT

PROGRAM: {{PROGRAM_NAME}}
REPOSITORY ROOT (read-only — use it to find the EXACT routes/paths): {{REPO_PATH}}

IN-SCOPE HOSTS — the ONLY hosts you may target. Every request URL must be an absolute `https://`
(or `http://`) URL whose host is one of these:
{{IN_SCOPE_HOSTS}}

OUT-OF-SCOPE (never touch — these are hard-blocked):
{{OUT_OF_SCOPE}}

PROHIBITED TECHNIQUES (hard limits — never exceed):
{{PROHIBITED_TECHNIQUES}}

FINDINGS TO PROBE (confirm/refute each where an HTTP signal is observable):
```json
{{FINDINGS_JSON}}
```

---

## HARD CONSTRAINTS (a violation makes your plan rejected wholesale, before anything is sent)

- **In-scope hosts only.** Every request `url` is an **absolute URL** whose host is one of the
  IN-SCOPE HOSTS above. Never target an out-of-scope, unknown, or loopback host. If a finding's
  endpoint is not reachable on an in-scope host, **omit it**.
- **Read-only methods** ({{METHOD_HINT}}). {{STATE_CHANGING_NOTE}}
- **No DoS, no scanning.** Honor the prohibited techniques. At most a handful of requests per finding;
  total well under {{MAX_REQUESTS}}. No flooding, no huge payloads, no fuzzing loops, no enumeration.
- You **observe**, you do not exploit. Prefer the single minimal request that distinguishes vulnerable
  from safe (e.g. an unauthenticated GET to an endpoint that should require auth; a boundary value).
- **Non-destructive only.** Never delete, overwrite, or mutate real data, even if writes were enabled.

## METHOD

1. For each finding, decide whether it has an **observable HTTP signal** on an in-scope host. Read the
   repo to map the code route to the **exact live URL** (controllers, route attributes, API base paths)
   and the response shape that distinguishes vulnerable vs safe.
2. Express the expectation precisely: the status code(s) and/or a `body_contains` token that proves the
   issue (e.g. an anonymous endpoint returning `200` with sensitive fields it should not expose).
3. **Differential confirmation (strongly preferred for access-control / authz).** A bare `200` is weak
   evidence — a login page, a generic handler, or a WAF can also return `200`. Add a **`control`**
   request to the probe: a baseline that *should* behave differently, so the finding is confirmed by the
   **difference**, not an absolute. Typical controls: the SAME endpoint that *should* be denied (expect
   `401/403`), a known-protected sibling, or a non-existent route (expect `404`). The control must also
   be an in-scope, read-only request. If test == control, it is **not** confirmed.
4. If a finding needs an authenticated session, **omit it** in L2 (anonymous, read-only probes only).

## OUTPUT — `live_probe_plan.json`

A JSON **array**, one entry per finding you can probe on an in-scope host:
```json
[
  {
    "finding_id": "<id from FINDINGS_JSON>",
    "note": "<one line: what this probe demonstrates>",
    "requests": [
      {"method": "GET", "url": "https://<in-scope-host>/admin/users", "headers": {},
       "expect": {"status": [200], "body_contains": ["<token proving the issue>"]},
       "control": {"method": "GET", "url": "https://<in-scope-host>/should-be-denied",
                   "expect": {"status": [401, 403]}}}
    ]
  }
]
```
The `control` field is OPTIONAL but recommended for access-control findings — it is a baseline request
run alongside the probe so the verdict can be judged on the **difference**. Omit it for findings where a
single response is already decisive. Emit ONLY this file. If no finding has a safe, in-scope, observable
probe, emit `[]`.
