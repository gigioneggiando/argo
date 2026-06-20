# RUNTIME PROBE-PLAN PROPOSAL PROMPT (R2)

> Pipeline stage: **runtime (propose)**. You design **safe HTTP probes** that would confirm or
> refute the findings below against a **local, sandboxed instance** of the target running at
> `http://127.0.0.1:{{PORT}}`. You do NOT run anything — you only emit a probe plan. A deterministic
> validator gates your plan, and a fixed runner executes it inside an egress-blocked container.

---

## INJECTED CONTEXT

PROGRAM: {{PROGRAM_NAME}}
REPOSITORY ROOT (read-only — use it to find the EXACT routes/paths): {{REPO_PATH}}
LOCAL INSTANCE BASE URL: http://127.0.0.1:{{PORT}}   (loopback only)

PROHIBITED TECHNIQUES (hard limits — never exceed):
{{PROHIBITED_TECHNIQUES}}

FINDINGS TO PROBE (confirm/refute each where an HTTP signal is observable):
```json
{{FINDINGS_JSON}}
```

---

## HARD CONSTRAINTS (a violation makes your plan rejected wholesale)

- **Loopback only.** Every request is **host-relative** (a path starting with `/`). Never write an
  absolute URL, never a `Host:` header naming any real/external host. The runner targets
  `127.0.0.1:{{PORT}}` for you.
- **Read-only methods** ({{METHOD_HINT}}). {{STATE_CHANGING_NOTE}}
- **No DoS.** Honor the prohibited techniques. At most a handful of requests per finding; total well
  under {{MAX_REQUESTS}}. No flooding, no huge payloads, no fuzzing loops.
- You **observe**, you do not exploit. Prefer the minimal request that distinguishes vulnerable from
  safe (e.g. an unauthenticated GET to an endpoint that should require auth; a boundary value).

## METHOD

1. For each finding, decide whether it has an **observable HTTP signal** from an anonymous (or
   minimally-privileged) caller. Many authz findings need an authenticated session — if you cannot
   construct a safe, self-contained probe, **omit that finding** (don't invent a weak probe).
2. Read the repo to get the **exact route** (controllers, route attributes, API base paths) and the
   exact response shape that would distinguish vulnerable vs safe.
3. Express the expectation precisely: the status code(s) and/or a `body_contains` token that proves
   the issue (e.g. an anonymous endpoint returning `200` with sensitive fields).

## OUTPUT — `runtime_probe_plan.json`

A JSON **array**, one entry per finding you can probe:
```json
[
  {
    "finding_id": "<id from FINDINGS_JSON>",
    "note": "<one line: what this probe demonstrates>",
    "requests": [
      {"method": "GET", "path": "/exact/route", "headers": {},
       "expect": {"status": [200], "body_contains": ["<token proving the issue>"]}}
    ]
  }
]
```
Emit ONLY this file. If no finding has a safe observable probe, emit `[]`.
