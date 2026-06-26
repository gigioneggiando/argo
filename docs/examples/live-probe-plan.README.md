# Live probe plan (`live_probe_plan.json`) — ⚠️ authorized live testing only

`argo live` (the opt-in, default-off live stage — see
[guardrails §2c](../guardrails.md#2c-the-opt-in-live-exception-the-live-stage-in-scope-hosts-only))
reads a **hand-written** `runs/<RUN_ID>/live_probe_plan.json` and makes the requests in it against the
program's **live in-scope hosts** to confirm findings. It is the live analog of the runtime probe plan,
but pointed at the real target — so it is gated hard. Copy `live-probe-plan.example.json` and edit it.

## Format

A JSON **array** of entries, one per finding you want to confirm:

```json
[
  {
    "finding_id": "AUTHZ-001",
    "requests": [
      { "method": "GET", "url": "https://api.example.com/v1/admin/users",
        "expect": { "status": [401, 403] } }
    ]
  }
]
```

- **`url`** must be an **absolute URL** whose host is a **registered in-scope web/api asset**. Relative
  paths, out-of-scope hosts, unknown hosts, and loopback are all **rejected before any request is sent**.
- **`method`** is **read-only** (GET/HEAD/OPTIONS) unless you pass `--allow-writes` (a deliberate second
  opt-in). Honor the program's `prohibited_techniques` (no DoS, no scanning if forbidden).
- **`headers`** / **`body`** are optional (body is size-capped, never logged to the audit trail).
- **`expect`** is optional: `status` (int or list) and `body_contains` (list of substrings). When set,
  the result is marked `expect_met` so you can see at a glance whether the finding was confirmed.

## Hard gates (all enforced in code, before anything is sent)

1. **RoE authorization** — the run's `scope.json` must have `automation_allowed: true`,
   `safe_harbor` not explicitly `false`, and a non-empty `prohibited_techniques`.
2. **In-scope-only** — every request host must match an in-scope asset; everything else is blocked.
3. **Read-only + caps** — read-only methods by default; total-request, rate, and body-size caps; an
   oversized plan is rejected whole (no silent truncation).

## Run it

```bash
argo live --run <RUN_ID> --i-have-authorization
# read-only by default; conservative caps. Tune with:
#   --max-requests N   --min-interval SECONDS   --allow-writes (second opt-in)
```

Outputs land in the run dir: `live_results.json` (per-request status + body snippet + `expect_met`)
and `live_audit_log.jsonl` (an accountable record of every request made: timestamp, method, URL,
status, size). **Authorized use only — this touches a real host, and that is your responsibility.**
