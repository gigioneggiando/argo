# Security Audit Report - Acme Widgets

> **Automated source-static audit - human-review bundle.** No live host was contacted, scanned, or exercised by any stage. Nothing here has been submitted; submission is a manual human action.

## Run metadata

- Run ID: `TEST-RUN-0001`
- Platform: HackerOne
- Target type: source_and_live
- Generated at: 2026-06-16T12:00:00+00:00
- Models: audit=claude-sonnet-5, ingest=claude-sonnet-5, recon=claude-opus-5, report=claude-sonnet-5, validate=claude-opus-5
- LLM cost: $0.0000 over 5 call(s)

## Executive summary

- Surviving findings: **3** (confirmed: 2, needs-runtime-verification: 1)
- Dropped in validation/scope filtering: **2**
- Surviving by severity: High: 3

## Fix first

1. **SQL injection in widget search** (High/Confirmed, CWE-89) - `src/api/search.py:42`
2. **IDOR: order access without ownership check** (High/High, CWE-639) - `src/api/orders.py:120`

## Findings (sorted by validated severity, then confidence)

### FULL-001 - SQL injection in widget search

- Severity: **High** (audit: High) | Confidence: **Confirmed** | Verdict: **confirmed**
- CWE: CWE-89 | OWASP: A03:2021 Injection
- Affected: `src/api/search.py:42`

**Vulnerable flow.** GET /api/search?q -> search() -> string-built SQL -> db.execute

**Why vulnerable.** The q query parameter is concatenated directly into a SQL LIKE clause with no parameterization or escaping.

**Exploit scenario.** An anonymous user supplies q=%' OR '1'='1 to exfiltrate rows or chain to stacked queries.

**Impact.** Database read/exfiltration; potential write depending on driver settings.

**Validated data flow.** GET /api/search?q -> search() -> 'SELECT ... LIKE %'+q+'%' -> db.execute (src/api/search.py:42)

**Recommended fix (guidance only).** Use parameterized queries / bound parameters; never build SQL by string concatenation.

**Live verification plan (for a human, in-scope, non-DoS).** With program authorization, send one benign sentinel value to /api/search and observe error/behavior; no automation, no DoS.

### AUTHZ-002 - IDOR: order access without ownership check

- Severity: **High** (audit: High) | Confidence: **High** | Verdict: **confirmed**
- CWE: CWE-639 | OWASP: A01:2021 Broken Access Control
- Affected: `src/api/orders.py:120`

**Vulnerable flow.** GET /api/orders/<id> -> get_order() -> repo.find(id) with no owner check

**Why vulnerable.** The order is fetched purely by client-supplied id; no check binds the order to the caller.

**Exploit scenario.** An authenticated user iterates order ids to read other customers' orders.

**Impact.** Cross-tenant data disclosure of all orders.

**Validated data flow.** GET /api/orders/<id> -> get_order() -> repo.find(id) (src/api/orders.py:120)

**Recommended fix (guidance only).** Enforce an ownership/authorization check binding order.owner to the caller.

**Live verification plan (for a human, in-scope, non-DoS).** With authorization, request two order ids belonging to a test account only; no enumeration of real users, no automation.

### FULL-003 - SSRF via user-controlled outbound fetch

- Severity: **High** (audit: High) | Confidence: **Medium** | Verdict: **needs_runtime_verification**
- CWE: CWE-918 | OWASP: A10:2021 SSRF
- Affected: `src/net/fetch.py:88`

**Vulnerable flow.** user url -> fetch(url) -> http.get(url) with no allow-list visible in source

**Why vulnerable.** A user-influenced URL reaches an outbound HTTP client with no source-visible allow-list.

**Exploit scenario.** Attacker points the URL at an internal metadata service to read credentials.

**Impact.** Access to internal services / cloud metadata; potential credential theft.

**Validated data flow.** user url -> fetch(url) -> http.get (src/net/fetch.py:88)

**Recommended fix (guidance only).** Enforce a strict egress allow-list and block internal ranges.

**Live verification plan (for a human, in-scope, non-DoS).** With authorization, issue one benign request to a controlled collaborator host; no scanning, no DoS.

## Residual unknowns

These need human runtime verification (static evidence strong; exploitability depends on runtime/config not visible from source):
- **SSRF via user-controlled outbound fetch** (CWE-918, `src/net/fetch.py:88`) - SSRF sink is reachable, but whether an egress allow-list blocks internal ranges depends on deploy-time config not visible from source.
- (recon) Whether an upstream WAF or auth middleware gates /api/* in production (not visible from source).
- (recon) Whether the SSRF allow-list is enforced at deploy time via config.

## Dropped findings (not reported)

- `FULL-002` Reflected XSS in legacy renderer (CWE-79) - out_of_scope (code-side scope filter)
- `AUTHZ-003` Service banner disclosure (CWE-200) - refuted

---

**Guardrails:** repo mounted read-only | no live interaction performed | no patching | no auto-submission. Submission drafts in `submission_drafts/` are marked DRAFT and require manual human review before any submission.
