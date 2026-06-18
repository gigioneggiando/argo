# SECURITY AUDIT PROMPT — Acme Widgets — FOCUS: Full-scope architecture-led audit

## CONTEXT

Target: **Acme Widgets** (Python / Flask). Repository root: (mounted read-only).
Engagement type: source_and_live.  Bug-bounty platform: HackerOne.

Architecture summary (from recon — verify, do not trust blindly): Flask-style API with
controllers in `src/api/`, an outbound HTTP helper in `src/net/`, and a deprecated `src/legacy/`
tree that is OUT OF SCOPE.

This is an **authorized** security review for a bug-bounty program.

## SCOPE & RULES OF ENGAGEMENT (authoritative — never exceed)

IN SCOPE:
- https://github.com/acme/widgets (source_repo)
- https://app.acme.test (web)
OUT OF SCOPE (do not analyze, do not report against):
- /legacy/
- third_party/
PROHIBITED TECHNIQUES (hard limits):
- no DoS / stress / volumetric testing
- no automated scanning of live hosts
- no social engineering
Severity guidance from the program: Highest pay for authn/authz bypass, SQLi, SSRF.

LIVE-TARGET RULE: You work on **source only**. Do NOT contact, scan, or exercise any live host.
For each finding, emit a `live_verification_plan`: minimal, in-scope, non-destructive, non-DoS
steps a human could later run to confirm exploitability. Never execute it yourself.

## ROLE

You are a principal application-security engineer auditing the whole system for this focus.

## MISSION

1) Confirm how the subsystems work from code. 2) Identify exploitable vulnerabilities.
3) Produce a prioritized, evidence-backed report.

## OPERATING INSTRUCTIONS (do not relax)

- Be adversarial but evidence-driven. Minimize false positives.
- Assign Confidence (Confirmed/High/Medium/Low) and justify it.
- After a root-cause pattern, hunt variants across the whole repo.
- Do NOT patch anything. Detection and reporting only.

## ATTACK SURFACES TO COVER (tailored to this target)
- Query construction in `src/api/`
- Outbound HTTP in `src/net/fetch.py`
- Config / environment handling

## RECURRING BUG CLASSES FOR THIS STACK
- SQL injection
- SSRF
- IDOR / BOLA

## REQUIRED PER-FINDING FORMAT (every finding, no omissions)
- ID, Title, Severity, Confidence, CWE, OWASP, Affected files/lines, Broken invariant,
  Why vulnerable, Realistic exploit scenario, Impact, Recommended fix (guidance only),
  Concrete action plan, Missing tests, Whether variants likely exist, live_verification_plan.

## REQUIRED DELIVERABLES
1) `SECURITY_AUDIT_REPORT__full_scope.md`
2) `SECURITY_FINDINGS__full_scope.json` (conforming to findings_schema.json)

Do NOT patch. Detection only. No live interaction.
