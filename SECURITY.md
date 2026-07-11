# Security Policy

## Reporting a vulnerability in Argo

If you find a security issue in **Argo itself** — the pipeline, orchestrator, CLI/API, or any code in
this repository — please report it privately rather than opening a public issue:

- Email: `luigicolluto2006@gmail.com`
- GitHub: [@gigioneggiando](https://github.com/gigioneggiando), or open a private
  [security advisory](https://github.com/gigioneggiando/argo/security/advisories/new)

Please include enough to reproduce it (version/commit, configuration, and steps). I'll acknowledge as
soon as I can and coordinate a fix and disclosure timeline with you. This is a personal open-source
project, so responses are best-effort — thanks for disclosing responsibly and for your patience.

## Scope

**In scope** — vulnerabilities in this repository's own code, for example:

- command/prompt injection, path traversal, or code execution in the pipeline stages, runner, or the
  web/API surface;
- the opt-in `live` / `runtime` stages contacting hosts, or building/executing code, outside their
  documented, gated, in-scope-only constraints;
- leakage of API keys, credentials, or scanned-target contents through logs, run artifacts, or the
  served UI.

**Out of scope**

- Findings that Argo *produces* about a third-party target. Argo is an analysis tool: a vulnerability
  it reports in some other project must be disclosed to **that** project through its own security
  process — not here. Argo's output is AI-assisted and may contain false positives; review before
  acting on it.
- Behaviour that only occurs when Argo is run outside its intended, authorized use (see below).

## Responsible use

Argo is for **authorized** security review only — your own code, bug-bounty programs with safe harbor,
CTFs, or research. By design the pipeline never auto-submits and never contacts live hosts unless you
explicitly enable the gated `live` stage with `--i-have-authorization`. Keep your use within the rules
of engagement of the program or system you are testing. See the "Principles and limits" section of the
[README](README.md) and [`docs/guardrails.md`](docs/guardrails.md).

## Supported versions

Argo is early-stage (v0.x). Security fixes land on the `main` branch; older tags are not separately
maintained.
