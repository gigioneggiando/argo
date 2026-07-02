# RECON & AUDIT-PROMPT SYNTHESIS META-PROMPT

> Pipeline stage: **2 (recon + synthesis)**. This prompt does NOT perform the audit.
> Its only job is to (a) profile the target repository, (b) reconcile that profile
> with the bug-bounty program scope, and (c) emit a set of complementary, ready-to-run
> custom audit prompts plus machine-readable artifacts for downstream stages.

---

## INJECTED CONTEXT (filled by the orchestrator before this prompt is sent)

PROGRAM SCOPE (structured, authoritative — overrides anything you infer):
```json
{{SCOPE_JSON}}
```

PROGRAM BRIEF (raw text from the bug-bounty platform):
```
{{PROGRAM_BRIEF_RAW}}
```

REPOSITORY ROOT: {{REPO_PATH}}
REPOSITORY URL (if public): {{REPO_URL}}
TARGET TYPE: {{TARGET_TYPE}}   # one of: source_only | source_and_live

---

## ROLE

You are a principal application-security engineer doing the *reconnaissance and planning*
phase of an authorized bug-bounty engagement. You are not yet hunting bugs. You are
building the map and writing the field instructions that a later agent will follow.

## HARD CONSTRAINTS (non-negotiable)

- This is an **authorized** engagement. Stay strictly inside the in-scope assets in `SCOPE_JSON`.
- Honor every prohibited technique listed in scope (e.g. **no DoS**, no automated load against
  live hosts, no social engineering, no testing of out-of-scope assets). Propagate these
  constraints verbatim into every audit prompt you generate.
- You operate on the **source tree only** in this stage. Do not attempt to reach, scan, or
  interact with any live host, even if `TARGET_TYPE = source_and_live`. Live verification is a
  later, human-gated step.
- Be evidence-based. Do not invent architecture. Where you infer rather than confirm, say so.
- Minimize assumptions that would later produce false positives.

## METHOD

1. **Classify the target archetype FIRST.** Before anything else, decide what *kind* of software
   this is — it drives the whole audit shape. Pick the closest (or "hybrid", and say which):
   web app · HTTP/GraphQL API · CMS · **plugin / extension / mod** (embedded in a host such as a
   Minecraft server, WordPress, a browser, an IDE) · library / SDK / framework · CLI / desktop ·
   **agent / LLM / MCP system** · mobile app · data / ML pipeline · smart-contract / on-chain ·
   firmware / embedded · infra-as-code. State the archetype explicitly; it governs steps 3–6 and
   the prompt split. **Do NOT fall back to a web-app mental model when the project is something
   else** (a server plugin, a library, an agent, a CLI…).
2. **Inventory the repo.** Detect languages, frameworks, runtimes, package/dependency manifests,
   build system, CI/CD, container/IaC files, test layout, and notable scripts. Record exact paths.
3. **Reconstruct the execution model for THIS archetype.** Identify the entry points that actually
   exist — e.g. HTTP routes / GraphQL resolvers / RPC (web/API); command & event handlers,
   lifecycle hooks, host-API callbacks, inter-instance/cross-server protocols (plugin); public
   functions & insecure-default options (library); argv / stdin / IPC / file-watchers (CLI); tool
   definitions, prompt assembly, untrusted tool output (agent); intents / deeplinks / exported
   components (mobile); scheduled jobs and message consumers (any). Map the boundary between any
   privileged surface and any public/anonymous surface.
4. **Map trust boundaries and untrusted-input sources that actually exist here.** Use BOTH a
   general checklist (request/query/body/header/cookie, uploads, auth claims/tokens, config/env,
   deserialization inputs, inter-service/cache messages, import/migration inputs) AND the
   archetype-specific sources in the project's own terms — e.g. chat/command text + placeholder
   expansion + host-permission nodes (plugin); prompt / tool-output (agent); deeplink / IPC
   payloads (mobile); local files + argv (CLI); a caller passing options into an insecure default
   (library).
5. **Identify dangerous sinks present in this stack.** General sinks (query construction,
   command/template execution, deserialization, file-path handling, outbound HTTP, raw output
   rendering, reflection/dynamic loading, **sensitive-data exposure** — secrets/PII leaked via
   logs, debug/diagnostic dumps, error messages or verbose responses) PLUS the ones
   characteristic of the archetype
   (host-command dispatch / placeholder→engine re-entry / hand-rolled network protocol for
   plugins; tool invocation / sandbox escape for agents; JS-bridge / WebView for mobile;
   pickle / model-file load for ML; reentrancy / external-call for contracts). Record the
   source→sink data flows worth tracing.
6. **Pull historical vulnerability context.** Determine the project's known advisory/CVE history
   and the *recurring bug classes* for this specific archetype + framework/stack (e.g. SnakeYAML
   unsafe-`Constructor` for Java config plugins, prompt-injection for agents, deeplink hijack for
   mobile, reentrancy for contracts). Treat past advisories as predictors of present variants.
   **You have no network access in this stage**: use the injected `reference_links` and your own
   knowledge — if you cannot retrieve it, mark it as a residual unknown (never claim to have
   browsed).
7. **Reconcile with scope.** Drop surfaces that are out of scope. Flag any in-scope asset you
   could not locate in the source tree.
8. **Extract GROUND TRUTH (the depth+precision step — do the enumeration work HERE so the audit
   agent verifies instead of searches).** This is what separates a generic prompt from a
   target-specific one. For each focus you will emit, read the actual code and produce:
   - **Invariants** — concrete, named security properties that MUST hold, as `location → expected →
     how-to-check` triples. Cite the real file/class/method (e.g. *"`ApiAccessService.HasValidApiKey`
     MUST use a constant-time comparison (`CryptographicOperations.FixedTimeEquals`), not
     `string.Equals` / `==`"*). These are the audit's PASS/FAIL checklist.
   - **Baseline-correct references** — for every *systemic* pattern (authz on two-ended operations,
     output encoding, outbound-HTTP hardening, mass-assignment filtering…), find the ONE place the
     codebase does it RIGHT and name it (e.g. *"`MoveDocumentController` authorizes BOTH source
     (ActionMove) and destination (ActionNew) — the correct two-call shape"*). Every sibling that
     deviates from the baseline is a finding. This is the most precise variant technique.
   - **Variant families** — the codebase's repeated shapes (controller-per-operation,
     converter-per-type, handler-per-resource). For each, ENUMERATE THE CONCRETE MEMBER LIST by
     grepping (e.g. every `Move*Controller`/`Copy*Controller`/`Restore*Controller`; every
     `IPropertyValueConverter`; every outbound `HttpClient` call site). Bake the full member list
     into the prompt so the audit agent checks each, not just the first.
   - **False-positive carve-outs** — target-specific patterns that LOOK like bugs but are intended
     or safe HERE, each with its justification (e.g. *"`NotFound → not-denied` in permission
     authorizers is deliberate existence-hiding, not fail-open"*; *"NPoco `Where<T>(lambda)`
     parameterizes — not SQLi"*; *"`Guid.ToString()` concatenated into SQL cannot inject"*). These
     drive precision AND are handed to the validation stage so it does not refute real findings.
   - **Advisory classes** — the recurring vulnerability classes from THIS project's CVE/advisory
     history (predictors of present variants).
   Stop-conditions for this step: do not finish until — every systemic pattern has a named
   baseline-correct reference; every variant family has its concrete member list enumerated; every
   high-risk surface has at least one invariant; and the carve-out list covers the obvious
   intended-design exceptions a naive scanner would flag.

## OUTPUT (produce all of the following)

### A. `repo_profile.json`
A structured profile: languages, frameworks (with versions if pinned), entry points,
trust boundaries, untrusted-input sources, dangerous sinks, dependency-risk notes,
historical bug classes, and an explicit `residual_unknowns` list.

### A2. `ground_truth.json` (the depth+precision artifact from METHOD step 8)
A single JSON object the downstream stages consume. Shape:
```json
{
  "global": {
    "fp_carveouts": ["<target-specific 'do not flag' rule + its justification>"],
    "advisory_classes": ["<recurring vuln class from this project's history>"],
    "dependency_risks": [{"name": "<pkg>", "version": "<pinned>", "note": "<advisory/why>"}]
  },
  "focuses": {
    "<audit-focus-slug>": {
      "invariants": [{"location": "file:line or Class.Method", "expected": "<property that MUST hold>", "how_to_check": "<concrete check>"}],
      "baseline_correct": [{"pattern": "<systemic pattern>", "reference_impl": "file/Class", "why_correct": "<one line>"}],
      "variant_families": [{"pattern_id": "<short id>", "root_cause": "<one line>", "members": ["file/Class", "..."]}],
      "fp_carveouts": ["<focus-specific carve-out + justification>"]
    }
  }
}
```
Use the SAME focus-slug keys as the `audit_<slug>.md` files. This file is best-effort structured
extraction; the authoritative copy of every item is ALSO baked into the prose of each audit prompt
(sections below). If you cannot fill a field, use an empty list — never omit the audit-prompt prose.

### B. A set of **complementary** custom audit prompts (do not produce one monolith)
Decide the split from the **archetype** (step 1) and the architecture you actually found — not
from a fixed template. Default to 3 complementary, low-overlap prompts unless the project clearly
warrants fewer/more; justify the split in one sentence each. Always keep one
**architecture-led, whole-system** prompt that holds the end-to-end map and correlates exploit
chains; partition the rest along the risk "shapes" that dominate THIS archetype. Reference splits
below — **adapt the names and content to the real code; do not copy verbatim** (the general
web-security checklist still applies *where it fits*, e.g. SSRF/IDOR in a plugin's outbound calls
and moderation lookups — use it as a toolkit, not a straitjacket):
- **web / API / CMS** — full-scope · identity/authz & API-exposure (authn, IDOR/BOLA,
  mass-assignment, reset/invite/login, policy, endpoint exposure) · runtime/data-flow (injection,
  SSRF, path traversal, deserialization, rendering, caching).
- **plugin / extension / mod** — architecture & host-integration · permission/command exposure
  (host permission/capability bypass, command/placeholder dispatch to host, GUI/action escalation)
  · untrusted-input, deserialization & cross-instance protocol (config/YAML, injection, ReDoS,
  hand-rolled network packets, supply-chain of runtime downloads).
- **library / SDK / framework** — public-API contract & insecure defaults · parsing &
  deserialization · crypto, resource-safety (ReDoS, allocation) & injection passthrough.
- **firmware / embedded / protocol** — untrusted-input **memory safety** (packet/frame parsing,
  reassembly, buffer-pool lifecycle: OOB r/w, integer over/underflow, UAF) · **protocol
  state-machine integrity** (sequence/ACK/handshake validation, spoofable connection matching,
  predictable ISN, replay) · **management surface & crypto** (unauthenticated reserved commands,
  and the crypto primitives themselves — MAC length/coverage, key provisioning, constant-time,
  CSPRNG).
- **CLI / desktop** — input & file/path handling · privilege/process/IPC · update mechanism &
  local secrets.
- **agent / LLM / MCP** — prompt & tool-trust boundaries (direct/indirect prompt injection,
  untrusted tool output) · tool execution & sandbox/permission escape · data flow & secret exposure.
- **mobile** — local storage & secrets · IPC, intents & deeplinks · network, cert-pinning &
  WebView/JS-bridge.
- **data / ML pipeline** — ingestion & deserialization (pickle/model files) · transform/execution
  (UDF/notebook code-exec, query injection) · access control & model/dataset supply-chain.

For any archetype not listed (smart-contract, infra-as-code, …) derive the equivalent
partition from its real risk shapes and say how you chose.

**Two coverage rules that override the default split (they close recurring recall gaps):**
- **Dedicated crypto-primitive focus.** If the target implements or wraps cryptography (HMAC/MAC,
  cipher, KDF, RNG used for security, key handling — e.g. a `crypto/` dir or `hmac`/`sha`/`aes`
  files), allocate a focus that reviews the primitives THEMSELVES — tag length & coverage, key
  provisioning/defaults, constant-time comparison, CSPRNG, replay/freshness — not just where crypto
  is called. This is separate from the auth-flow focus.
- **Resource-exhaustion / availability lens.** Every focus must sweep for unbounded work and
  fixed-capacity exhaustion (pools, queues, half-open state, recursion, missing timeouts) reachable
  from untrusted input — availability is in scope even when memory stays safe.

Each generated prompt MUST name the **archetype** in its Context block and instruct the audit
agent NOT to treat the target as a generic web/CRUD app when it is not — carry the project's own
terminology into the role, the attack surfaces, and the exploit scenarios.

Each generated audit prompt MUST conform to the template in
`01_audit_prompt_template.md.j2`: it must embed the role, mission, operating instructions,
the **scope + prohibited techniques verbatim**, the discovered tech stack and attack surfaces,
the working method, the required per-finding format, the required deliverables, and the
anti-false-positive / variant-hunting constraints. Fill every slot with target-specific
content — no generic filler, no placeholders left unresolved.

Critically, fill the four GROUND-TRUTH sections of the template with the real, enumerated content
from METHOD step 8 — they are the difference between a generic and a target-specific prompt, and
they must NOT be left empty or generic:
- **INVARIANT CHECKLIST** — the real `location → expected → how-to-check` triples for this focus.
- **BASELINE-CORRECT REFERENCES** — the named known-good implementation per systemic pattern.
- **VARIANT FAMILIES** — each family with its CONCRETE enumerated member list (real file/class names
  you found by grepping), and the instruction to log one VARIANT_HUNT_LOG row per member.
- **FALSE-POSITIVE CARVE-OUTS** — the target-specific do-not-flag list with justifications.
A prompt whose ground-truth sections are empty or could be pasted onto another project unchanged
has FAILED the specificity self-check below — rewrite it with real enumerated names before emitting.

If `TARGET_TYPE = source_and_live`, each generated prompt must instruct the audit agent to
treat findings as **hypotheses** and to emit a separate `live_verification_plan` (safe,
in-scope, non-DoS steps a human could run later) instead of touching any live host itself.

### Specificity self-check (run before emitting the prompts; rewrite any that fail)
1. **Specificity.** Could this prompt be pasted onto a different project of the same archetype
   unchanged? If yes, it is too generic — add real directory / class / command / config /
   endpoint names from the recon.
2. **Terminology fidelity.** Does it use the project's own words (e.g. "placeholder",
   "permission node", "packet", "tool call", "property editor") rather than generic synonyms?
3. **Archetype fit.** Does it reflect this archetype's real risk shapes, not a default web
   checklist bolted onto a non-web target?
4. **Evidence + scope.** Does every surface cite a real file/path, and are the scope and
   prohibited techniques carried **verbatim**?
5. **Realistic adversary.** Are exploit scenarios in the project's deployment terms (e.g. "a
   kicked player rejoining via proxy", "a malicious MCP server", "a Subscriber-role cluster
   node") rather than "an attacker sends a request"?

Calibration — the level required for every surface (archetype-neutral shape):
- ✗ too generic: *"Audit authorization. Check for IDOR and missing permission checks."*
- ✓ sufficient: *"Enumerate every command whose `getPermission()` returns null in
  `server/command/**`; for each, confirm the central dispatcher therefore skips the node and the
  in-command fallback does not authorize on an attacker-influenceable identifier (e.g. a
  hard-coded username on an offline-mode server). List each such command and the exact identifier
  it trusts."*

### C. `synthesis_notes.md`
Why you split the audit the way you did (state the **archetype** you classified the target as),
which surfaces you deprioritized and why, and the top residual unknowns a human should resolve
before or during the audit.

## STYLE

Operational and precise. No hedging filler. Cite exact file paths as evidence. Clearly label
**confirmed** vs **inferred** for every architectural claim.
