# META-PROMPT: Generatore di 3 prompt custom per security audit di un repository

Questo file è un **meta-prompt**: da copiare e incollare in un LLM (Claude, GPT, ecc.) **insieme al blocco "Target project" compilato**. L'LLM userà questo testo per generare tre prompt operativi (audit → patch → verify) altamente specifici al progetto indicato.

Regola d'oro: i tre prompt generati devono essere **indistinguibili per livello di customizzazione dagli audit enterprise reali**. Se il prompt prodotto potesse essere incollato su un altro progetto dello stesso tipo senza modifiche, il lavoro non è fatto.

---

## BLOCCO DA COMPILARE PRIMA DI ESEGUIRE IL META-PROMPT

```
TARGET PROJECT:
- Name:
- Repository URL:
- Official documentation URLs (list all):
- Known tech stack (optional, LLM will verify):
- Known areas of concern (optional):
- Bug bounty / VDP program URL, if any:
- Scope restrictions, if any:
```

---

## META-PROMPT (copia tutto da qui in giù)

You are an expert security-prompt engineer. Your single task is to produce three high-quality, deeply-customized prompts that a security-focused LLM agent will later use to (1) AUDIT, (2) PATCH, and (3) VERIFY the target repository listed in the `TARGET PROJECT` block above.

The three generated prompts must be so specific to this repository that a reader familiar with the project would recognize it from the prompt alone. Generic prompts fail this task.

You will work in two phases. Do NOT skip Phase 1. Do NOT produce the three prompts before completing Phase 1.

---

## PHASE 1 — MANDATORY DEEP DISCOVERY

Before writing any prompt, reconstruct the target from its repository and documentation. Use web browsing, repository inspection, and documentation reading. Produce a `# DISCOVERY` section at the top of your response that concretely answers each of the following. Cite file paths, class names, and doc URLs wherever possible. Explicitly mark anything you cannot verify as `ASSUMED — needs runtime confirmation`.

### 1.1 Project identity
- What kind of software is this? (web app, API backend, CMS, plugin/extension, library, CLI, mobile, desktop, agent/LLM system, data pipeline, infra-as-code, hybrid)
- Primary language(s), runtime versions, major frameworks.
- Build system and dependency manifest file names.
- Deployment model: self-hosted? SaaS? embedded as library? installed into a host environment (e.g. Minecraft server, Umbraco host, WordPress instance)?

### 1.2 Concrete architecture
- Top-level modules/projects/packages with their actual directory names.
- The 5–15 directories where security-critical code concentrates (name them: e.g. `src/Umbraco.Cms.Api.Management/Controllers/**`, `src/auth/`, `packages/server/handlers/`).
- Entry points by kind: HTTP routes, GraphQL resolvers, RPC handlers, CLI entrypoints, command handlers, event/webhook listeners, message consumers, scheduled jobs, file-watcher triggers, plugin lifecycle hooks.
- Persistence layers and backends (list every one: Postgres, SQLite, Redis, S3-like, filesystem, YAML, JSON, cache).
- External integrations (list each: OAuth providers, webhooks, Discord, Telegram, payment, mail, cloud APIs, LLMs).
- Extensibility surface: plugin manifests, DI registration points, extension points, script-loading, template engines.
- Configuration and reload model: where configs live, how they're parsed, whether reload is hot, whether partial reload can corrupt state.

### 1.3 Trust boundaries and untrusted inputs specific to THIS product
- Enumerate every class of caller: anonymous internet, authenticated end-user, privileged admin/operator, external API client, plugin/extension code, CI/CD, other instances in a cluster.
- For each caller, list what they can reach.
- Enumerate every class of untrusted input **in the project's own terminology**: not "form inputs" but e.g. "property editor values (block list, block grid, TipTap rich text)", not "command strings" but e.g. "placeholder expansion inside `/discordmessage embed <channel ID> <JSON>`".

### 1.4 Critical surfaces named by real product terminology
Identify the specific features, endpoints, commands, GUIs, or flows that are most security-relevant. Name them using the project's own naming convention. Examples of the level of specificity required:
- ChatPlugin: `/chatlog`, `/iplookup`, `/accountcheck`, `/discordmessage embed <channel ID> <JSON>`, `/telegrammessage`, custom GUIs loaded from YAML, anti-ban-evading flows.
- Umbraco: `ManagementApiControllerBase`, `[Authorize(Policy = BackOfficeAccess)]`, `DeliveryApiAccessAttribute`, `UmbracoJsonTypeInfoResolver`, `BackofficeHub` / `ServerEventHub`, `WebhookFiring` named HttpClient.
If the project does not expose such named surfaces, identify the equivalent concrete constructs (e.g. specific route patterns, specific service classes, specific config sections).

### 1.5 Project-specific vulnerability classes
Beyond the standard OWASP list, what vulnerability shapes are especially likely in this kind of software?
- Plugin/extension: placeholder injection, unsafe command dispatch to host, YAML deserialization, cross-server cache poisoning, permission-node bypass.
- CMS: property editor stored XSS, package manifest JSON polymorphism abuse, rich-text sanitization bypass, Lucene syntax passthrough, preview-mode authorization gaps.
- Agent/LLM system: prompt injection, unsafe tool invocation, untrusted tool output feedback, sandbox escape.
- Mobile app: insecure local storage, deep-link hijacking, WebView JS-bridge abuse.
Pick the three to eight vulnerability classes most likely to hide critical findings in THIS project.

### 1.6 Historical security signal
- Search the project's public CVE history, GitHub Security Advisories, dedicated trust-center pages, disclosed HackerOne/Intigriti/YesWeHack reports, and changelog security sections.
- Identify past patterns that reappear across releases (e.g. "Umbraco has had multiple SignalR hub authorization bugs").
- Note any `SECURITY.md`, public bug-bounty/VDP policy, and in-scope/out-of-scope rules. Generated prompts must respect these.

### 1.7 Honest confidence annotation
List every assumption you're carrying forward into Phase 2 with confidence level. Example:
- `[HIGH] Build system is Gradle with a root settings.gradle.kts — verified by file listing.`
- `[LOW] Webhook signing uses HMAC-SHA256 — inferred from docs page, code path not yet traced.`

---

## PHASE 2 — PRODUCE THE THREE TAILORED PROMPTS

After `# DISCOVERY`, emit three fully self-contained prompts. Each is designed to be copy-pasted standalone into a fresh LLM session.

### Shared rules for all three generated prompts

Every generated prompt MUST begin with a `Context:` block containing:
- Project name and repository URL.
- A bulleted list of **every documentation URL the agent must consult before touching code** (pull from Phase 1).
- A one-paragraph description of what kind of software this is and how it is deployed. Explicitly warn against treating it as a generic web app when the project is, say, a server plugin or an agent system.
- A bulleted list of the **project-specific attack surfaces** identified in Phase 1.4.

Every generated prompt MUST include operating instructions:
- Evidence over guesswork. Every claim requires a file:line citation plus a quoted excerpt.
- Minimize false positives; a correct severity downgrade is more valuable than a flashy wrong severity.
- Distinguish explicitly: `CONFIRMED` / `HIGH-CONFIDENCE` / `MEDIUM-CONFIDENCE` / `LOW-CONFIDENCE` smell.
- Hunt for variants across the entire repo; name the controller/handler/service pattern and grep for siblings.
- Do not invent architecture details; if code and docs diverge, code is authoritative and the divergence itself is a finding.
- Respect the project's scope rules (from 1.6). Out-of-scope assets must not be tested.

### PROMPT 1 — AUDIT

Role framing: "You are a principal application security engineer and senior [language/stack] [product-type] architect performing a deep, full-scope security and reliability audit of this repository." Tailor `[language/stack]` and `[product-type]` to Phase 1.1.

Required body sections:
1. **Repository layout enumeration** — explicit list of directories the agent must map (from Phase 1.2), named.
2. **Untrusted input enumeration** — full list from Phase 1.3, using the project's terminology.
3. **Critical surface audit list** — every item from Phase 1.4, each expanded into 3–8 concrete audit questions. Example of required specificity:
   - Not: "audit authorization policies"
   - But: "Enumerate every policy registered in `src/Umbraco.Cms.Api.Management/DependencyInjection/BackOfficeAuthPolicyBuilderExtensions.cs`, list its requirements and handlers, verify every state-changing controller calls `IAuthorizationService.AuthorizeResourceAsync`, and confirm bidirectional authorization on move/copy/restore."
4. **Project-specific vulnerability classes to hunt** (from Phase 1.5), each with 2–4 concrete sinks or patterns to grep for.
5. **Method** — numbered steps for mapping, tracing, grepping, dependency audit, test-gap analysis, variant hunting, correlation into realistic exploit paths.
6. **Finding template** — every finding must include: ID, Title, Severity (Critical/High/Medium/Low/Informational), Confidence (Confirmed/High/Medium/Low), CWE, OWASP category, Affected files/classes/methods, Vulnerable data flow, Why it is vulnerable, Realistic exploit scenario **in the project's deployment context** (e.g. "a kicked player returning via VPN..." for a Minecraft plugin), Impact, Recommended fix, Concrete action plan, Missing tests, Whether variants likely exist elsewhere.
7. **Required deliverables**: `SECURITY_AUDIT_REPORT.md`, `SECURITY_FINDINGS.json`, short plain-English summary, architecture summary, top 10 immediate actions, fix-first ordering, residual unknowns requiring runtime verification.
8. **Explicit prohibition**: no patching, no runtime exploitation against live systems; static analysis only unless otherwise authorized.

### PROMPT 2 — PATCH

Role framing: staff security engineer and senior maintainer implementing production-grade fixes.

Required body sections:
1. **Inputs**: the repository + `SECURITY_AUDIT_REPORT.md` + `SECURITY_FINDINGS.json`.
2. **Goal statement**: real code changes, root-cause over band-aid, preserve intended behavior unless insecure, minimize diff, refactor duplicated insecure patterns into shared safe abstractions, no hardcoded secrets, document rotation steps for any exposed secrets.
3. **Project-runtime reality constraints** — call out facts like "this is a Minecraft plugin: fixes must respect event-loop and async scheduler realities, not just static code style" or "this is a multi-server CMS: fixes must preserve cache-instruction consistency across Subscriber nodes".
4. **Security engineering principles tuned to THIS stack** — e.g. "centralize permission checks in `ManagementApiControllerBase`", "use parameterized queries across all storage adapters (H2, SQLite, MySQL)", "sanitize for each output context: chat renderer, GUI text, Discord embed, Telegram message".
5. **Mandatory focus areas**: the named features from Phase 1.4, one-by-one, with the specific patch objective for each.
6. **Workflow**: read findings → group by domain → remediation plan → patch highest-risk first → variant sweep → add tests → update validators/configs/docs → re-run tests → clean final patch (not a pile of one-off edits).
7. **Deliverables**: actual code changes, new/updated tests, `PATCH_SUMMARY.md` (issue fixed / files changed / technical rationale / security rationale / behavior change / rollout notes), `CHANGELOG_SECURITY.md`.
8. **Final summary requirements**: fixed Critical/High, remaining Medium/Low, items requiring infra/admin/secret rotation outside code, any migration/config/deployment steps.

### PROMPT 3 — VERIFICATION

Role framing: senior verification engineer specializing in AppSec, QA, regression prevention, and release hardening for [project-type].

Required body sections:
1. **Inputs**: patched branch + `SECURITY_AUDIT_REPORT.md` + `SECURITY_FINDINGS.json` + `PATCH_SUMMARY.md` + `CHANGELOG_SECURITY.md`.
2. **Adversarial stance**: do not assume patches work because the code looks cleaner; validate behavior through tests, targeted abuse cases, and end-to-end reasoning; fix regressions found during verification.
3. **Project validation pipeline** — concrete commands for this stack:
   - Build: `<actual build command>` (e.g. `./gradlew build`, `dotnet build Umbraco.sln`, `npm run build && npm test`)
   - Type/compile/lint: the real ones for this project
   - Tests: unit + integration + e2e if present
   - Packaging checks if applicable (e.g. plugin JAR loads, NuGet package restores)
4. **Project-appropriate security tooling** — choose from Semgrep, OSV-Scanner, SpotBugs/FindSecBugs, pip-audit, npm audit, cargo audit, gosec, etc., based on the actual stack.
5. **Must-verify list** — every item derived from Phase 1.4 critical surfaces, rephrased as verification questions.
6. **Targeted negative tests** — a list of adversarial input scenarios specific to this product (e.g. "malicious JSON payload to `/discordmessage embed`", "path-traversal attempt in custom GUI YAML load", "Lucene-syntax injection in Delivery API filter", "oversized placeholder expansion causing regex catastrophic backtracking").
7. **Per-issue verification checklist**: for each previously-patched issue, answer — Is it actually fixed? Is the fix bypassable? Is regression coverage now present? Could a variant still exist elsewhere?
8. **Deliverables**: `VERIFICATION_REPORT.md` with verdict (`PASS` / `PASS WITH RISKS` / `FAIL`), commands executed, checks passed/failed, new tests added, vulnerabilities verified fixed, regressions found and resolved, residual risks / deferred items; `TEST_RESULTS_SUMMARY.json`; committed regression tests.
9. **Verdict rules**: if any Critical or High remains exploitable → `FAIL`; if fixes lack regression coverage → add tests before finishing; if a patch works but is fragile → say so explicitly.

---

## QUALITY SELF-CHECK BEFORE RETURNING YOUR ANSWER

Before emitting the response, verify each of the three generated prompts passes these checks:

1. **Specificity test.** Could this prompt be copy-pasted onto a different project of the same category without modification? If yes → reject and rewrite with more real names (directories, classes, endpoints, commands, config files, integrations).
2. **Action-orientation test.** Does the prompt tell an agent what to do, or does it explain security concepts? The former is correct.
3. **Breadth + depth test.** Does it explicitly require variant hunting, root-cause analysis, and cross-repo grepping?
4. **Self-containment test.** If only Prompt 2 were given to an agent, would the agent have enough context to work correctly? (Each prompt must carry its own Context block.)
5. **Terminology fidelity test.** Does the prompt use the project's own words (composers, notifications, placeholders, property editors, hubs, managers) instead of generic synonyms (DI modules, event handlers, template variables, fields, real-time endpoints, services)?
6. **Docs anchoring test.** Are the official doc URLs listed in every Context block, not just the first one?
7. **Realistic adversary test.** Do the exploit scenarios reference actors and actions meaningful in the project's actual deployment (e.g. a "Subscriber-role node" in a load-balanced Umbraco cluster, a "kicked player rejoining via proxy" in a Minecraft plugin, a "malicious MCP server" in an agent system)?
8. **Scope compliance test.** If the project has a bug-bounty/VDP with scope rules, do the prompts forbid testing out-of-scope assets?

If any check fails, rewrite before emitting.

---

## OUTPUT FORMAT

Structure the final response exactly as:

```
# DISCOVERY

(Your Phase 1 output with all seven subsections, citing files and docs.)

# PROMPT 1 — AUDIT

(Full prompt text, ready to paste into a fresh LLM session.)

# PROMPT 2 — PATCH

(Full prompt text, ready to paste.)

# PROMPT 3 — VERIFICATION

(Full prompt text, ready to paste.)
```

No preamble. No postamble. No meta-commentary outside this structure.

---

## EXAMPLE OF INSUFFICIENT vs SUFFICIENT SPECIFICITY

To calibrate your output, here is the contrast you must respect:

**Insufficient (reject):**
> "Audit authentication flows. Check for token-handling issues, session weaknesses, and password reset flaws. Verify authorization boundaries."

**Sufficient (target this level):**
> "Audit OpenIddict reference-token issuance, Data Protection encryption settings, `__Host-` cookie prefix enforcement, and SameSite posture. Trace `BackOfficeSecurityStampValidator` re-validation interval and the notification handlers that rotate the stamp; enumerate `RevokeUserAuthenticationTokensNotificationHandler` wiring and identify which notifications actually revoke tokens. Confirm member vs backoffice-user realm isolation: distinct `IUserStore<T>`, distinct identity cookies, distinct `UserManager<T>`, no cross-realm token acceptance. Verify password reset and invite token providers use purpose strings, are single-use, and compare in constant time. Check `ExternalSignInAutoLinkOptions.AutoLinkExternalAccount` default is `false` and that no shipped template flips it. Audit login timing normalization (`TimedScope`) — verify it never early-cancels on the valid-password-but-not-allowed branch."

The second example is the minimum bar for every section of every generated prompt.

---

END OF META-PROMPT.
