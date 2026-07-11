# Prompt synthesis (Stage 2) — the archetype-driven prompt maker

Stage 2 is where a handful of reusable assets become a set of audit prompts tailored to one
specific target. It runs `00_recon_synthesis_meta_prompt.md` (the "meta-prompt" / prompt maker)
on the repo with **read-only** access and produces three machine-readable artifacts:

- `repo_profile.json` — structured recon (languages, frameworks, entry points, trust boundaries,
  untrusted-input sources, dangerous sinks, historical bug classes, `residual_unknowns`);
- `prompts/audit_*.md` — N complementary custom audit prompts, each conforming to
  `01_audit_prompt_template.md.j2`;
- `synthesis_notes.md` — why the audit was split this way, deprioritized surfaces, residual unknowns;
- `ground_truth.json` — the structured ground-truth pack (per-focus invariants, baseline-correct
  references, variant families, FP carve-outs) — see below.

Default model: **Opus** (`config.DEFAULT_STAGE_MODELS["recon"]`). This stage is the highest
leverage in the pipeline — validation can only remove false positives, it cannot recover a bug a
weak recon never pointed the auditor at.

## Archetype-driven generation (the de-biasing)

The meta-prompt's **first** method step is to classify the target archetype, and everything
downstream inherits from it:

```
web app · HTTP/GraphQL API · CMS · plugin/extension/mod · library/SDK/framework ·
CLI/desktop · agent/LLM/MCP · mobile · data/ML pipeline · smart-contract · firmware · IaC
```

The classification then drives:

1. **Entry-point reconstruction** — HTTP routes for web/API, command & event handlers and
   inter-instance protocols for plugins, public functions & insecure defaults for libraries, tool
   definitions & prompt assembly for agents, intents/deeplinks for mobile, etc.
2. **Untrusted-input + sink mapping** — a general security checklist (request/query/header,
   deserialization, SSRF, path traversal, sensitive-data exposure, …) **plus** the sources and
   sinks characteristic of the archetype, in the project's own terminology.
3. **The prompt split** — instead of a fixed "web/CMS/API" partition, the meta-prompt carries a
   *reference split per archetype* (e.g. plugin → architecture & host-integration ·
   permission/command exposure · untrusted-input/deserialization/cross-instance protocol). The
   model adapts the names and content to the real code; it always keeps one architecture-led,
   whole-system prompt that correlates exploit chains.

The general web-security toolkit (SSRF, IDOR, injection) is kept and applied **where it fits**
(a Minecraft plugin still has SSRF via player-name-in-URL and IDOR on moderation lookups) — it is
a toolkit, not a straitjacket. The change was about *adding* archetype lenses, not removing the
general checklist.

## Ground-truth extraction (the depth + precision lever)

The decisive difference between a generic prompt and one that finds the long tail is **how much
ground truth recon has already established by reading the code**. METHOD step 8 of the meta-prompt
makes recon do the enumeration work up front and bake it into both the audit-prompt prose and
`ground_truth.json`, per focus:

- **Invariants** — `location → expected → how-to-check` triples (e.g. *"`HasValidApiKey` MUST use a
  constant-time compare"*). The audit turns these into a PASS/FAIL checklist instead of open-ended
  hunting.
- **Baseline-correct references** — for each *systemic* pattern, the one place the code does it
  right (e.g. *"`MoveDocumentController` authorizes both source and destination"*). Every sibling is
  diffed against it — the most precise way to find variant bugs.
- **Variant families** — the repeated shapes (controller-per-operation, converter-per-type, …) with
  their **concrete enumerated member list**, so the audit verifies *each* member, not just the first.
- **False-positive carve-outs** — target-specific "do not flag" rules with justifications. These
  raise precision in the audit **and are passed to the validator** (`stages/validate._format_ground_truth`)
  so it does not re-derive them and wrongly refute a real finding.

These map to required sections in `01_audit_prompt_template.md.j2` (INVARIANT CHECKLIST,
BASELINE-CORRECT REFERENCES, VARIANT FAMILIES, FALSE-POSITIVE CARVE-OUTS) plus a mandated
`VARIANT_HUNT_LOG` deliverable (one row per family member, verdict 🟢/🟡/🔴) as a coverage
forcing-function. Recon emits a non-fatal warning (`recon._warn_shallow_prompts`) if a generated
prompt is missing any of the four — a regression-to-generic signal.

## Mandatory coverage checklist (recall + anti-drop)

The archetype-keyed vuln index (`data/vuln_index.yaml`, via `knowledge.format_for_prompt`) is injected
into recon as **advisory** reference. That is necessary but not sufficient: a recon model can still fail
to propagate a lens into the prompts it emits. A real run showed exactly this — the audit foci were
transport / framing / services, and it missed a 32-bit-truncated MAC and a zero-default HMAC key because
no focus reviewed the crypto *primitives*, and it under-rated real crypto/protocol weaknesses that were
then dropped from the shortlist. Two mechanisms close that gap:

- **Deterministic per-prompt coverage checklist** (`checklists.ensure_coverage_checklist_present`,
  injected by recon right after the design-context block, mirroring `ensure_prohibited_present`). Gated
  on cheap repo signals (`detect_native`, `detect_crypto`, `detect_free_then_reparse`), it appends a `## MANDATORY COVERAGE
  CHECKLIST` to **every** audit prompt with: a **variant-family CENSUS** rule (always — the #1 recall
  miss is reporting one instance of an enumerable class and moving on, so census EVERY member: every
  untrusted-driven collection, every OS sink, every panic point, every URL fetch); an always-on
  **resource-exhaustion / availability** lens (CWE-400/770); a **secrets-in-sinks** lens (CWE-532 —
  credentials into logs/telemetry/errors); an **outbound-request / SSRF** lens (CWE-918/601 — destination
  validation + per-hop redirect re-validation + zero-click); a **memory-safety** lens for native code
  (CWE-787/125/…) OR, for memory-safe languages, a **panic/abort census** (CWE-248/617 — every
  `unwrap`/`expect`/index/overflow/`unreachable!`/busy-loop reachable from untrusted input, plus every
  `unsafe`/FFI escape hatch). The native memory-safety lens also names the **free-then-reparse /
  free-then-reuse-without-nulling** double-free idiom (CWE-415/416 — `free(obj->field)` then a
  `parse_into(&obj->field)` whose failing path leaves the freed pointer live for a later second free,
  plus the `bool f(…, T *out)` helper that returns false without writing `*out`); when a deterministic
  pre-scan (`detect_free_then_reparse` — a `free(x)` shortly followed by `&x` with no `x = NULL` in
  between) actually hits in the target, a HIGH-SIGNAL callout is escalated into that lens. This idiom
  lens was added after the ds4 cross-check, where all-but-one audit pass missed a `free(r->model)` /
  `json_string(&r->model)` double-free Critical. A **crypto-primitive** lens when crypto is present; and the
  **one-finding-per-root-cause** rule (P1); an always-on **insecure-defaults / fail-open** lens
  (CWE-1188/453/636/306/862 — enumerate every security-relevant default and ask whether it fails OPEN:
  a configured-but-failed authenticator/authorizer/TLS component that silently falls back to
  allow-all/accept-all/plaintext instead of failing closed, a default-open control API / metrics / pprof
  under a non-default auth mode, or a surprising anonymous/allow-all default). The census + panic lens
  were added after two cross-checks (libcsp, halloy) showed Argo finds the *theme* but under-enumerates
  *variant families*; the fail-open lens was added after the moquette (fail-open on auth-class load) and
  mediamtx (default `authHTTPExclude` leaving the control API unauthenticated) cross-checks, where the
  blind second-opinion caught insecure-default gaps Argo's audit missed.
- **Severity symmetry** in the design-context block (`rendering.design_context_block`, P2): the
  counterpart to the anti-over-claim rule — a finding that *defeats a security mechanism the project
  itself ships* (auth, MAC, crypto, security-RNG, replay, access control) is rated by the property it
  breaks, and must NOT be downgraded to "informational hardening" just because exploitation needs
  on-path access or a partial trust model.
- **Niche/opt-in component severity** in the design-context block (added after the Rebus cross-check):
  a carve-out noting a component is documented as dev/test-only or uncommonly deployed answers
  *whether to report* a finding, not *how severe it is* once wire-reachability and impact are
  confirmed — "how commonly is this chosen" and "how bad is it once chosen" are different axes.
  Without this, validate discounted a fully wire-reachable arbitrary-file-write / cross-instance
  message-forgery finding (`FileSystemTransport`) to Medium purely because the transport itself is
  niche, even though its own write-up had already proven full reachability and impact.
- **Config/deser→exec is a finding, not by-design** in the design-context block (added after the legba
  cross-check): the "purpose-is-the-feature" carve-out covers only the OPERATOR directly invoking an
  exec/command/eval feature through its intended channel — NOT the same capability reached silently via
  a DATA artifact the design doesn't imply is executable (a shareable recipe/config/template, or a
  DESERIALIZED saved-state file that reconstructs the feature). This closed a real miss: Argo's validate
  repeatedly DROPPED legba's recipe→`cmd`-plugin RCE as out_of_scope ("the tool runs commands anyway")
  while two independent second-opinion runs kept it — loading a shareable recipe that silently runs a
  command is a config→exec trust-boundary crossing, distinct from the operator typing `--plugin cmd`.
- **Substitute-then-parse dual-failure census** in the coverage checklist (added after the legba
  cross-check): at any sink that string-substitutes untrusted input into a command/argv/query/path
  template and THEN parses/splits it, census BOTH the INJECTION (the value crosses a token boundary
  because substitution preceded tokenization) AND the PANIC (the post-substitution split is
  `unwrap()`ed). Argo's legba audit caught only the `shell_words::split().unwrap()` panic and missed the
  argument-injection at the same site.
- **Recon scope-completeness census** in `00_recon_synthesis_meta_prompt.md` (added after the Rebus
  cross-check): before finalizing the audit-focus split, recon must confirm every top-level in-scope
  directory/module is assigned to at least one focus, and flag modules that compose with another
  in-scope feature (e.g. an audit/logging step running inside the same pipeline as encryption) as
  likely sites for a cross-feature defect. This closed a real miss: an independent second-opinion
  scan on Rebus found that message auditing silently forwards decrypted plaintext when both
  `EnableEncryption` and `EnableMessageAuditing` are configured — `Rebus/Auditing/` had never been
  assigned to any of Argo's 4 audit foci in the first place.

The vuln index itself was also strengthened for native/protocol targets: a new `firmware` archetype
section (memory-safety, protocol-state, management-surface, weak-RNG, exhaustion) and expanded
`library_sdk` crypto/memory entries, plus a resource-exhaustion class in `general`.

## Quality controls inside the meta-prompt

- **Each generated prompt must name the archetype** in its Context and warn the auditor not to
  treat a non-web target as a generic web/CRUD app.
- **A specificity self-check** runs before the prompts are emitted (5 tests): could this be pasted
  onto another project of the same archetype unchanged? does it use the project's own terms? does
  it fit the archetype? does every surface cite a real file/path with scope + prohibited
  techniques verbatim? are exploit scenarios written in the deployment's terms?
- **A calibration example** (archetype-neutral) shows the required level: vague "audit
  authorization" vs. "enumerate every command whose `getPermission()` returns null in
  `server/command/**` …".

## Guardrail interaction

The orchestrator independently re-verifies every generated prompt before it drives an audit
session (`guardrails.assert_audit_prompt_wellformed`): it must carry the template's RoE sections,
the prohibited techniques **verbatim**, the per-finding format, and "Do NOT patch". A prompt that
loses these fails the run. So the meta-prompt's freedom to tailor content never lets it drop a
safety constraint. See [guardrails.md](guardrails.md).

## Relationship to `META_PROMPT_generator.md` (archived under [legacy/](legacy/))

[`legacy/META_PROMPT_generator.md`](legacy/META_PROMPT_generator.md) is an earlier, standalone
copy-paste meta-prompt (a two-phase
DISCOVERY → AUDIT/PATCH/VERIFY generator for a human to paste into an LLM). The Stage-2 meta-prompt
**harvested its best ideas**, adapted to this pipeline:

| Reused | Why |
|---|---|
| Explicit project-archetype taxonomy | the core de-biasing — classify first, adapt everything |
| Per-archetype vulnerability classes / reference splits | replaces the single web-default split |
| The specificity self-check + insufficient-vs-sufficient calibration | raises the floor for weaker models |
| "Warn against treating it as a generic web app" | propagated into every generated prompt |

| **Not** reused | Why not |
|---|---|
| The PATCH and VERIFY prompts | the pipeline is **detection-only** — patching is a hard guardrail violation, and VERIFY assumes a patched branch + builds/tests the pipeline never runs |
| "Use web browsing for CVE history" | the recon session has **no network tools** (guardrail); it uses the injected `reference_links` + model knowledge, and marks gaps as residual unknowns |
| The standalone copy-paste framing | Stage 2 is an orchestrated step with machine-readable outputs (`repo_profile.json` + template-conforming prompts) |

The legacy file is archived under `docs/legacy/` as a reference / idea source; nothing imports it
at runtime.

## Changing the meta-prompt safely (validation methodology)

The Stage-2 output is already near-professional on the default (Opus) path, so the risk of any
edit is **regression**. Validate every meta-prompt change against a baseline before trusting it:

1. Keep a known-good run as the **baseline** (e.g. `runs/<program>/<id>/`).
2. After editing `00_…`, **re-sync it into `argo/prompts/`** (the pipeline loads the asset from
   there, not from the repo root).
3. Run **`pipeline --dry-run`** on the same target reusing the baseline repo copy as `--repo`
   (ingest + recon only, no audit — a few dollars of Opus recon, no audit/validation spend):
   ```bash
   python -m argo.cli pipeline --dry-run \
     --brief <program>/brief.md --repo runs/<program>/<id>/repo \
     --links <program>/links.txt --runs-dir _validate --run NEW
   ```
4. **Diff** the new `repo_profile.json`, `prompts/audit_*.md`, and `synthesis_notes.md` against the
   baseline. Keep the change only if quality holds or improves; revert otherwise.

> Note: two Opus recon runs on the same repo differ (model nondeterminism), so judge by
> **structural** signals (archetype classified, split fit, file:line citation density, explicit
> handling of out-of-scope/absent modules), not by exact per-term coverage in a single run.

### Worked example (the archetype change)

Validating the archetype-driven rewrite against the ChatPlugin baseline (a Minecraft plugin)
showed: an explicit `## Archetype classification` section (absent before), a more plugin-native
split (`architecture-proxy-protocol` / `permission-command-dispatch` /
`untrusted-input-storage-integrations`), **+17 `file.java:NN` citations** in the prompts (vs 0),
and explicit in-prompt handling of the absent `premium` module — with no structural regression.
One secondary surface (the `Debugger`/`@SensitiveData` secret-leak) was less prominent in that
single run (model variance), which motivated adding "sensitive-data exposure" to the general sink
list to lift recall of that whole class.
