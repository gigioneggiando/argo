# Prompt synthesis (Stage 2) — the archetype-driven prompt maker

Stage 2 is where a handful of reusable assets become a set of audit prompts tailored to one
specific target. It runs `00_recon_synthesis_meta_prompt.md` (the "meta-prompt" / prompt maker)
on the repo with **read-only** access and produces three machine-readable artifacts:

- `repo_profile.json` — structured recon (languages, frameworks, entry points, trust boundaries,
  untrusted-input sources, dangerous sinks, historical bug classes, `residual_unknowns`);
- `prompts/audit_*.md` — N complementary custom audit prompts, each conforming to
  `01_audit_prompt_template.md.j2`;
- `synthesis_notes.md` — why the audit was split this way, deprioritized surfaces, residual unknowns.

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
