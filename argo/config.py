"""Central configuration: model assignment, tool allowlists, budgets, paths.

Everything tunable lives here so the guardrails and stages read from a single source.
Per-stage models are overridable at runtime (CLI flags / ``PipelineConfig`` overrides);
``audit`` is the headline knob because the audit model sets the missed-bug (false-negative)
rate — the validation stage can only remove false positives, never recover a bug the audit
model failed to surface.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, fields, replace
from pathlib import Path

# --- Model IDs (the most capable current Claude models) -----------------------------
OPUS = "claude-opus-5"
SONNET = "claude-sonnet-5"
HAIKU = "claude-haiku-4-5-20251001"  # cheapest; used for the headless smoke run

# --- Model IDs (Gemini CLI backend). Pinned concrete ids, never the auto-resolving
# "pro"/"flash" aliases: an alias breaks MODEL_PRICING's substring match, run-to-run
# reproducibility, and (confirmed empirically against gemini-cli v0.49.0) can trigger an
# extra internal "which model should handle this" routing call that a pinned id skips
# entirely. Re-confirm these strings periodically -- preview ids churn; there is no
# `--list-models` flag, these were read directly off real `stats.models` keys.
GEMINI_PRO = "gemini-3.1-pro"
GEMINI_FLASH = "gemini-3.5-flash"
GEMINI_FLASH_LITE = "gemini-3.1-flash-lite"  # cheapest; used for the Gemini smoke run

# --- Model IDs (Codex CLI backend), for the two cases that need a PINNED id rather than
# "omit codex_model and let the CLI's own configured default apply" (the normal, recommended
# path -- see docs/backends.md): calibrated() (a controlled top-tier run) and the cross-backend
# benchmark's --tier flag (a controlled, reproducible comparison point). Unlike Claude/Gemini,
# Codex has no per-stage tiering (model_for() uses one flat codex_model for every stage), so
# these are the only two named tiers needed.
CODEX_TOP = "gpt-5-codex"      # Codex's own coding-focused top model; priced same as gpt-5/gpt-5.5
CODEX_CHEAP = "o4-mini"        # a real lighter/cheaper OpenAI model, mirrors Haiku/Flash-Lite's role

#: Default per-stage model assignment.
#:  * ingest   -> Sonnet (never Haiku: misreading scope/RoE has outsized consequences).
#:  * recon    -> Opus   (judgment-heavy synthesis, low volume).
#:  * audit    -> Sonnet (high-volume parallel fan-out; flip to Opus for high-value targets
#:                        or during prompt calibration via --calibration / --audit-model).
#:  * validate -> Opus   (adversarial confutation; the lever on accepted-report rate).
#:  * report   -> deterministic code assembly (no LLM by default).
DEFAULT_STAGE_MODELS: dict[str, str] = {
    "ingest": SONNET,
    "recon": OPUS,
    "audit": SONNET,
    "validate": OPUS,
    "report": SONNET,  # only used if report LLM-polish is ever enabled; off by default.
    "chat": SONNET,    # interactive post-run analysis (explain / why-not-found / test-gen)
    "remediate": OPUS, # Phase-6 fix generation (proposed patch per confirmed finding)
    "research": SONNET, # opt-out Stage-0 web OSINT / threat intel (feeds recon)
    "sca": OPUS,        # dependency / software-composition analysis (manifest -> known-vuln deps)
    "runtime": SONNET,  # R2: propose loopback probe plans + interpret results (offline, validated)
    "live": SONNET,     # L2: propose in-scope live probe plans + interpret results (offline, validated)
    "corroborate": SONNET,  # post-validation cross-check vs project docs + repo VCS history (networked)
    "verify": OPUS,     # deep re-derivation: unbounded, full repo access, cross-finding aware (opt-in)
    "asan_poc": OPUS,   # single-shot, precision-critical harness authoring (opt-in, C/C++ only)
}

#: Default per-stage model assignment for the Gemini backend. Same placement rationale as
#: DEFAULT_STAGE_MODELS above (Pro for judgment-heavy/low-volume stages, Flash for high-volume
#: fan-out) -- Gemini's pro/flash tier genuinely maps onto that split, unlike Codex's flat model.
DEFAULT_GEMINI_STAGE_MODELS: dict[str, str] = {
    "ingest": GEMINI_FLASH,
    "recon": GEMINI_PRO,
    "audit": GEMINI_FLASH,
    "validate": GEMINI_PRO,
    "report": GEMINI_FLASH,
    "chat": GEMINI_FLASH,
    "remediate": GEMINI_PRO,
    "research": GEMINI_FLASH,
    "sca": GEMINI_PRO,
    "runtime": GEMINI_FLASH,
    "live": GEMINI_FLASH,
    "corroborate": GEMINI_FLASH,
    "verify": GEMINI_PRO,
    "asan_poc": GEMINI_PRO,
}

#: Default per-stage wall-clock overrides (seconds). Recon now does deep ground-truth extraction
#: (enumerating variant families, baseline-correct refs, invariants across the whole tree) and the
#: audit walks every family member — both want more headroom than the 1800s global default. The
#: completeness-critic re-pass (audit) also runs inside the audit stage budget.
DEFAULT_STAGE_TIMEOUTS: dict[str, int] = {
    "recon": 3600,
    "audit": 3600,
    "verify": 3600,  # unbounded per-finding re-derivation; give it the same headroom as audit/recon
    "asan_poc": 3600,  # full read-only repo access to isolate one function; same headroom as verify
}

# --- Cost estimation for backends that report tokens but not USD ---------------------
# Claude Code returns an authoritative ``total_cost_usd`` per call. The Codex CLI (OpenAI / OSS)
# and the Gemini CLI report tokens, not dollars, so for both we ESTIMATE: tokens x this rough price
# table. Figures are USD per 1M tokens (input, output); used only for the budget guard + cost
# analytics, never billed. Unknown models (incl. ``--oss`` / local) estimate to $0 — tokens are
# still logged. Gemini figures confirmed 2026-08-17 from ai.google.dev/gemini-api/docs/pricing
# (standard tier, <=200k-token prompts; Pro steps up to $4/$18 above 200k -- not modeled here,
# estimate_cost_usd doesn't take a prompt-size argument, so very large Pro-tier prompts undercount
# slightly rather than justify a tiered lookup for a rare case).
MODEL_PRICING: dict[str, tuple[float, float]] = {
    "gpt-5.5": (1.25, 10.0), "gpt-5-codex": (1.25, 10.0), "gpt-5": (1.25, 10.0),
    "gpt-4o": (2.5, 10.0), "gpt-4.1": (2.0, 8.0), "o4-mini": (1.1, 4.4), "o3": (2.0, 8.0),
    GEMINI_PRO: (2.00, 12.00), GEMINI_FLASH: (1.50, 9.00), GEMINI_FLASH_LITE: (0.25, 1.50),
}


def _codex_default_model() -> str | None:
    """The Codex CLI's configured default model (``model =`` in ~/.codex/config.toml), so a Codex
    run that doesn't pin a model still logs/estimates the *real* model. Best-effort, never raises."""
    try:
        import tomllib
        p = Path.home() / ".codex" / "config.toml"
        if p.exists():
            m = tomllib.loads(p.read_text(encoding="utf-8")).get("model")
            return m.strip() if isinstance(m, str) and m.strip() else None
    except Exception:
        return None
    return None


def estimate_cost_usd(model: str | None, input_tokens: int, output_tokens: int) -> float:
    """Best-effort USD estimate from token counts (for token-only backends). $0 if the model is
    unknown or local/OSS — tokens are still recorded."""
    if not model:
        return 0.0
    m = model.lower()
    for key, (in_rate, out_rate) in MODEL_PRICING.items():
        if key in m:
            return (input_tokens * in_rate + output_tokens * out_rate) / 1_000_000
    return 0.0


# --- Tool allowlists (defense-in-depth; the runner re-enforces these) ----------------
#: Tools that can reach the network or spawn sub-agents. NEVER allowed in any session —
#: this is the structural guarantee that no stage can touch a live host.
NETWORK_TOOLS: frozenset[str] = frozenset(
    {"Bash", "WebFetch", "WebSearch", "Task", "Agent", "BashOutput", "KillShell"}
)
#: Tools that mutate files. Never allowed: the pipeline never patches the target.
MUTATION_TOOLS: frozenset[str] = frozenset({"Edit", "MultiEdit", "NotebookEdit"})

#: Read-only analysis tools (repo inspection, no writes anywhere).
READ_ONLY_TOOLS: tuple[str, ...] = ("Read", "Grep", "Glob")
#: Read-only analysis + Write (scoped to the session's writable scratch cwd, never the
#: read-only repo). Used by stages whose model must emit artifact files.
ARTIFACT_TOOLS: tuple[str, ...] = ("Read", "Grep", "Glob", "Write")

#: OSINT subset of the network tools: read-only public web access (search + fetch), NO shell,
#: NO sub-agents. Permitted ONLY in the opt-out ``research`` stage (see guardrails), which never
#: receives the repo and is forbidden the program's live in-scope target hosts.
OSINT_TOOLS: frozenset[str] = frozenset({"WebSearch", "WebFetch"})
#: The research stage's allowlist: public web OSINT + Write to its scratch dir. No repo, no shell.
RESEARCH_TOOLS: tuple[str, ...] = ("WebSearch", "WebFetch", "Read", "Write")

#: Tools explicitly disallowed on every session (passed to --disallowedTools).
ALWAYS_DISALLOWED: tuple[str, ...] = tuple(sorted(NETWORK_TOOLS | MUTATION_TOOLS))


@dataclass(frozen=True)
class PipelineConfig:
    """Immutable run configuration. Use :meth:`with_overrides` to derive a variant."""

    # Model assignment per stage.
    stage_models: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_STAGE_MODELS))
    # Gemini backend's own per-stage assignment (Gemini is tiered like Claude, not flat like Codex —
    # see DEFAULT_GEMINI_STAGE_MODELS). Only consulted when runner == "gemini".
    gemini_stage_models: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_GEMINI_STAGE_MODELS))

    # Execution.
    runner: str = "headless"            # "headless" (Claude Code) | "codex" (Codex CLI) | "gemini" (Gemini CLI) | "mock"
    # Resilience: ordered fallback backends. When the primary runner hits a retryable limit
    # (session-limit / rate-limit / 429), the same call is transparently retried on the next backend
    # (e.g. ["codex"] => Claude -> Codex). A walled backend is skipped for the rest of the run.
    runner_fallbacks: list[str] = field(default_factory=list)
    # Multi-account Claude: CLAUDE_CONFIG_DIR for THIS headless runner (selects which logged-in
    # account it uses). ``claude_accounts`` is an ordered list of such dirs — the headless backend
    # becomes an account-fallback chain (limits are PER-ACCOUNT, so account A -> account B doubles
    # capacity before falling through to runner_fallbacks). Set up each dir once with
    # ``CLAUDE_CONFIG_DIR=<dir> claude login``.
    claude_config_dir: str | None = None
    claude_accounts: list[str] = field(default_factory=list)
    # Multi-account Codex: same idea via CODEX_HOME (default ~/.codex). ``codex_accounts`` is an
    # ordered list of CODEX_HOME dirs -> the codex backend becomes an account-fallback chain.
    codex_home: str | None = None
    codex_accounts: list[str] = field(default_factory=list)
    # Multi-account Gemini: unlike Claude/Codex's directory-based accounts, Gemini's practical
    # automation-auth lever is the GEMINI_API_KEY env var, so ``gemini_accounts`` holds ordered KEY
    # VALUES (not directory paths) -- a deliberate deviation from the Claude/Codex pattern, not an
    # inconsistency. These are real secrets (the credential lives IN the value, not on disk outside
    # Argo's state) -- see _SECRET_FIELDS below, which redacts both from runs/<id>/config.json.
    gemini_api_key: str | None = None
    gemini_accounts: list[str] = field(default_factory=list)
    max_parallel_audits: int = 3        # concurrency cap for Stage 3 / Stage 4 fan-out
    # Efficiency: validate/corroborate historically span ONE session per finding, which is ~90% of a
    # run's sessions and the main driver of rate-limit exhaustion. Batching groups N findings into a
    # single session that judges each INDEPENDENTLY (no precision loss — same model, same adversarial
    # rules), cutting session count ~Nx. 1 = the legacy per-finding path (kept for chat/B1 re-validate).
    validate_batch_size: int = 8        # findings per adversarial-validation session
    corroborate_batch_size: int = 8     # findings per corroboration session
    # Cross-focus semantic dedup (Stage 4, before the adversarial fan-out): structural dedup
    # (validate._merge) only collapses EXACT (file, line, cwe) matches, so the same root-cause bug
    # reported by two different audit foci at two different call sites survives as two findings (seen
    # on gguf-tools: a single "general.alignment=0 -> div-by-zero" bug reported 3x from 3 foci, each
    # citing a different exact line). One extra cheap batched session clusters near-duplicates by
    # meaning (title + explanation), not just by exact line — before the MUCH more expensive per-
    # finding validate/corroborate fan-out. Skipped below the finding-count floor (not worth a session
    # for a handful of findings); fails open (keeps every finding separate) on any error.
    semantic_dedup_enabled: bool = True
    semantic_dedup_min_findings: int = 6

    # Codex backend (runner == "codex"). One model for all stages (Codex isn't tiered per stage
    # the way Claude is). codex_model=None lets the Codex CLI use its own configured default model.
    codex_model: str | None = None
    codex_oss: bool = False             # use Codex's open-source provider (--oss)
    codex_local_provider: str | None = None  # "ollama" | "lmstudio" (with --oss)
    session_timeout_s: int = 1800       # default per-session wall-clock cap (seconds)
    # per-stage wall-clock overrides; seeded with DEFAULT_STAGE_TIMEOUTS (deep recon + audit).
    stage_timeouts: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_STAGE_TIMEOUTS))
    budget_usd: float | None = None     # HARD per-run USD ceiling; None = unbounded

    # Per-session safety caps (this CLI has NO --max-turns flag in v2.1.178):
    #   * cost is capped mid-session natively via --max-budget-usd (see runner),
    #   * turns are a post-hoc tripwire enforced by the orchestrator (cannot pre-empt).
    session_max_cost_usd: float | None = None   # per-session cost cap (also -> --max-budget-usd)
    session_max_turns: int | None = None        # per-session turn tripwire; None = off
    max_focuses: int | None = None              # cap audit fan-out to first N focuses (smoke)
    # Completeness-critic re-passes per focus (Phase-3 depth lever): after a focus's first audit
    # session, re-invoke it to find what was MISSED — uncovered variant-family members, unverified
    # invariants, 🟡 rows not promoted. Each pass appends only NEW findings; passes stop early when
    # a pass yields nothing new (loop-until-dry, capped). 0 disables. Trades tokens for recall.
    audit_critic_passes: int = 1
    # Software-composition analysis: read dependency manifests and flag pinned versions with known
    # advisories. Emits a synthetic `dependencies` focus that joins the normal validate+report flow.
    sca_enabled: bool = True

    # Stage-0 web OSINT / threat intel before recon. Historically this was passed as a separate
    # run_pipeline argument; keeping it in the persisted config makes resume reconstruct the original
    # stage set instead of guessing whether the run was started with --research or --no-research.
    research_enabled: bool = True

    # --- Second opinion (opt-in; runs AFTER audit/[sca], BEFORE validate) --------------------------
    # OFF by default (0 = disabled). N >= 1 runs N ADDITIONAL, fully independent recon+audit passes
    # over the same already-ingested scope/repo, then merges their raw findings into the primary's
    # findings_dir before validate runs. Encodes the manual "blind second opinion" methodology used
    # on fastjson2/open62541: a single audit pass is one noisy sample of what a careful reader would
    # find; an independent second pass (ideally on a different backend via second_opinion_backend,
    # for real diversity rather than just re-sampling the same model) both recovers findings the
    # first pass missed and, when it independently converges on the same bug, produces a real
    # corroboration signal no single pass can produce alone. See stages/second_opinion.py.
    second_opinion_passes: int = 0
    # Runner override for the second-opinion passes only (e.g. "headless" when the primary run used
    # "codex", for genuine cross-engine diversity rather than just re-sampling the same model). None
    # = same backend as the primary.
    second_opinion_backend: str | None = None

    # --- Corroboration (opt-out, networked; runs AFTER validate, BEFORE runtime/live) -------------
    # ON by default. For each surviving finding, cross-checks it against the project's own DOCS and
    # the source repo's VCS HISTORY (commits / releases / advisories) over public web OSINT, to
    # CONFIRM or DISCARD it: a finding the docs describe as intended -> downgraded to design_accepted;
    # one already patched in a newer commit -> moved to fixed_upstream (kept in an appendix, never
    # silently deleted). Best-effort: a failure never fails the run. Uses the same scope forbidden-
    # live-hosts rail as research (repo host + docs are public OSINT; live in-scope hosts are not).
    corroborate_enabled: bool = True
    # Curated documentation URLs to ground the cross-check (additive to the scope's reference_links +
    # source repo). If empty, the stage searches the web for the project's official docs + repo.
    doc_links: list[str] = field(default_factory=list)
    corroborate_max_searches: int = 8   # soft cap on web searches per finding (in-prompt guidance)

    # --- Deep verify (opt-in, offline, full repo access; runs AFTER corroborate, BEFORE runtime/live) --
    # OFF by default (the most expensive annotation stage: unbounded reasoning, one full agentic
    # session per finding, never batched). Where validate is a cheap, deliberately finding-ISOLATED
    # adversarial pass and corroborate is a networked docs/history cross-check, deep-verify is the
    # final, deepest, most skeptical pass: independently RE-DERIVE each surviving finding from the
    # actual source (not the excerpt) with full Read/Grep/Glob access, and reason ACROSS the whole
    # survivor set so it can catch what per-finding isolation structurally cannot — one finding that
    # is actually N distinct bugs (split), two findings that are the same root cause (merged), or a
    # finding whose mechanism is real but a factual detail is wrong (corrected). Modeled on the
    # standard of manual re-verification used before a disclosure ships: read every cited line, trace
    # every sibling function, and show the work. See docs/deep-verify.md.
    verify_enabled: bool = False
    # Hard cap on how many survivors get a deep-verify session (cost control on a huge survivor set);
    # None = verify every survivor. Findings past the cap are left unverified (kept, never dropped).
    verify_max_findings: int | None = None
    # Retries per finding on a transient session failure (CLI/sandbox crash, no output produced,
    # malformed JSON) before falling back to `inconclusive`. Default 2 (1 retry): unlike validate/
    # corroborate's cheap per-session cost, a verify session runs unbounded with no excerpt budget
    # (seen for real: 1-4M input tokens, $1-4 per session) - worth one retry before giving up on a
    # crash. 1 = no retry (legacy/cheap behavior).
    verify_max_attempts: int = 2
    # Explicit finding-id scope for this invocation (mirrors `fix --only`). None = the default,
    # resumable behavior: findings that already carry a real (non-infra-failure) verification are
    # left untouched and only findings with no verification yet, or an infra-failure `inconclusive`
    # from a prior interrupted run, get a session. When set, exactly these ids get a (re-)session
    # regardless of their current state, and every other survivor is left completely untouched -
    # for deliberately re-verifying specific findings without re-spending on the rest.
    verify_only: frozenset[str] | None = None

    # --- Freshness check (opt-in, networked git history check; informational only) -----------------
    # OFF by default. Late in the pipeline, check whether cited files were touched on the audited
    # branch after the pinned commit or on version-looking sibling release/maintenance branches.
    # This never proves a finding is fixed and never changes/drops findings; it only adds a
    # "verify before sending" flag for human review. Best-effort: no git/network/origin -> skip.
    freshness_check_enabled: bool = False
    freshness_lookback_days: int = 365

    # --- Runtime verification (opt-in, sandboxed; see docs/runtime-verification-study.md) ---------
    # OFF by default. When on, build the OSS target from the cloned source into an EPHEMERAL,
    # EGRESS-BLOCKED (--network=none), LOOPBACK-ONLY container and probe ONLY that local instance to
    # confirm/refute findings with HTTP-level PoCs. NEVER touches the program's live in-scope hosts.
    runtime_enabled: bool = False
    runtime_image: str | None = None        # docker image that contains/builds the runnable app
    runtime_run_cmd: str | None = None      # command (in-container) that starts the app on the port
    runtime_build_cmd: str | None = None    # optional in-container build step before run
    runtime_port: int = 8080                # in-container loopback port the app listens on
    runtime_boot_timeout_s: int = 180       # max wait for the app to come up on 127.0.0.1:port
    runtime_request_timeout_s: int = 10     # per-probe HTTP timeout
    runtime_max_requests: int = 50          # hard cap on total probe requests (anti-DoS)
    runtime_min_request_interval_s: float = 0.2   # rate cap between probes (anti-DoS)
    runtime_max_payload_bytes: int = 8192   # cap request body size (anti-DoS)
    runtime_allow_state_changing: bool = False    # default: read-only probes (GET/HEAD/OPTIONS)

    # --- ASan PoC generation (opt-in, sandboxed, C/C++ only) ---------------------------------------
    # OFF by default. When on, runs AFTER verify (or validate if verify is off): for each surviving
    # memory-safety finding on a C/C++ file, an offline LLM session writes a MINIMAL, single-
    # translation-unit harness that #includes the real vulnerable source directly (never
    # reimplements it), then a FIXED (non-model) step compiles it with
    # `clang -fsanitize=address,undefined` and runs it inside an egress-blocked (--network=none)
    # Docker container. A real ASan crash trace is the most credibility-boosting artifact a
    # disclosure can carry, and was the single most time-consuming manual step across every C/C++
    # campaign so far. V1 is deliberately narrow (see docs/architecture.md): no attempt to drive an
    # arbitrary third-party CMake/Autotools/Meson build — only the single-file-compile case, which
    # covers the common shape of a parser/decoder/buffer-handling memory-safety bug. Anything outside
    # that (can't isolate the function, non-C/C++ finding, no Docker) degrades to an honest, logged
    # skip per finding — never a silent failure, and NEVER refutes the finding itself.
    asan_poc_enabled: bool = False
    asan_poc_image: str = "silkeh/clang"       # a small image with clang + libc dev headers
    asan_poc_max_findings: int | None = None   # cap how many survivors get a harness (cost control)
    asan_poc_compile_timeout_s: int = 60
    asan_poc_run_timeout_s: int = 30

    # --- LIVE testing of in-scope hosts (opt-in, heavily gated; see docs ⚠️ WARNING) -------------
    # OFF by default. When on, a FIXED executor makes BOUNDED, IN-SCOPE-ONLY, read-only HTTP requests
    # to the program's live in-scope assets (scope-locked + RoE-gated + capped + fully audit-logged).
    # NEVER touches out-of-scope or non-in-scope hosts. Authorized-use only (your responsibility).
    live_enabled: bool = False
    live_allow_writes: bool = False                # default read-only (GET/HEAD/OPTIONS); writes = 2nd opt-in
    live_max_writes: int = 5                        # L3: separate cap on state-changing reqs (DELETE always blocked)
    live_max_requests: int = 30                    # hard total cap (anti-DoS)
    live_min_request_interval_s: float = 1.0       # rate cap between live requests (anti-DoS)
    live_request_timeout_s: int = 15               # per-request timeout
    live_max_payload_bytes: int = 4096             # cap request body size
    live_max_retries: int = 2                       # retry transient errors (timeout/conn/5xx/429) — idempotent reqs ONLY
    live_max_redirects: int = 3                     # follow at most N redirects (idempotent only), each re-validated in-scope
    live_user_agent: str = "Argo-live/1.0 (authorized security testing)"  # identifies the tool to the target

    # "Produced by Argo" provenance footer on human-facing audit artifacts (REPORT.md, drafts) + an
    # attribution block in fixes_report.json. Default ON (same signature for every user); set False
    # (--no-attribution) to opt out. Attribution only — never changes any license.
    attribution: bool = True
    runtime_mount_source: bool = True   # mount the isolated source copy at /src:ro (build-at-run
                                        # model). Set False for a self-contained PRE-BUILT image.
    runtime_build_timeout_s: int = 1800  # R3: max seconds to docker-build a recipe/repo Dockerfile
    # R2-auth: optional credentials the LLM may use to script a login step so authz findings can be
    # runtime-confirmed (the probe runner keeps a per-finding cookie jar across the auth + probes).
    runtime_credentials: dict = field(default_factory=dict)   # e.g. {"username":..., "password":...}

    # Validation excerpt sizing.
    excerpt_context_lines: int = 40     # +/- lines of source around each cited file:line
    excerpt_max_bytes: int = 60_000     # hard cap on total excerpt bytes per finding

    # Paths.
    runs_dir: Path = Path("runs")
    prompts_dir: Path = Path(__file__).resolve().parent / "prompts"
    ledger_path: Path = Path(__file__).resolve().parent / "ledger.sqlite"

    # Mock runner fixtures (only used when runner == "mock").
    fixtures_dir: Path = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
    fixtures_scenario: str = "happy"

    def model_for(self, stage: str) -> str:
        # Codex uses one model for all stages (the label is for logging/cost; the runner passes the
        # real id via -m only when codex_model is set, else the Codex CLI's own default is used).
        if self.runner == "codex":
            return self.codex_model or _codex_default_model() or "codex-default"
        # Gemini is tiered per stage like Claude, via its own dict (see DEFAULT_GEMINI_STAGE_MODELS).
        if self.runner == "gemini":
            try:
                return self.gemini_stage_models[stage]
            except KeyError:  # pragma: no cover - defensive
                raise KeyError(f"No Gemini model configured for stage {stage!r}") from None
        try:
            return self.stage_models[stage]
        except KeyError:  # pragma: no cover - defensive
            raise KeyError(f"No model configured for stage {stage!r}") from None

    def timeout_for(self, stage: str) -> int:
        return self.stage_timeouts.get(stage, self.session_timeout_s)

    def with_overrides(self, **kwargs) -> "PipelineConfig":
        """Return a copy with the given top-level fields replaced."""
        return replace(self, **kwargs)

    def with_stage_model(self, stage: str, model: str) -> "PipelineConfig":
        if self.runner == "gemini":
            models = dict(self.gemini_stage_models)
            models[stage] = model
            return replace(self, gemini_stage_models=models)
        models = dict(self.stage_models)
        models[stage] = model
        return replace(self, stage_models=models)

    def calibrated(self) -> "PipelineConfig":
        """Calibration default: run the audit stage on the backend's top-tier model
        (effectively all-Opus / all-Pro / all-CODEX_TOP) so a weak prompt is never confounded
        with a weak model when diagnosing missed bugs.

        Codex fix (2026-08-17): this used to call with_stage_model("audit", OPUS) unconditionally,
        which is a NO-OP for Codex -- model_for() ignores stage_models entirely when
        runner=="codex" (it reads codex_model instead), so calibrated() silently did nothing for a
        Codex run. Caught while building the cross-backend benchmark, whose --tier top mode
        depends on calibrated() actually working per backend to be a fair comparison."""
        if self.runner == "gemini":
            return self.with_stage_model("audit", GEMINI_PRO)
        if self.runner == "codex":
            return self.with_overrides(codex_model=CODEX_TOP)
        return self.with_stage_model("audit", OPUS)

    def for_smoke(self) -> "PipelineConfig":
        """De-risked first real headless run: cheap models, one audit focus, low budget +
        short timeout + tight per-session caps. Validates the headless seam end-to-end for
        real at minimal cost.

        Recon uses Sonnet (not Haiku): the synthesis stage is guardrail-gated (each generated
        prompt must carry the RoE + prohibited techniques + 'Do NOT patch' verbatim), and Haiku
        is too unreliable at reproducing the template. Every other stage stays on Haiku.

        Primes BOTH stage_models (Claude) and gemini_stage_models (Gemini) unconditionally, same
        reasoning either way: the CLI's --smoke flow calls for_smoke() first, then re-applies the
        actually-requested --runner afterward (see cli.py), so whichever backend ends up selected
        must already have its cheap dict ready."""
        models = {k: HAIKU for k in self.stage_models}
        models["recon"] = SONNET
        gemini_models = {k: GEMINI_FLASH_LITE for k in self.gemini_stage_models}
        gemini_models["recon"] = GEMINI_FLASH
        return replace(
            self,
            runner="headless",
            stage_models=models,
            gemini_stage_models=gemini_models,
            budget_usd=2.0,
            stage_timeouts={},            # smoke stays cheap: no deep recon/audit overrides
            session_timeout_s=600,        # sonnet recon explores the repo; give it headroom
            session_max_cost_usd=0.75,
            session_max_turns=60,
            max_focuses=1,
            max_parallel_audits=1,
            audit_critic_passes=0,        # smoke stays single-session
        )


_PATH_FIELDS = {"runs_dir", "prompts_dir", "ledger_path", "fixtures_dir"}

# Fields holding real secret material (as opposed to claude_config_dir/codex_home, which are just
# directory paths -- the credential lives on disk outside Argo's state, not in the field value
# itself). Gemini's practical auth lever is GEMINI_API_KEY, so these two DO carry raw key values.
# Every PipelineConfig field is serialized verbatim into runs/<id>/config.json for `argo resume` /
# `argo chat` to read back -- redact these two so a run directory never leaks a live API key.
_SECRET_FIELDS = {"gemini_api_key", "gemini_accounts"}
_REDACTED = "<redacted>"


def _jsonable(value):
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def pipeline_config_to_dict(config: PipelineConfig) -> dict:
    """Return a JSON-safe representation of the effective PipelineConfig. Secret-bearing fields
    (see _SECRET_FIELDS) are redacted -- `argo resume` on a Gemini run needs the key re-supplied,
    a narrow, deliberate deviation from resume's normal zero-flags-needed behavior."""
    out = {}
    for f in fields(PipelineConfig):
        if f.name in _SECRET_FIELDS:
            value = getattr(config, f.name)
            out[f.name] = ([_REDACTED] * len(value)) if isinstance(value, list) else (
                _REDACTED if value else value)
        else:
            out[f.name] = _jsonable(getattr(config, f.name))
    return out


def pipeline_config_from_dict(raw: dict) -> PipelineConfig:
    """Reconstruct PipelineConfig from config.json, ignoring unknown future keys."""
    if not isinstance(raw, dict):
        raise ValueError("config.json must contain a JSON object")
    known = {f.name for f in fields(PipelineConfig)}
    data = {k: v for k, v in raw.items() if k in known}
    for name in _PATH_FIELDS:
        if name in data and data[name] is not None:
            data[name] = Path(data[name])
    return PipelineConfig(**data)


def write_pipeline_config(path: Path, config: PipelineConfig) -> None:
    Path(path).write_text(json.dumps(pipeline_config_to_dict(config), indent=2), encoding="utf-8")


def load_pipeline_config(path: Path) -> PipelineConfig:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(p)
    return pipeline_config_from_dict(json.loads(p.read_text(encoding="utf-8-sig")))
