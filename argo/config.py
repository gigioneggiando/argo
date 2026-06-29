"""Central configuration: model assignment, tool allowlists, budgets, paths.

Everything tunable lives here so the guardrails and stages read from a single source.
Per-stage models are overridable at runtime (CLI flags / ``PipelineConfig`` overrides);
``audit`` is the headline knob because the audit model sets the missed-bug (false-negative)
rate — the validation stage can only remove false positives, never recover a bug the audit
model failed to surface.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

# --- Model IDs (the most capable current Claude models) -----------------------------
OPUS = "claude-opus-4-8"
SONNET = "claude-sonnet-4-6"
HAIKU = "claude-haiku-4-5-20251001"  # cheapest; used for the headless smoke run

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
}

#: Default per-stage wall-clock overrides (seconds). Recon now does deep ground-truth extraction
#: (enumerating variant families, baseline-correct refs, invariants across the whole tree) and the
#: audit walks every family member — both want more headroom than the 1800s global default. The
#: completeness-critic re-pass (audit) also runs inside the audit stage budget.
DEFAULT_STAGE_TIMEOUTS: dict[str, int] = {
    "recon": 3600,
    "audit": 3600,
}

# --- Cost estimation for backends that report tokens but not USD ---------------------
# Claude Code returns an authoritative ``total_cost_usd`` per call. The Codex CLI (OpenAI / OSS)
# reports tokens, not dollars, so for it we ESTIMATE: tokens x this rough price table. Figures are
# USD per 1M tokens (input, output); used only for the budget guard + cost analytics, never billed.
# Unknown models (incl. ``--oss`` / local) estimate to $0 — tokens are still logged.
MODEL_PRICING: dict[str, tuple[float, float]] = {
    "gpt-5.5": (1.25, 10.0), "gpt-5-codex": (1.25, 10.0), "gpt-5": (1.25, 10.0),
    "gpt-4o": (2.5, 10.0), "gpt-4.1": (2.0, 8.0), "o4-mini": (1.1, 4.4), "o3": (2.0, 8.0),
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

    # Execution.
    runner: str = "headless"            # "headless" (Claude Code) | "codex" (Codex CLI) | "mock"
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
    max_parallel_audits: int = 3        # concurrency cap for Stage 3 / Stage 4 fan-out

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
        models = dict(self.stage_models)
        models[stage] = model
        return replace(self, stage_models=models)

    def calibrated(self) -> "PipelineConfig":
        """Calibration default: run the audit stage on Opus (effectively all-Opus) so a
        weak prompt is never confounded with a weak model when diagnosing missed bugs."""
        return self.with_stage_model("audit", OPUS)

    def for_smoke(self) -> "PipelineConfig":
        """De-risked first real headless run: cheap models, one audit focus, low budget +
        short timeout + tight per-session caps. Validates the headless seam end-to-end for
        real at minimal cost.

        Recon uses Sonnet (not Haiku): the synthesis stage is guardrail-gated (each generated
        prompt must carry the RoE + prohibited techniques + 'Do NOT patch' verbatim), and Haiku
        is too unreliable at reproducing the template. Every other stage stays on Haiku."""
        models = {k: HAIKU for k in self.stage_models}
        models["recon"] = SONNET
        return replace(
            self,
            runner="headless",
            stage_models=models,
            budget_usd=2.0,
            stage_timeouts={},            # smoke stays cheap: no deep recon/audit overrides
            session_timeout_s=600,        # sonnet recon explores the repo; give it headroom
            session_max_cost_usd=0.75,
            session_max_turns=60,
            max_focuses=1,
            max_parallel_audits=1,
            audit_critic_passes=0,        # smoke stays single-session
        )
