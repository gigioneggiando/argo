"""Argo — CLI (typer). Source-static security audits for bug-bounty programs.

    argo ingest   --brief BRIEF.txt --repo PATH_OR_URL [--links LINKS.txt] -> scope.json  (Stage 1)
    argo recon    --run RUN_ID                            -> repo_profile + prompts (Stage 2)
    argo run      --run RUN_ID                            -> per-focus findings     (Stage 3)
    argo second-opinion --run RUN_ID --passes N            -> extra blind passes merged in (opt-in)
    argo validate --run RUN_ID                            -> validated findings     (Stage 4)
    argo verify   --run RUN_ID                            -> deep-verified findings (Stage 7, opt-in)
    argo freshness --run RUN_ID                           -> freshness flags       (opt-in)
    argo report   --run RUN_ID                            -> REPORT.md + drafts     (Stage 5)
    argo pipeline --brief ... --repo ... [--links ...]    -> stages 1-5, STOPS before submission

There is deliberately NO submit command: submission is a manual human action.
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import typer

from .config import OPUS, PipelineConfig, load_pipeline_config
from .estimate import estimate_cost, format_estimate
from .orchestrator import (build_context, do_audit, do_corroborate, do_freshness_check, do_ingest,
                           do_live, do_recon, do_report, do_runtime, do_sca, do_second_opinion,
                           do_validate, do_verify, new_run_id,
                           resume_pipeline, run_pipeline)
from .progress import read_status
from .runner import parse_retry_after

app = typer.Typer(add_completion=False, help="Argo — authorized source-static bug-bounty audits.")


# --- shared options -------------------------------------------------------------------
def _build_config(
    runner: str,
    audit_model: Optional[str],
    calibration: bool,
    budget: Optional[float],
    parallel: int,
    runs_dir: Path,
    scenario: str,
    timeout: Optional[int] = None,
    max_turns: Optional[int] = None,
    session_budget: Optional[float] = None,
    codex_model: Optional[str] = None,
    codex_oss: bool = False,
    codex_local_provider: Optional[str] = None,
    fallback: Optional[str] = None,
    claude_accounts: Optional[str] = None,
    codex_accounts: Optional[str] = None,
) -> PipelineConfig:
    cfg = PipelineConfig(
        runner=runner,
        max_parallel_audits=parallel,
        budget_usd=budget,                # HARD per-run ceiling (aborts remaining sessions)
        runs_dir=runs_dir,
        fixtures_scenario=scenario,
        session_max_turns=max_turns,
        session_max_cost_usd=session_budget,
        codex_model=codex_model,
        codex_oss=codex_oss,
        codex_local_provider=codex_local_provider,
    )
    if timeout is not None:
        cfg = cfg.with_overrides(session_timeout_s=timeout)
    if calibration:
        cfg = cfg.calibrated()            # audit -> Opus
    if audit_model:
        cfg = cfg.with_stage_model("audit", audit_model)
    if fallback:
        names = [n.strip() for n in fallback.split(",") if n.strip()]
        cfg = cfg.with_overrides(runner_fallbacks=names)
    if claude_accounts:
        dirs = [d.strip() for d in claude_accounts.split(",") if d.strip()]
        cfg = cfg.with_overrides(claude_accounts=dirs)
    if codex_accounts:
        dirs = [d.strip() for d in codex_accounts.split(",") if d.strip()]
        cfg = cfg.with_overrides(codex_accounts=dirs)
    return cfg


RunnerOpt = typer.Option("headless", "--runner",
                         help="headless (Claude Code CLI) · codex (Codex CLI / OpenAI / OSS) · mock")
CodexModelOpt = typer.Option(None, "--codex-model",
                             help="(runner=codex) model id, e.g. gpt-5-codex; omit to use the "
                                  "Codex CLI's own default")
CodexOssOpt = typer.Option(False, "--codex-oss", help="(runner=codex) use the open-source provider (--oss)")
CodexProviderOpt = typer.Option(None, "--codex-local-provider",
                                help="(runner=codex --codex-oss) ollama | lmstudio")
AuditModelOpt = typer.Option(None, "--audit-model", help="override the Stage-3 audit model")
CalibrationOpt = typer.Option(False, "--calibration", help="run audit on Opus (all-Opus)")
BudgetOpt = typer.Option(None, "--budget", help="HARD per-run USD ceiling; aborts further sessions")
ParallelOpt = typer.Option(3, "--parallel", help="max concurrent audit/validate sessions")
RunsDirOpt = typer.Option(Path("runs"), "--runs-dir", help="root dir for run artifacts")
AttributionOpt = typer.Option(True, "--attribution/--no-attribution",
    help="append a 'Produced by Argo' provenance footer to REPORT.md / drafts / fix report "
         "(default on; --no-attribution to opt out). Attribution only — never changes any license.")
ScenarioOpt = typer.Option("happy", "--scenario", help="mock fixtures scenario (runner=mock)")
TimeoutOpt = typer.Option(None, "--timeout", help="per-session wall-clock cap (seconds)")
MaxTurnsOpt = typer.Option(None, "--max-turns", help="per-session turn tripwire (orchestrator-side)")
SessionBudgetOpt = typer.Option(None, "--session-budget",
                                help="per-session USD cap (native --max-budget-usd)")
FallbackOpt = typer.Option(None, "--fallback",
                           help="comma-separated fallback backends used when the primary hits a "
                                "session/rate limit, e.g. --fallback codex (Claude -> Codex)")
ClaudeAccountsOpt = typer.Option(
    None, "--claude-accounts",
    help="comma-separated CLAUDE_CONFIG_DIR paths to chain across (multi-account; limits are "
         "per-account). Set up each once with `CLAUDE_CONFIG_DIR=<dir> claude login`. "
         "e.g. --claude-accounts ~/.claude,~/.claude-b (account A -> account B -> --fallback)")
CodexAccountsOpt = typer.Option(
    None, "--codex-accounts",
    help="comma-separated CODEX_HOME paths to chain across (multi-account Codex; limits are "
         "per-account). Set up each once with `CODEX_HOME=<dir> codex login`. "
         "e.g. --codex-accounts ~/.codex,~/.codex-b")
RunIdArg = typer.Option(..., "--run", help="existing RUN_ID under --runs-dir")
AcceptedRisksOpt = typer.Option(
    None, "--accepted-risks", exists=True,
    help="file describing intended / accepted-by-design behaviors (the vendor's threat model / "
         "known-limitations). Injected into audit + validate + corroborate so those behaviors are "
         "not reported as vulnerabilities. Additive; never inferred from the brief.")


def _emit(obj: dict) -> None:
    typer.echo(json.dumps(obj, indent=2))


def _parse_duration(text: str) -> timedelta:
    raw = text.strip().lower()
    if raw.isdigit():
        return timedelta(seconds=int(raw))
    total = timedelta()
    pos = 0
    import re
    for m in re.finditer(r"(\d+(?:\.\d+)?)([smhd])", raw):
        if m.start() != pos:
            raise typer.BadParameter(f"invalid duration {text!r}; use forms like 30m, 12h, 1d")
        value = float(m.group(1))
        unit = m.group(2)
        if unit == "s":
            total += timedelta(seconds=value)
        elif unit == "m":
            total += timedelta(minutes=value)
        elif unit == "h":
            total += timedelta(hours=value)
        elif unit == "d":
            total += timedelta(days=value)
        pos = m.end()
    if pos != len(raw) or total.total_seconds() <= 0:
        raise typer.BadParameter(f"invalid duration {text!r}; use forms like 30m, 12h, 1d")
    return total


def _resume_config(run: str, runs_dir: Path) -> PipelineConfig:
    run_dir = Path(runs_dir) / run
    config_path = run_dir / "config.json"
    if not config_path.exists():
        raise typer.BadParameter(
            f"cannot resume run {run}: {config_path} is missing. This run predates config "
            "persistence; use the manual per-stage commands with the original flags instead.")
    try:
        cfg = load_pipeline_config(config_path)
    except Exception as exc:
        raise typer.BadParameter(f"cannot resume run {run}: failed to read {config_path}: {exc}") from exc
    if Path(cfg.runs_dir).resolve() != Path(runs_dir).resolve():
        cfg = cfg.with_overrides(runs_dir=Path(runs_dir))
    return cfg


def _failed_retry_after(status: dict | None) -> str | None:
    if not status:
        return None
    for st in status.get("stages") or []:
        if isinstance(st, dict) and st.get("state") == "failed" and st.get("retry_after"):
            return st.get("retry_after")
    return status.get("retry_after")


def _sleep_until_retry_after(retry_after: str, *, max_wait: timedelta) -> None:
    target = parse_retry_after(retry_after)
    if target is None:
        return
    now = datetime.now(timezone.utc).astimezone(target.tzinfo)
    wake = target + timedelta(seconds=60)
    if wake <= now:
        return
    wait_for = wake - now
    if wait_for > max_wait:
        raise typer.BadParameter(
            f"retry_after {retry_after!r} is {wait_for} away, beyond --max-wait {max_wait}")
    while True:
        now = datetime.now(timezone.utc).astimezone(wake.tzinfo)
        remaining = wake - now
        if remaining.total_seconds() <= 0:
            return
        typer.echo(f"[resume] waiting {remaining} until retry_after={retry_after!r}")
        time.sleep(min(300, max(1, remaining.total_seconds())))


# --- commands -------------------------------------------------------------------------
@app.command()
def ingest(
    brief: Optional[Path] = typer.Option(None, "--brief", exists=True,
                                         help="program brief text file (OMIT for a local/personal "
                                              "source-only review synthesized from --repo)"),
    repo: str = typer.Option(..., "--repo", help="codebase to analyze: a local folder path or a git URL"),
    links: Optional[Path] = typer.Option(
        None, "--links", exists=True,
        help="curated reference links file (one http(s) URL per line; '#' comments ok). "
             "Additive to extracted links; the --repo code is NOT a reference link."),
    accepted_risks: Optional[Path] = AcceptedRisksOpt,
    run: Optional[str] = typer.Option(None, "--run", help="run id (generated if omitted)"),
    runner: str = RunnerOpt, audit_model: Optional[str] = AuditModelOpt,
    calibration: bool = CalibrationOpt, budget: Optional[float] = BudgetOpt,
    parallel: int = ParallelOpt, runs_dir: Path = RunsDirOpt, scenario: str = ScenarioOpt,
):
    cfg = _build_config(runner, audit_model, calibration, budget, parallel, runs_dir, scenario)
    ctx = build_context(cfg, run or new_run_id())
    scope = do_ingest(ctx, brief, repo, links_path=links, accepted_risks_path=accepted_risks)
    _emit({"run_id": ctx.run_id, "scope": str(ctx.scope_path),
           "program": scope.program_name, "target_type": scope.target_type})


@app.command()
def recon(run: str = RunIdArg, runner: str = RunnerOpt,
          audit_model: Optional[str] = AuditModelOpt, calibration: bool = CalibrationOpt,
          budget: Optional[float] = BudgetOpt, parallel: int = ParallelOpt,
          runs_dir: Path = RunsDirOpt, scenario: str = ScenarioOpt):
    cfg = _build_config(runner, audit_model, calibration, budget, parallel, runs_dir, scenario)
    ctx = build_context(cfg, run)
    prompts = do_recon(ctx)
    _emit({"run_id": run, "prompts": [str(p) for p in prompts],
           "repo_profile": str(ctx.repo_profile_path)})


@app.command(name="run")
def run_audit(run: str = RunIdArg, runner: str = RunnerOpt,
              audit_model: Optional[str] = AuditModelOpt, calibration: bool = CalibrationOpt,
              budget: Optional[float] = BudgetOpt, parallel: int = ParallelOpt,
              runs_dir: Path = RunsDirOpt, scenario: str = ScenarioOpt):
    cfg = _build_config(runner, audit_model, calibration, budget, parallel, runs_dir, scenario)
    ctx = build_context(cfg, run)
    findings = do_audit(ctx)
    _emit({"run_id": run, "findings": [str(p) for p in findings]})


@app.command()
def sca(run: str = RunIdArg, runner: str = RunnerOpt,
        audit_model: Optional[str] = AuditModelOpt, calibration: bool = CalibrationOpt,
        budget: Optional[float] = BudgetOpt, parallel: int = ParallelOpt,
        runs_dir: Path = RunsDirOpt, scenario: str = ScenarioOpt):
    """Software-composition analysis: flag dependency manifest pins with known advisories
    (emits a `dependencies` focus into findings/ that joins the validate+report flow)."""
    cfg = _build_config(runner, audit_model, calibration, budget, parallel, runs_dir, scenario)
    ctx = build_context(cfg, run)
    path = do_sca(ctx)
    _emit({"run_id": run, "dependency_findings": str(path) if path else None})


@app.command()
def runtime(run: str = RunIdArg,
            image: Optional[str] = typer.Option(None, "--runtime-image",
                help="Docker image that contains/builds the runnable app"),
            run_cmd: Optional[str] = typer.Option(None, "--runtime-run-cmd",
                help="in-container command that starts the app on --runtime-port (127.0.0.1)"),
            build_cmd: Optional[str] = typer.Option(None, "--runtime-build-cmd",
                help="optional in-container build step before run"),
            port: int = typer.Option(8080, "--runtime-port", help="in-container loopback port"),
            boot_timeout: int = typer.Option(180, "--runtime-boot-timeout",
                help="max seconds to wait for the app to listen (raise for slow first-boot installs)"),
            mount_source: bool = typer.Option(True, "--mount-source/--no-mount-source",
                help="mount the isolated source at /src (build-at-run). Use --no-mount-source for a "
                     "self-contained PRE-BUILT image."),
            runner: str = RunnerOpt, runs_dir: Path = RunsDirOpt, scenario: str = ScenarioOpt):
    """OPT-IN, SANDBOXED runtime verification: build the target into an egress-blocked, loopback-only
    container and probe ONLY that local instance (never the program's live hosts) to confirm/refute
    findings. Reads a hand-written runs/<id>/runtime_probe_plan.json (R1)."""
    cfg = _build_config(runner, None, False, None, 3, runs_dir, scenario).with_overrides(
        runtime_enabled=True, runtime_image=image, runtime_run_cmd=run_cmd,
        runtime_build_cmd=build_cmd, runtime_port=port, runtime_boot_timeout_s=boot_timeout,
        runtime_mount_source=mount_source)
    ctx = build_context(cfg, run)
    path = do_runtime(ctx)
    _emit({"run_id": run, "runtime_results": str(path) if path else None})


@app.command()
def live(run: str = RunIdArg,
         confirm: bool = typer.Option(False, "--i-have-authorization",
             help="REQUIRED acknowledgement that the program's rules of engagement authorize live "
                  "interaction and that you accept responsibility. Without it, live is refused."),
         allow_writes: bool = typer.Option(False, "--allow-writes",
             help="SECOND opt-in: permit NON-DESTRUCTIVE state-changing methods (POST/PUT/PATCH). "
                  "DELETE is never allowed. Default is read-only (GET/HEAD/OPTIONS)."),
         max_writes: int = typer.Option(5, "--max-writes",
             help="(--allow-writes) separate cap on state-changing requests"),
         max_requests: int = typer.Option(30, "--max-requests", help="hard total request cap (anti-DoS)"),
         rate: float = typer.Option(1.0, "--min-interval",
             help="minimum seconds between live requests (anti-DoS rate cap)"),
         runner: str = RunnerOpt, runs_dir: Path = RunsDirOpt, scenario: str = ScenarioOpt):
    """[WARNING] OPT-IN LIVE testing of the program's IN-SCOPE hosts (L1, read-only).

    A FIXED executor makes BOUNDED, IN-SCOPE-ONLY HTTP requests to the live target to confirm findings.
    Hard rails: refuses unless the scope's RoE authorize it (automation_allowed, safe_harbor, declared
    prohibited_techniques); every request must target an in-scope asset (out-of-scope/unknown hosts are
    blocked); read-only by default; total/rate/size caps; every request is written to an audit log.
    Uses a hand-written runs/<id>/live_probe_plan.json if present; otherwise (L2) an offline LLM session
    generates one from the validated findings, gated by the same validators. AUTHORIZED USE ONLY."""
    if not confirm:
        _emit({"run_id": run, "live_results": None,
               "refused": "live testing requires --i-have-authorization (the program's rules must "
                          "permit it and you accept responsibility)."})
        raise typer.Exit(code=2)
    cfg = _build_config(runner, None, False, None, 3, runs_dir, scenario).with_overrides(
        live_enabled=True, live_allow_writes=allow_writes, live_max_writes=max_writes,
        live_max_requests=max_requests, live_min_request_interval_s=rate)
    ctx = build_context(cfg, run)
    path = do_live(ctx)
    _emit({"run_id": run, "live_results": str(path) if path else None})


@app.command(name="second-opinion")
def second_opinion_cmd(run: str = RunIdArg,
                       passes: int = typer.Option(1, "--passes",
                           help="how many additional blind recon+audit passes to run"),
                       backend: Optional[str] = typer.Option(
                           None, "--backend",
                           help="runner override for the extra passes only (e.g. 'headless' when the "
                                "primary run used 'codex'); omit to reuse the primary's backend"),
                       runner: str = RunnerOpt, audit_model: Optional[str] = AuditModelOpt,
                       calibration: bool = CalibrationOpt, budget: Optional[float] = BudgetOpt,
                       parallel: int = ParallelOpt, runs_dir: Path = RunsDirOpt, scenario: str = ScenarioOpt):
    """Run N additional, fully independent blind recon+audit passes over the run's already-ingested
    scope/repo and merge their findings into findings/ before validate runs. Each pass gets its own
    isolated run_dir; a failed pass is skipped, never aborts. Re-run `argo validate` afterward to
    reconcile everything (structural + semantic dedup already collapse cross-pass duplicates)."""
    cfg = _build_config(runner, audit_model, calibration, budget, parallel, runs_dir, scenario
                        ).with_overrides(second_opinion_passes=passes, second_opinion_backend=backend)
    ctx = build_context(cfg, run)
    do_second_opinion(ctx)
    _emit({"run_id": run, "findings_dir": str(ctx.findings_dir)})


@app.command()
def validate(run: str = RunIdArg, runner: str = RunnerOpt,
             audit_model: Optional[str] = AuditModelOpt, calibration: bool = CalibrationOpt,
             budget: Optional[float] = BudgetOpt, parallel: int = ParallelOpt,
             runs_dir: Path = RunsDirOpt, scenario: str = ScenarioOpt):
    cfg = _build_config(runner, audit_model, calibration, budget, parallel, runs_dir, scenario)
    ctx = build_context(cfg, run)
    path = do_validate(ctx)
    _emit({"run_id": run, "validated_findings": str(path)})


@app.command()
def corroborate(run: str = RunIdArg,
                docs_url: Optional[list[str]] = typer.Option(
                    None, "--docs-url",
                    help="documentation URL to ground corroboration (repeatable); omit to web-search"),
                runner: str = RunnerOpt, audit_model: Optional[str] = AuditModelOpt,
                calibration: bool = CalibrationOpt, budget: Optional[float] = BudgetOpt,
                parallel: int = ParallelOpt, runs_dir: Path = RunsDirOpt, scenario: str = ScenarioOpt):
    """Cross-check each surviving finding against the project's docs + the repo's VCS history
    (commits/releases/advisories) over public web OSINT, to confirm or discard it (downgrade
    by-design, move already-fixed to an appendix). Networked, best-effort. Rewrites
    validated_findings.json in place."""
    cfg = _build_config(runner, audit_model, calibration, budget, parallel, runs_dir, scenario
                        ).with_overrides(doc_links=list(docs_url or []))
    ctx = build_context(cfg, run)
    path = do_corroborate(ctx)
    _emit({"run_id": run, "validated_findings": str(path)})


@app.command()
def verify(run: str = RunIdArg,
          max_findings: Optional[int] = typer.Option(
              None, "--max-findings",
              help="cap how many survivors get a deep-verify session (cost control); "
                   "omit to deep-verify every survivor"),
          runner: str = RunnerOpt, audit_model: Optional[str] = AuditModelOpt,
          calibration: bool = CalibrationOpt, budget: Optional[float] = BudgetOpt,
          parallel: int = ParallelOpt, runs_dir: Path = RunsDirOpt, scenario: str = ScenarioOpt):
    """Deep-verify: independently RE-DERIVE each surviving finding from the actual source (full
    repo access, one full session per finding, no batching, no excerpt budget) and reason across
    the whole survivor set — catches what validate/corroborate's per-finding isolation cannot: a
    finding that is actually several distinct bugs (split), two findings sharing one root cause
    (merged), or a finding whose mechanism is real but a stated detail is wrong (corrected).
    Offline, opt-in, best-effort. Rewrites validated_findings.json in place."""
    cfg = _build_config(runner, audit_model, calibration, budget, parallel, runs_dir, scenario
                        ).with_overrides(verify_enabled=True, verify_max_findings=max_findings)
    ctx = build_context(cfg, run)
    path = do_verify(ctx)
    _emit({"run_id": run, "validated_findings": str(path)})


@app.command()
def freshness(run: str = RunIdArg,
              lookback_days: int = typer.Option(
                  365, "--lookback-days",
                  help="how many days of branch history to inspect for same-file commits"),
              runner: str = RunnerOpt, audit_model: Optional[str] = AuditModelOpt,
              calibration: bool = CalibrationOpt, budget: Optional[float] = BudgetOpt,
              parallel: int = ParallelOpt, runs_dir: Path = RunsDirOpt, scenario: str = ScenarioOpt):
    """Freshness check: look for same-file commits on the audited branch after the pinned commit
    and on version-looking sibling branches. Informational only; verdicts/statuses are unchanged.
    Networked git history check, opt-in, best-effort. Rewrites validated_findings.json in place only
    when flags are found."""
    cfg = _build_config(runner, audit_model, calibration, budget, parallel, runs_dir, scenario
                        ).with_overrides(freshness_check_enabled=True,
                                         freshness_lookback_days=lookback_days)
    ctx = build_context(cfg, run)
    path = do_freshness_check(ctx)
    _emit({"run_id": run, "validated_findings": str(path)})


@app.command()
def report(run: str = RunIdArg, runner: str = RunnerOpt,
           audit_model: Optional[str] = AuditModelOpt, calibration: bool = CalibrationOpt,
           budget: Optional[float] = BudgetOpt, parallel: int = ParallelOpt,
           runs_dir: Path = RunsDirOpt, scenario: str = ScenarioOpt,
           attribution: bool = AttributionOpt):
    cfg = _build_config(runner, audit_model, calibration, budget, parallel, runs_dir, scenario
                        ).with_overrides(attribution=attribution)
    ctx = build_context(cfg, run)
    path = do_report(ctx)
    _emit({"run_id": run, "report": str(path), "drafts_dir": str(ctx.drafts_dir)})


@app.command()
def resume(
    run: str = RunIdArg,
    wait: bool = typer.Option(False, "--wait",
                              help="sleep until the failed stage's retry_after hint, then resume"),
    max_wait: str = typer.Option("12h", "--max-wait",
                                 help="maximum time to wait with --wait, e.g. 30m, 12h, 1d"),
    runs_dir: Path = RunsDirOpt,
):
    """Resume an existing pipeline run using the run's persisted config.json."""
    cfg = _resume_config(run, runs_dir)
    status = read_status(Path(cfg.runs_dir) / run)
    retry_after = _failed_retry_after(status)
    target = parse_retry_after(retry_after) if retry_after else None
    if target is not None and target > datetime.now(timezone.utc).astimezone(target.tzinfo):
        if not wait:
            raise typer.BadParameter(f"resume again after {retry_after}")
        _sleep_until_retry_after(retry_after, max_wait=_parse_duration(max_wait))
    ctx = build_context(cfg, run)
    summary = resume_pipeline(ctx)
    _emit(summary)


@app.command()
def fix(run: str = RunIdArg,
        no_verify: bool = typer.Option(False, "--no-verify",
                                       help="skip the compile / no-new-errors verification"),
        docker: Optional[str] = typer.Option(None, "--docker", metavar="IMAGE",
                                             help="run the build/compile check inside this Docker "
                                                  "image (offline, --network=none)"),
        build_cmd: Optional[str] = typer.Option(None, "--build-cmd",
                                                help="explicit build/compile command to verify the "
                                                     "patch (run in the isolated copy)"),
        only: Optional[str] = typer.Option(None, "--only",
                                           help="comma-separated finding ids to fix (default: all "
                                                "confirmed)"),
        re_audit: bool = typer.Option(False, "--re-audit",
                                      help="also re-audit the patched copy to check the vuln is gone "
                                           "(one extra model session per patch; needs verify on)"),
        runner: str = RunnerOpt, audit_model: Optional[str] = AuditModelOpt,
        calibration: bool = CalibrationOpt, budget: Optional[float] = BudgetOpt,
        parallel: int = ParallelOpt, runs_dir: Path = RunsDirOpt, scenario: str = ScenarioOpt,
        attribution: bool = AttributionOpt):
    """Phase 6 (opt-in): propose a reviewable patch per confirmed finding and VERIFY each on an
    ISOLATED COPY (applies? compiles? no new errors?). Never modifies the target repo."""
    from .fixes import generate_fixes
    cfg = _build_config(runner, audit_model, calibration, budget, parallel, runs_dir, scenario
                        ).with_overrides(attribution=attribution)
    ctx = build_context(cfg, run)
    ids = {s.strip() for s in only.split(",") if s.strip()} if only else None
    report = generate_fixes(ctx, verify=not no_verify, docker=docker, build_cmd=build_cmd,
                            only=ids, re_audit=re_audit)
    _emit(report)


def _archetype_for_run(run_dir: Path) -> str:
    try:
        meta = json.loads((run_dir / "meta.json").read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return "other"
    arch = meta.get("archetype") if isinstance(meta, dict) else None
    return str(arch or "other")


@app.command()
def estimate(
    brief: Optional[Path] = typer.Option(None, "--brief", exists=True,
                                         help="program brief text file (omit for a local/personal "
                                              "source-only review synthesized from --repo)"),
    repo: str = typer.Option(..., "--repo", help="codebase to analyze: a local folder path or a git URL"),
    links: Optional[Path] = typer.Option(
        None, "--links", exists=True,
        help="curated reference links file (same meaning as argo pipeline --links)"),
    run: Optional[str] = typer.Option(None, "--run", help="run id (generated if omitted)"),
    commit: Optional[str] = typer.Option(
        None, "--commit", help="pin --repo at this git revision before recon"),
    research: bool = typer.Option(
        True, "--research/--no-research",
        help="run the cheap Stage-0 OSINT step before recon when a brief is provided"),
    sca: bool = typer.Option(True, "--sca/--no-sca",
                             help="include/exclude SCA in the estimated full config"),
    second_opinion: int = typer.Option(
        0, "--second-opinion",
        help="estimate N additional blind recon+audit passes"),
    second_opinion_backend: Optional[str] = typer.Option(
        None, "--second-opinion-backend",
        help="runner override for second-opinion passes"),
    corroborate: bool = typer.Option(
        True, "--corroborate/--no-corroborate",
        help="include/exclude corroboration in the estimated full config"),
    docs_url: Optional[list[str]] = typer.Option(
        None, "--docs-url",
        help="documentation URL to ground corroboration (repeatable)"),
    verify: bool = typer.Option(False, "--verify/--no-verify",
                                help="include/exclude deep verify in the estimate"),
    verify_max_findings: Optional[int] = typer.Option(
        None, "--verify-max-findings",
        help="(--verify) cap how many survivors get deep verify"),
    freshness_check: bool = typer.Option(
        False, "--freshness-check/--no-freshness-check",
        help="include/exclude the late freshness-check stage"),
    freshness_lookback_days: int = typer.Option(
        365, "--freshness-lookback-days",
        help="(--freshness-check) days of branch history to inspect"),
    accepted_risks: Optional[Path] = AcceptedRisksOpt,
    critic_passes: Optional[int] = typer.Option(
        None, "--critic-passes",
        help="completeness-critic re-passes per audit focus"),
    runtime: bool = typer.Option(False, "--runtime/--no-runtime",
        help="include/exclude sandboxed runtime verification in the estimate"),
    runtime_image: Optional[str] = typer.Option(None, "--runtime-image",
        help="(--runtime) Docker image that contains/builds the runnable app"),
    runtime_run_cmd: Optional[str] = typer.Option(None, "--runtime-run-cmd",
        help="(--runtime) in-container command that starts the app"),
    runner: str = RunnerOpt, audit_model: Optional[str] = AuditModelOpt,
    calibration: bool = CalibrationOpt, budget: Optional[float] = BudgetOpt,
    parallel: int = ParallelOpt, runs_dir: Path = RunsDirOpt, scenario: str = ScenarioOpt,
    timeout: Optional[int] = TimeoutOpt, max_turns: Optional[int] = MaxTurnsOpt,
    session_budget: Optional[float] = SessionBudgetOpt,
    codex_model: Optional[str] = CodexModelOpt, codex_oss: bool = CodexOssOpt,
    codex_local_provider: Optional[str] = CodexProviderOpt, fallback: Optional[str] = FallbackOpt,
    claude_accounts: Optional[str] = ClaudeAccountsOpt,
    codex_accounts: Optional[str] = CodexAccountsOpt,
):
    """Run ingest+recon only, classify the target, and print a pre-audit cost estimate."""
    cfg = _build_config(runner, audit_model, calibration, budget, parallel, runs_dir, scenario,
                        timeout=timeout, max_turns=max_turns, session_budget=session_budget,
                        codex_model=codex_model, codex_oss=codex_oss,
                        codex_local_provider=codex_local_provider, fallback=fallback,
                        claude_accounts=claude_accounts, codex_accounts=codex_accounts)
    cfg = cfg.with_overrides(sca_enabled=sca, research_enabled=research, runtime_enabled=runtime,
                             runtime_image=runtime_image, runtime_run_cmd=runtime_run_cmd,
                             corroborate_enabled=corroborate, doc_links=list(docs_url or []),
                             verify_enabled=verify, verify_max_findings=verify_max_findings,
                             freshness_check_enabled=freshness_check,
                             freshness_lookback_days=freshness_lookback_days,
                             second_opinion_passes=second_opinion,
                             second_opinion_backend=second_opinion_backend)
    if critic_passes is not None:
        cfg = cfg.with_overrides(audit_critic_passes=critic_passes)
    if brief is None:
        research = False
        cfg = cfg.with_overrides(research_enabled=False, corroborate_enabled=False)

    ctx = build_context(cfg, run or new_run_id())
    try:
        summary = run_pipeline(ctx, brief, repo, dry_run=True, research_enabled=research,
                               links_path=links, accepted_risks_path=accepted_risks,
                               commit=commit)
        arch = _archetype_for_run(ctx.run_dir)
        est = estimate_cost(ctx.ledger, Path(cfg.runs_dir), arch, cfg, run_id=ctx.run_id)
        typer.echo(format_estimate(est))
        typer.echo(f"Run artifacts kept in {ctx.run_dir} for reuse or review.")
        _emit({"run_id": ctx.run_id, "stopped_after": summary.get("stopped_after"),
               "archetype": arch, "estimate": est})
    finally:
        ctx.ledger.close()


@app.command()
def pipeline(
    brief: Optional[Path] = typer.Option(None, "--brief", exists=True,
                                         help="program brief text file. OPTIONAL: omit it to audit "
                                              "a local/personal codebase as a source-only review "
                                              "(scope is synthesized from --repo, zero-token ingest)."),
    repo: Optional[str] = typer.Option(None, "--repo", help="codebase to analyze: a local folder "
                                                            "path OR a git URL"),
    links: Optional[Path] = typer.Option(
        None, "--links", exists=True,
        help="curated reference links file (one http(s) URL per line; '#' comments ok). "
             "Additive to extracted links; the --repo code is NOT a reference link."),
    run: Optional[str] = typer.Option(None, "--run", help="run id (generated if omitted)"),
    commit: Optional[str] = typer.Option(
        None, "--commit", help="pin --repo at this git revision (reproducible / known-CVE checkout); "
        "for a URL it is fetched, for a local path the copy is checked out at it"),
    dry_run: bool = typer.Option(False, "--dry-run",
                                 help="run ingest+recon only, then STOP before any audit"),
    yes: bool = typer.Option(False, "--yes",
                             help="proceed past the pre-audit cost estimate without prompting"),
    research: bool = typer.Option(
        True, "--research/--no-research",
        help="Stage-0 web OSINT/threat-intel before recon (the ONLY networked stage; never the "
             "live in-scope hosts). On by default; --no-research keeps the run fully offline."),
    smoke: bool = typer.Option(
        False, "--smoke",
        help="de-risked REAL headless check: cheapest model, ONE audit focus, low budget + "
             "short timeout + tight caps. Defaults --brief/--repo to the bundled fixtures."),
    sca: bool = typer.Option(True, "--sca/--no-sca",
                             help="software-composition analysis of dependency manifests (on by default)"),
    second_opinion: int = typer.Option(
        0, "--second-opinion",
        help="OPT-IN: run N additional, fully independent blind recon+audit passes over the same "
             "scope/repo before validate, then merge their findings in (encodes the manual blind "
             "second-opinion methodology). 0 disables (default). Each pass gets its own isolated "
             "run_dir; a failed pass is skipped, never aborts the run."),
    second_opinion_backend: Optional[str] = typer.Option(
        None, "--second-opinion-backend",
        help="(--second-opinion) runner override for the extra passes only, e.g. 'headless' when "
             "--runner codex, for real cross-engine diversity. Omit to reuse the primary's backend."),
    corroborate: bool = typer.Option(
        True, "--corroborate/--no-corroborate",
        help="after validation, cross-check each finding against the project's docs + the repo's "
             "VCS history (commits/releases/advisories) over public web OSINT, to confirm or discard "
             "it (downgrade by-design, exclude already-fixed). On by default; networked, best-effort."),
    docs_url: Optional[list[str]] = typer.Option(
        None, "--docs-url",
        help="documentation URL to ground corroboration (repeatable). If omitted, the stage searches "
             "the web for the project's official docs."),
    verify: bool = typer.Option(
        False, "--verify/--no-verify",
        help="OPT-IN deep-verify: after corroboration, independently re-derive each surviving "
             "finding from the actual source (full repo access, one full session per finding, no "
             "batching) and reason across the whole survivor set to catch splits/merges/corrections "
             "that per-finding-isolated stages cannot. Offline. Off by default: expensive."),
    verify_max_findings: Optional[int] = typer.Option(
        None, "--verify-max-findings",
        help="(--verify) cap how many survivors get a deep-verify session (cost control)"),
    freshness_check: bool = typer.Option(
        False, "--freshness-check/--no-freshness-check",
        help="OPT-IN: before reporting, check audited/sibling branch git history for same-file "
             "commits that should be manually verified before sending"),
    freshness_lookback_days: int = typer.Option(
        365, "--freshness-lookback-days",
        help="(--freshness-check) days of branch history to inspect"),
    accepted_risks: Optional[Path] = AcceptedRisksOpt,
    critic_passes: Optional[int] = typer.Option(
        None, "--critic-passes",
        help="completeness-critic re-passes per audit focus (depth lever; default 1, 0 disables)"),
    runtime: bool = typer.Option(False, "--runtime/--no-runtime",
        help="OPT-IN sandboxed runtime verification (build target in an egress-blocked, "
             "loopback-only container; probe ONLY the local instance). Needs a launcher recipe."),
    runtime_image: Optional[str] = typer.Option(None, "--runtime-image",
        help="(--runtime) Docker image that contains/builds the runnable app"),
    runtime_run_cmd: Optional[str] = typer.Option(None, "--runtime-run-cmd",
        help="(--runtime) in-container command that starts the app on --runtime-port"),
    runner: str = RunnerOpt, audit_model: Optional[str] = AuditModelOpt,
    calibration: bool = CalibrationOpt, budget: Optional[float] = BudgetOpt,
    parallel: int = ParallelOpt, runs_dir: Path = RunsDirOpt, scenario: str = ScenarioOpt,
    timeout: Optional[int] = TimeoutOpt, max_turns: Optional[int] = MaxTurnsOpt,
    session_budget: Optional[float] = SessionBudgetOpt,
    codex_model: Optional[str] = CodexModelOpt, codex_oss: bool = CodexOssOpt,
    codex_local_provider: Optional[str] = CodexProviderOpt, fallback: Optional[str] = FallbackOpt,
    claude_accounts: Optional[str] = ClaudeAccountsOpt,
    codex_accounts: Optional[str] = CodexAccountsOpt,
    attribution: bool = AttributionOpt,
):
    """Run stages 1-5 and STOP at human-review drafts. Never submits."""
    cfg = _build_config(runner, audit_model, calibration, budget, parallel, runs_dir, scenario,
                        timeout=timeout, max_turns=max_turns, session_budget=session_budget,
                        codex_model=codex_model, codex_oss=codex_oss,
                        codex_local_provider=codex_local_provider, fallback=fallback,
                        claude_accounts=claude_accounts, codex_accounts=codex_accounts)
    cfg = cfg.with_overrides(sca_enabled=sca, research_enabled=research, runtime_enabled=runtime,
                             runtime_image=runtime_image, runtime_run_cmd=runtime_run_cmd,
                             corroborate_enabled=corroborate, doc_links=list(docs_url or []),
                             verify_enabled=verify, verify_max_findings=verify_max_findings,
                             freshness_check_enabled=freshness_check,
                             freshness_lookback_days=freshness_lookback_days,
                             second_opinion_passes=second_opinion,
                             second_opinion_backend=second_opinion_backend,
                             attribution=attribution)
    if critic_passes is not None:
        cfg = cfg.with_overrides(audit_critic_passes=critic_passes)
    if smoke:
        cfg = cfg.for_smoke()                              # cheapest model, 1 focus, low caps
        # for_smoke() defaults to the Claude backend; honor an explicit --runner (e.g. codex).
        cfg = cfg.with_overrides(runner=runner, codex_model=codex_model, codex_oss=codex_oss,
                                 codex_local_provider=codex_local_provider)
        research = False                                   # a cheap smoke stays fully offline
        cfg = cfg.with_overrides(research_enabled=False,
                                 corroborate_enabled=False)  # ...and skips the networked cross-check
        if brief is None:
            brief = Path("tests/fixtures/brief.txt")       # bundled tiny fixture
        if repo is None:
            repo = "tests/fixtures/repo"
    if repo is None:
        raise typer.BadParameter("--repo is required (a local folder path or a git URL)")
    if brief is None:
        research = False     # local/personal review: no program context to web-research, stay offline
        cfg = cfg.with_overrides(research_enabled=False,
                                 corroborate_enabled=False)  # ...and no networked corroboration
    ctx = build_context(cfg, run or new_run_id())

    def _print_estimate(text: str) -> None:
        typer.echo(text, err=True)

    def _confirm_estimate(_estimate: dict) -> bool:
        if yes or cfg.budget_usd is not None:
            return True
        if not sys.stdin.isatty():
            return True
        return typer.confirm("Proceed into audit?", default=False)

    summary = run_pipeline(ctx, brief, repo, dry_run=dry_run, research_enabled=research,
                           links_path=links, accepted_risks_path=accepted_risks, commit=commit,
                           estimate_before_audit=not dry_run, estimate_output=_print_estimate,
                           estimate_confirm=_confirm_estimate)
    summary["smoke"] = smoke
    _emit(summary)


@app.command()
def bench(suite: Path = typer.Option(..., "--suite", exists=True, file_okay=False,
                                     help="suite dir (each <case>/case.json + expected_findings.json)"),
          fixes: bool = typer.Option(False, "--fixes",
                                     help="also score Phase-6 patch quality (verified rate)"),
          ab_audit_model: Optional[str] = typer.Option(
              None, "--ab-audit-model", metavar="MODEL",
              help="run the suite a second time with this audit model and report the delta"),
          parallel_cases: int = typer.Option(
              1, "--parallel-cases", min=1, max=16, metavar="N",
              help="run N cases concurrently (corpora at scale; real cost adds up on headless)"),
          re_audit: bool = typer.Option(
              False, "--re-audit",
              help="with --fixes: re-audit each patched copy and report the bug-actually-gone rate"),
          runner: str = RunnerOpt, audit_model: Optional[str] = AuditModelOpt,
          calibration: bool = CalibrationOpt, budget: Optional[float] = BudgetOpt,
          parallel: int = ParallelOpt, runs_dir: Path = RunsDirOpt, scenario: str = ScenarioOpt):
    """Phase 7: run a labeled suite and score findings precision/recall/F1 (by archetype + CWE).
    Use --runner mock for a free harness check; headless measures real model quality."""
    from .benchmark import ab_compare, run_suite
    cfg = _build_config(runner, audit_model, calibration, budget, parallel, runs_dir, scenario)
    if ab_audit_model:
        _emit(ab_compare(cfg, suite, audit_model_b=ab_audit_model, fixes=fixes,
                         parallel_cases=parallel_cases, re_audit=re_audit))
    else:
        _emit(run_suite(cfg, suite, fixes=fixes, parallel_cases=parallel_cases, re_audit=re_audit))


def _ledger_for(ledger: Optional[Path]):
    from .config import PipelineConfig
    from .ledger import Ledger
    return Ledger(ledger or PipelineConfig().ledger_path)


@app.command()
def feedback(
    program: Optional[str] = typer.Option(None, "--program", help="program name to match"),
    dedup: Optional[str] = typer.Option(None, "--dedup", help="finding dedup_key to match"),
    accepted: Optional[bool] = typer.Option(
        None, "--accepted/--rejected", help="the triager outcome for the matched finding(s)"),
    run: Optional[str] = typer.Option(None, "--run", help="scope the update to one RUN_ID"),
    note: Optional[str] = typer.Option(None, "--note", help="optional triager reason / comment"),
    import_file: Optional[Path] = typer.Option(
        None, "--import", exists=True, dir_okay=False, metavar="FILE",
        help="bulk-import a JSON list of {program_name, dedup_key, accepted, run_id?, feedback?}"),
    ledger: Optional[Path] = typer.Option(None, "--ledger", help="ledger DB path (default: bundled)")):
    """A2: record real-world triager feedback (accept/reject) for reported findings, feeding the
    accept-rate. Source of truth is the Fleece registry — this only ingests it into the ledger."""
    led = _ledger_for(ledger)
    try:
        if import_file is not None:
            items = json.loads(Path(import_file).read_text(encoding="utf-8-sig"))
            updated = 0
            for it in items:
                updated += led.record_triager_feedback(
                    program_name=it["program_name"], dedup_key=it["dedup_key"],
                    accepted=bool(it["accepted"]), run_id=it.get("run_id"),
                    feedback=it.get("feedback"))
            _emit({"imported": len(items), "rows_updated": updated})
        else:
            if not (program and dedup and accepted is not None):
                raise typer.BadParameter("provide --program, --dedup and --accepted/--rejected "
                                         "(or use --import FILE)")
            n = led.record_triager_feedback(program_name=program, dedup_key=dedup,
                                            accepted=accepted, run_id=run, feedback=note)
            _emit({"program": program, "dedup_key": dedup, "accepted": accepted,
                   "rows_updated": n})
    finally:
        led.close()


@app.command()
def quality(
    program: Optional[str] = typer.Option(None, "--program", help="scope to one program"),
    runs_dir: Path = RunsDirOpt,
    ledger: Optional[Path] = typer.Option(None, "--ledger", help="ledger DB path (default: bundled)")):
    """A2: emit quality.json — the real-world triager accept-rate (human precision proxy) paired
    with the latest benchmark recall. Writes <runs_dir>/quality.json."""
    from .quality import write_quality
    led = _ledger_for(ledger)
    try:
        _emit(write_quality(led, runs_dir, program_name=program))
    finally:
        led.close()


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="bind address (keep localhost)"),
    port: int = typer.Option(8000, "--port"),
    runs_dir: Path = RunsDirOpt,
    open_browser: bool = typer.Option(False, "--open", help="open the web UI in your browser"),
):
    """Start the HTTP API + web UI (FastAPI + uvicorn)."""
    import uvicorn
    from server.app import create_app
    cfg = PipelineConfig(runs_dir=runs_dir)
    url = f"http://{host}:{port}/"
    typer.echo(f"Serving Argo on {url}  (runs dir: {runs_dir})")
    if open_browser:
        import threading
        import webbrowser
        threading.Timer(1.5, lambda: _safe_open(webbrowser, url)).start()
    uvicorn.run(create_app(cfg), host=host, port=port)


def _safe_open(webbrowser, url: str) -> None:
    try:
        webbrowser.open(url)
    except Exception:
        pass  # opening a browser is best-effort; never crash the server over it


if __name__ == "__main__":
    app()
