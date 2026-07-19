"""Second-opinion stage (opt-in blind recon+audit passes merged in before validate) — zero token
spend on the mock runner.

Covers: off by default (no behavior change), each pass gets its own isolated run_dir and findings
get merged into the primary's findings_dir tagged with source_pass, validate's existing structural
dedup naturally collapses an exact cross-pass duplicate and records corroborating_passes (the
reuse this stage was designed around — no new matching logic needed), and a failed pass is skipped
rather than aborting the run.
"""
import json

import pytest

from argo.models import Finding
from argo.orchestrator import run_pipeline
from argo.stages import second_opinion

from conftest import BRIEF, REPO


def _validated(ctx) -> dict:
    return json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))


def test_disabled_by_default_no_extra_findings_or_dirs(env):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    assert not any("source_pass" in (f.get("source_pass") or "") for f in vf["findings"])
    assert not (ctx.config.runs_dir / f"{ctx.run_id}-so1").exists()


def test_second_opinion_pass_gets_isolated_run_dir(env):
    ctx = env(second_opinion_passes=1)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    sub_run_dir = ctx.config.runs_dir / f"{ctx.run_id}-so1"
    assert sub_run_dir.is_dir()
    assert (sub_run_dir / "scope.json").is_file()          # reused, not re-parsed
    assert (sub_run_dir / "repo").is_dir()                 # reused, not re-cloned
    assert (sub_run_dir / "llm_log.jsonl").is_file()        # its OWN recon+audit sessions
    sub_stages = [json.loads(l)["stage"] for l in
                  (sub_run_dir / "llm_log.jsonl").read_text(encoding="utf-8").strip().splitlines()]
    assert "recon" in sub_stages and "audit" in sub_stages
    # the sub-pass's sessions must NOT appear in the primary's own log
    primary_stages = [json.loads(l)["stage"] for l in
                      (ctx.run_dir / "llm_log.jsonl").read_text(encoding="utf-8").strip().splitlines()]
    assert primary_stages.count("recon") == 1               # only the primary's own recon
    assert primary_stages.count("audit") == 2                # only the primary's own 2 foci


def test_second_opinion_findings_merged_and_tagged(env):
    ctx = env(second_opinion_passes=1)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    merged_files = sorted(ctx.findings_dir.glob("second-opinion-1-*.json"))
    assert merged_files, "expected the second-opinion pass's findings copied into the primary findings_dir"
    doc = json.loads(merged_files[0].read_text(encoding="utf-8"))
    assert doc["source_pass"] == "second-opinion-1"
    assert doc["findings"]


def test_exact_cross_pass_duplicate_is_recorded_as_corroborating(env):
    """The mock fixtures are fully deterministic (see runner.py's _recon/_audit), so a second-opinion
    pass over the SAME scope/repo reproduces the identical raw findings as the primary — the cleanest
    possible test of the corroborating_passes bookkeeping: an exact dedup_key collision spanning two
    distinct source_pass values."""
    ctx = env(second_opinion_passes=1)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    findings = [Finding.model_validate(f) for f in vf["findings"]]
    corroborated = [f for f in findings if len(f.corroborating_passes) > 1]
    assert corroborated, "expected at least one finding independently confirmed by both passes"
    for f in corroborated:
        assert "primary" in f.corroborating_passes
        assert "second-opinion-1" in f.corroborating_passes


def test_report_surfaces_cross_pass_corroboration(env):
    ctx = env(second_opinion_passes=1)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    report_md = (ctx.run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "independently confirmed by" in report_md.lower()
    assert "Independently confirmed by 2 blind audit passes" in report_md
    assert "primary, second-opinion-1" in report_md


def test_multiple_passes_each_get_a_distinct_run_dir(env):
    ctx = env(second_opinion_passes=2)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    assert (ctx.config.runs_dir / f"{ctx.run_id}-so1").is_dir()
    assert (ctx.config.runs_dir / f"{ctx.run_id}-so2").is_dir()
    assert any(ctx.findings_dir.glob("second-opinion-1-*.json"))
    assert any(ctx.findings_dir.glob("second-opinion-2-*.json"))


def test_second_opinion_runs_after_audit_before_validate(env):
    ctx = env(second_opinion_passes=1)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    status = json.loads((ctx.run_dir / "status.json").read_text(encoding="utf-8"))
    stage_names = [s["name"] for s in status["stages"]]
    assert stage_names.index("audit") < stage_names.index("second_opinion") < stage_names.index("validate")


def test_second_opinion_backend_override_uses_a_different_runner(env):
    ctx = env(second_opinion_passes=1, second_opinion_backend="mock")
    # "mock" == same backend here (env() already forces runner=mock), but exercises the override
    # branch (a distinct sub_config + a freshly built runner) instead of just reusing ctx.runner.
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    assert any(ctx.findings_dir.glob("second-opinion-1-*.json"))


def test_failed_pass_is_skipped_not_fatal(env, monkeypatch):
    ctx = env(second_opinion_passes=1)
    real_recon_run = second_opinion.recon.run

    def _boom_only_for_second_opinion(sub_ctx):
        if sub_ctx.run_id.endswith("-so1"):
            raise RuntimeError("simulated recon session outage")
        return real_recon_run(sub_ctx)

    monkeypatch.setattr(second_opinion.recon, "run", _boom_only_for_second_opinion)
    # run_pipeline itself must not raise, and the primary's own findings must be unaffected.
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    assert vf["findings"]                                  # primary survivors still present
    assert not any(ctx.findings_dir.glob("second-opinion-1-*.json"))  # nothing merged from the failed pass


def test_retrying_second_opinion_after_a_failure_does_not_collide(env, monkeypatch):
    """A failed pass (session outage, backend rate-limit, ...) leaves a partial sub-run dir (incl. a
    seeded repo copy) behind. The standalone `argo second-opinion` command is documented as safe to
    re-run — it must not collide with that leftover dir on the next attempt (ingest.acquire_repo
    refuses to copy into an existing target)."""
    ctx = env(second_opinion_passes=1)
    real_recon_run = second_opinion.recon.run
    calls = {"n": 0}

    def _fail_once(sub_ctx):
        if sub_ctx.run_id.endswith("-so1"):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("simulated outage on the first attempt")
        return real_recon_run(sub_ctx)

    monkeypatch.setattr(second_opinion.recon, "run", _fail_once)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    assert not any(ctx.findings_dir.glob("second-opinion-1-*.json"))  # first attempt failed, as expected
    sub_run_dir = ctx.config.runs_dir / f"{ctx.run_id}-so1"
    assert sub_run_dir.is_dir()  # the partial seed (repo copy etc.) was left behind

    monkeypatch.setattr(second_opinion.recon, "run", real_recon_run)  # simulate the outage clearing
    second_opinion.run(ctx)  # standalone retry, same ctx/run_id — must not raise FileExistsError
    assert any(ctx.findings_dir.glob("second-opinion-1-*.json"))  # the retry succeeded
