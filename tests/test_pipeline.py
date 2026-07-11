"""End-to-end pipeline tests on the mock runner (zero token spend), incl. the failure paths:
dedup/merge, scope-filter + validation drops, missing-manifest fallback, partial-session
recovery, oversized-findings no-truncation, ledger cost logging + resubmission flagging, and
the structural no-submit guardrail.
"""

import json
from pathlib import Path

from argo.orchestrator import (do_audit, do_ingest, do_recon, do_report, do_validate,
                                   run_pipeline)
from argo.schemas import validate_findings

from conftest import BRIEF, REPO

GOLDEN = Path(__file__).parent / "golden" / "REPORT.md"

SURVIVORS = {"FULL-001", "AUTHZ-002", "FULL-003"}
DROPPED = {"FULL-002", "AUTHZ-003"}
CONFIRMED_DRAFTS = {"FULL-001.md", "AUTHZ-002.md"}


def _validated(ctx) -> dict:
    return json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- happy path
def test_full_pipeline_happy(env):
    ctx = env()
    summary = run_pipeline(ctx, BRIEF, str(REPO))
    vf = _validated(ctx)
    assert vf["stats"] == {"raw": 6, "after_dedup": 5, "after_semantic_dedup": 5, "validated": 4,
                           "survivors": 3, "dropped": 2, "survivors_not_actually_validated": 0}
    assert {f["id"] for f in vf["findings"]} == SURVIVORS
    assert {d["id"] for d in vf["dropped"]} == DROPPED
    # drafts: confirmed findings only, each marked DRAFT
    drafts = {p.name for p in ctx.drafts_dir.glob("*.md")}
    assert drafts == CONFIRMED_DRAFTS
    for p in ctx.drafts_dir.glob("*.md"):
        assert "DRAFT - NOT SUBMITTED" in p.read_text(encoding="utf-8")
    assert Path(summary["report"]).exists()
    # recon captured the archetype into meta.json (from the repo_profile fixture)
    meta = json.loads(ctx.meta_path.read_text(encoding="utf-8"))
    assert meta["archetype"] == "web_api_cms"


def test_research_stage_on_by_default(env):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO))                 # research on by default
    assert ctx.research_brief_path.exists()
    intel = json.loads(ctx.threat_intel_path.read_text(encoding="utf-8"))
    assert "suspected_vuln_classes" in intel
    # the research call is logged as its own stage, before recon
    assert ctx.ledger.run_call_count(ctx.run_id) == 6   # 5 core + 1 research (validate batched to 1)
    stages = [json.loads(l)["stage"] for l in
              (ctx.run_dir / "llm_log.jsonl").read_text(encoding="utf-8").strip().splitlines()]
    assert "research" in stages and stages.index("research") < stages.index("recon")


def test_local_review_synthesizes_scope_no_brief(env, tmp_path):
    """A local folder with NO brief -> source-only scope synthesized, zero-token ingest."""
    from argo.stages import ingest
    ctx = env()
    repo = tmp_path / "my-private-app"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    scope = ingest.run(ctx, brief_path=None, repo=str(repo))
    assert scope.program_name == "my-private-app" and scope.target_type == "source_only"
    assert scope.in_scope and scope.in_scope[0].type == "source_repo"
    assert scope.prohibited_techniques                       # conservative defaults applied
    assert ctx.ledger.run_call_count(ctx.run_id) == 0        # ingest spent ZERO tokens
    assert ctx.scope_path.exists() and (ctx.repo_dir / "a.py").exists()
    meta = json.loads(ctx.meta_path.read_text(encoding="utf-8"))
    assert meta["repo_is_url"] is False and meta["program_name"] == "my-private-app"


def test_local_review_full_pipeline_repairs_prohibited(env, tmp_path):
    """Full local-folder run (no brief): recon's deterministic repair re-inserts the synthesized
    prohibited defaults into the model-generated prompts, so the well-formedness gate passes and
    the pipeline completes end-to-end (the real-backend failure this guards against)."""
    from argo.stages.ingest import _DEFAULT_PROHIBITED
    ctx = env()
    repo = tmp_path / "personal-app"
    repo.mkdir()
    (repo / "auth.py").write_text("q = 'SELECT * FROM u WHERE n=' + name\n", encoding="utf-8")
    summary = run_pipeline(ctx, None, str(repo), research_enabled=False)   # brief=None -> local
    assert Path(summary["report"]).exists()
    prompts = list(ctx.prompts_out_dir.glob("audit_*.md"))
    assert prompts
    for p in prompts:                                   # every prompt carries every default
        text = p.read_text(encoding="utf-8")
        for prohibited in _DEFAULT_PROHIBITED:
            assert prohibited in text


def test_no_research_keeps_run_offline(env):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    assert not ctx.research_brief_path.exists()
    assert ctx.ledger.run_call_count(ctx.run_id) == 5   # ingest+recon+audit(2)+validate(1 batch)
    stages = [json.loads(l)["stage"] for l in
              (ctx.run_dir / "llm_log.jsonl").read_text(encoding="utf-8").strip().splitlines()]
    assert "research" not in stages


def test_report_matches_golden(env):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)   # golden = the 5-stage core
    produced = (ctx.run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert produced == GOLDEN.read_text(encoding="utf-8")   # attribution off in tests -> byte-stable


def test_findings_files_schema_conformant(env):
    ctx = env()
    do_ingest(ctx, BRIEF, str(REPO))
    do_recon(ctx)
    do_audit(ctx)
    files = list(ctx.findings_dir.glob("*.json"))
    assert files
    for f in files:
        validate_findings(json.loads(f.read_text(encoding="utf-8")))


# --------------------------------------------------------------------------- dedup
def test_dedup_merges_cross_focus_duplicate(env):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO))
    vf = _validated(ctx)
    # SQLi reported by both focuses collapses to one survivor (FULL-001).
    sqli = [f for f in vf["findings"] if f["cwe"] == "CWE-89"]
    assert len(sqli) == 1
    keeper = sqli[0]
    assert keeper["id"] == "FULL-001"
    # variant text from the AUTHZ duplicate is unioned in.
    assert "/api/v2/search" in (keeper.get("variants") or "")


# --------------------------------------------------------------------------- filtering
def test_codeside_scope_filter_drops_legacy(env):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO))
    vf = _validated(ctx)
    dropped = {d["id"]: d for d in vf["dropped"]}
    assert "FULL-002" in dropped
    assert "out_of_scope" in dropped["FULL-002"]["reason"]
    # never validated (dropped pre-validation): no validate session dir for it
    assert not (ctx.work_dir("validate", "FULL-002")).exists()


def test_refuted_dropped_confirmed_and_nrv_kept(env):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO))
    vf = _validated(ctx)
    verdicts = {f["id"]: f["validation"]["verdict"] for f in vf["findings"]}
    assert verdicts == {"FULL-001": "confirmed", "AUTHZ-002": "confirmed",
                        "FULL-003": "needs_runtime_verification"}
    assert "AUTHZ-003" in {d["id"] for d in vf["dropped"]}  # refuted -> dropped


def test_drafts_only_for_confirmed(env):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO))
    # FULL-003 is needs_runtime_verification -> appears in report, but NOT a confirmed draft
    drafts = {p.stem for p in ctx.drafts_dir.glob("*.md")}
    assert "FULL-003" not in drafts
    assert drafts == {"FULL-001", "AUTHZ-002"}


# --------------------------------------------------------------------------- fallbacks
def test_missing_manifest_recon_glob_fallback(env, make_scenario):
    fixtures_dir, scen = make_scenario(
        lambda d: (d / "recon" / "_no_manifest").write_text("", encoding="utf-8"),
        name="nomanifest")
    ctx = env(scen, fixtures_dir=fixtures_dir)
    run_pipeline(ctx, BRIEF, str(REPO))
    # Prompts were still recovered (by globbing the scratch dir) -> pipeline completed.
    assert {p.name for p in ctx.prompts_out_dir.glob("audit_*.md")} == {
        "audit_p1_full_scope.md", "audit_p2_authz.md"}
    assert {f["id"] for f in _validated(ctx)["findings"]} == SURVIVORS


def test_partial_audit_session_recovered(env, make_scenario):
    fixtures_dir, scen = make_scenario(
        lambda d: (d / "audit" / "audit_p1_full_scope._partial").write_text("", "utf-8"),
        name="partial")
    ctx = env(scen, fixtures_dir=fixtures_dir)
    do_ingest(ctx, BRIEF, str(REPO))
    do_recon(ctx)
    do_audit(ctx)
    # Even though the session reported is_error, the partial findings file is recovered.
    recovered = ctx.findings_dir / "audit_p1_full_scope.json"
    assert recovered.exists()
    validate_findings(json.loads(recovered.read_text(encoding="utf-8")))


def test_oversized_findings_no_truncation(env, make_scenario):
    N = 60

    def mutate(d: Path):
        doc = {
            "program_name": "Acme Widgets",
            "audit_focus": "Full-scope architecture-led audit",
            "generated_at": "2026-06-16T12:00:00Z",
            "findings": [{
                "id": f"BIG-{i:03d}",
                "title": f"Synthetic finding {i} " + ("x" * 400),
                "severity": "Medium", "confidence": "Medium", "cwe": "CWE-200",
                "affected": [f"src/api/util.py:{i}"],
                "vulnerable_flow": "flow " * 50,
                "why_vulnerable": "why " * 50, "exploit_scenario": "ex " * 50,
                "impact": "impact " * 50, "recommended_fix": "fix " * 50,
            } for i in range(N)],
        }
        (d / "audit" / "audit_p1_full_scope.findings.json").write_text(
            json.dumps(doc), encoding="utf-8")

    fixtures_dir, scen = make_scenario(mutate, name="oversized")
    ctx = env(scen, fixtures_dir=fixtures_dir)
    do_ingest(ctx, BRIEF, str(REPO))
    do_recon(ctx)
    do_audit(ctx)
    saved = json.loads((ctx.findings_dir / "audit_p1_full_scope.json").read_text("utf-8"))
    # All N findings survive the file round-trip — no stdout truncation in play.
    assert len(saved["findings"]) == N


# --------------------------------------------------------------------------- ledger
def test_cost_calls_logged(env):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    # ingest(1) + recon(1) + audit(2) + validate(1 batch) = 5 calls
    assert ctx.ledger.run_call_count(ctx.run_id) == 5
    lines = (ctx.run_dir / "llm_log.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 5
    rec = json.loads(lines[0])
    assert {"stage", "model", "prompt_sha256", "cost_usd"} <= rec.keys()


def test_resubmission_flagged_across_runs(env):
    first = env(run_id="RUN-A")
    run_pipeline(first, BRIEF, str(REPO))
    second = env(run_id="RUN-B")                 # shares the same ledger file
    run_pipeline(second, BRIEF, str(REPO))
    report = (second.run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "Possible resubmissions" in report
    assert "RUN-A" in report


# --------------------------------------------------------------------------- dry run
def test_dry_run_stops_before_audit(env):
    ctx = env()
    summary = run_pipeline(ctx, BRIEF, str(REPO), dry_run=True)
    assert "dry-run" in summary["stopped_after"]
    assert ctx.prompts_out_dir.glob("audit_*.md")          # prompts produced
    assert not ctx.findings_dir.exists()                    # no audit ran
    assert not (ctx.run_dir / "REPORT.md").exists()


# --------------------------------------------------------------------------- no submit
def test_cli_has_no_submit_command():
    from argo.cli import app
    names = set()
    for c in app.registered_commands:
        names.add(c.name or c.callback.__name__)
    assert "ingest" in names and "pipeline" in names
    assert not any("submit" in n.lower() for n in names)
