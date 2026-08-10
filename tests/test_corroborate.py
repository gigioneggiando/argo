"""Corroboration stage (docs + VCS-history cross-check) on the mock runner — zero token spend.

Covers: per-finding verdict attachment, the fixed_upstream partition into an appendix (kept, not
deleted), design_accepted suppressing a submission draft, best-effort coercion of a bad verdict to
``unknown``, the networked-stage guardrail (OSINT permitted, shell dropped), and the call-count/order
in the pipeline.
"""

import json
from pathlib import Path

from argo.guardrails import enforce_session_tools, session_policy
from argo.orchestrator import run_pipeline

from conftest import BRIEF, REPO

SURVIVORS = {"FULL-001", "AUTHZ-002", "FULL-003"}


def _validated(ctx) -> dict:
    return json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))


def _corr_fixture(d: Path, finding_id: str, doc: dict) -> None:
    cdir = d / "corroborate"
    cdir.mkdir(parents=True, exist_ok=True)
    (cdir / f"{finding_id}.json").write_text(json.dumps(doc), encoding="utf-8")


# --------------------------------------------------------------------------- happy
def test_corroborate_attaches_blocks(env):
    ctx = env(corroborate_enabled=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    assert {f["id"] for f in vf["findings"]} == SURVIVORS         # nothing removed by default
    for f in vf["findings"]:
        assert f["corroboration"]["verdict"] == "corroborated"   # mock default
    assert vf["stats"]["corroborated"] == {
        "corroborated": 3, "design_accepted": 0, "fixed_upstream": 0, "unknown": 0}


def test_corroborate_runs_after_validate_before_report(env):
    ctx = env(corroborate_enabled=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    stages = [json.loads(l)["stage"] for l in
              (ctx.run_dir / "llm_log.jsonl").read_text(encoding="utf-8").strip().splitlines()]
    # 5 core + 1 corroborate (survivors batched into one session)
    assert stages.count("corroborate") == 1
    assert max(i for i, s in enumerate(stages) if s == "validate") \
        < min(i for i, s in enumerate(stages) if s == "corroborate")
    assert ctx.ledger.run_call_count(ctx.run_id) == 6


# --------------------------------------------------------------------------- fixed_upstream
def test_fixed_upstream_partitioned_to_appendix(env, make_scenario):
    fixtures_dir, scen = make_scenario(
        lambda d: _corr_fixture(d, "FULL-001", {
            "finding_id": "FULL-001", "verdict": "fixed_upstream",
            "rationale": "patched in a newer release", "fix_commit": "abc1234",
            "evidence_urls": ["https://github.com/acme/widgets/commit/abc1234"]}),
        name="fixedup")
    ctx = env(scen, fixtures_dir=fixtures_dir, corroborate_enabled=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    # moved OUT of active findings, INTO the appendix list (not deleted)
    assert "FULL-001" not in {f["id"] for f in vf["findings"]}
    assert {f["id"] for f in vf["fixed_upstream"]} == {"FULL-001"}
    assert vf["stats"]["fixed_upstream"] == 1
    report = (ctx.run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "Already fixed upstream" in report and "abc1234" in report
    # and no submission draft is produced for a fixed-upstream finding
    assert "FULL-001.md" not in {p.name for p in ctx.drafts_dir.glob("*.md")}


# --------------------------------------------------------------------------- design_accepted
def test_design_accepted_kept_but_no_draft(env, make_scenario):
    fixtures_dir, scen = make_scenario(
        lambda d: _corr_fixture(d, "AUTHZ-002", {
            "finding_id": "AUTHZ-002", "verdict": "design_accepted",
            "rationale": "documented as intended", "doc_url": "https://docs.acme/security"}),
        name="byd")
    ctx = env(scen, fixtures_dir=fixtures_dir, corroborate_enabled=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    kept = {f["id"]: f for f in vf["findings"]}
    assert "AUTHZ-002" in kept                                   # stays (downgrade-don't-delete)
    assert kept["AUTHZ-002"]["corroboration"]["verdict"] == "design_accepted"
    # AUTHZ-002 is a confirmed finding, but design_accepted suppresses its draft
    drafts = {p.stem for p in ctx.drafts_dir.glob("*.md")}
    assert "AUTHZ-002" not in drafts and "FULL-001" in drafts
    report = (ctx.run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "Vendor-documented design decision" in report


# ------------------------------------------------------------- verdict self-consistency backstop
def test_verdict_self_corrected_when_rationale_asserts_design_accepted(env, make_scenario):
    """The model can (and, once for real on gitea, did) write a rationale that itself asserts
    vendor-confirmed intent while leaving verdict at "corroborated" — a genuine self-contradiction.
    The deterministic backstop must catch this, correct the verdict, and preserve the original call."""
    fixtures_dir, scen = make_scenario(
        lambda d: _corr_fixture(d, "AUTHZ-002", {
            "finding_id": "AUTHZ-002", "verdict": "corroborated",
            "rationale": "The GitHub issue tracker shows this is documented as intended by the "
                         "maintainers; see issue #42.",
        }),
        name="selfcontradict")
    ctx = env(scen, fixtures_dir=fixtures_dir, corroborate_enabled=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    kept = {f["id"]: f for f in vf["findings"]}
    corr = kept["AUTHZ-002"]["corroboration"]
    assert corr["verdict"] == "design_accepted"                  # corrected, not left at corroborated
    assert corr["verdict_overridden_from"] == "corroborated"     # original call preserved, not lost
    assert vf["stats"]["verdict_self_corrected"] == 1
    # no submission draft for a (corrected) design_accepted finding
    assert "AUTHZ-002" not in {p.stem for p in ctx.drafts_dir.glob("*.md")}
    report = (ctx.run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "auto-corrected from `corroborated` to `design_accepted`" in report


def test_verdict_not_corrected_for_an_ordinary_corroborated_rationale(env, make_scenario):
    """Precision check: a rationale that merely mentions "documentation" in passing (without
    asserting the behavior itself is vendor-confirmed as intended) must NOT trigger the backstop —
    a false positive here would wrongly downgrade a real, still-open vulnerability."""
    fixtures_dir, scen = make_scenario(
        lambda d: _corr_fixture(d, "AUTHZ-002", {
            "finding_id": "AUTHZ-002", "verdict": "corroborated",
            "rationale": "The documentation does not mention this behavior anywhere, and no "
                         "issue or PR addresses it, so it still appears to be a real, unaddressed bug.",
        }),
        name="notriggerfp")
    ctx = env(scen, fixtures_dir=fixtures_dir, corroborate_enabled=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    kept = {f["id"]: f for f in vf["findings"]}
    corr = kept["AUTHZ-002"]["corroboration"]
    assert corr["verdict"] == "corroborated"
    assert corr.get("verdict_overridden_from") is None
    assert vf["stats"]["verdict_self_corrected"] == 0


# --------------------------------------------------------------------------- best effort
def test_bad_verdict_coerced_to_unknown(env, make_scenario):
    fixtures_dir, scen = make_scenario(
        lambda d: _corr_fixture(d, "FULL-003", {
            "finding_id": "FULL-003", "verdict": "definitely-real"}),  # not a valid verdict
        name="badverdict")
    ctx = env(scen, fixtures_dir=fixtures_dir, corroborate_enabled=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    f3 = next(f for f in vf["findings"] if f["id"] == "FULL-003")
    assert f3["corroboration"]["verdict"] == "unknown"           # coerced, finding kept


# --------------------------------------------------------------------------- guardrail
def test_corroborate_is_networked_but_no_shell():
    assert session_policy("corroborate").network is True
    allowed, disallowed = enforce_session_tools(
        ["WebSearch", "WebFetch", "Read", "Write", "Bash", "Task"], stage="corroborate")
    assert "WebSearch" in allowed and "WebFetch" in allowed     # OSINT kept
    assert "Bash" not in allowed and "Task" not in allowed      # shell / sub-agents dropped
    # a non-networked stage still loses OSINT entirely
    assert session_policy("validate").network is False
    a2, _ = enforce_session_tools(["WebSearch", "Read"], stage="validate")
    assert "WebSearch" not in a2
