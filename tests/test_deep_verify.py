"""Deep-verify stage (independent re-derivation, cross-finding aware) on the mock runner — zero
token spend.

Covers: per-finding verification attachment with a default ``reconfirmed`` verdict, ``corrected``
kept in place with a note, ``split`` replacing one finding with N independent children (parent kept
in an appendix), ``merged`` folding a finding away (kept in an appendix, never deleted), ``refuted``
moving to the dropped list, best-effort coercion of a bad verdict to ``inconclusive``, the
offline-stage guardrail (no network tools, full repo access), and the call-count/order in the
pipeline (after corroborate, before report; never batched — one session per finding)."""

import json
from pathlib import Path

from argo.guardrails import enforce_session_tools, session_policy
from argo.orchestrator import run_pipeline

from conftest import BRIEF, REPO

SURVIVORS = {"FULL-001", "AUTHZ-002", "FULL-003"}


def _validated(ctx) -> dict:
    return json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))


def _verify_fixture(d: Path, finding_id: str, doc: dict) -> None:
    vdir = d / "verify"
    vdir.mkdir(parents=True, exist_ok=True)
    (vdir / f"{finding_id}.json").write_text(json.dumps(doc), encoding="utf-8")


def _fail_once(d: Path, finding_id: str) -> None:
    vdir = d / "verify"
    vdir.mkdir(parents=True, exist_ok=True)
    (vdir / f"{finding_id}._fail_once").write_text("", encoding="utf-8")


# --------------------------------------------------------------------------- happy
def test_verify_attaches_blocks(env):
    ctx = env(verify_enabled=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    assert {f["id"] for f in vf["findings"]} == SURVIVORS         # nothing removed by default
    for f in vf["findings"]:
        assert f["verification"]["verdict"] == "reconfirmed"     # mock default
        assert f["verification"]["independent_derivation"]       # never blank
    assert vf["stats"]["deep_verified"]["reconfirmed"] == 3


def test_verify_runs_after_corroborate_before_report(env):
    ctx = env(verify_enabled=True, corroborate_enabled=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    stages = [json.loads(l)["stage"] for l in
              (ctx.run_dir / "llm_log.jsonl").read_text(encoding="utf-8").strip().splitlines()]
    assert stages.count("verify") == 3          # never batched: one session per survivor
    assert max(i for i, s in enumerate(stages) if s == "corroborate") \
        < min(i for i, s in enumerate(stages) if s == "verify")
    # report is deterministic (no LLM call), so it never appears in llm_log.jsonl; verify's
    # position relative to corroborate is the meaningful ordering check here.


def test_verify_off_by_default(env):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    assert all("verification" not in f for f in vf["findings"])


# --------------------------------------------------------------------------- corrected
def test_corrected_kept_with_note(env, make_scenario):
    fixtures_dir, scen = make_scenario(
        lambda d: _verify_fixture(d, "FULL-001", {
            "finding_id": "FULL-001", "verdict": "corrected",
            "rationale": "mechanism real, one detail was wrong",
            "independent_derivation": "opened src/api/search.py:42, re-traced the flow",
            "corrections": "the sink is actually at line 44, not 42"}),
        name="corrected")
    ctx = env(scen, fixtures_dir=fixtures_dir, verify_enabled=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    kept = {f["id"]: f for f in vf["findings"]}
    assert "FULL-001" in kept                                     # downgrade-don't-delete
    assert kept["FULL-001"]["verification"]["verdict"] == "corrected"
    assert "line 44" in kept["FULL-001"]["verification"]["corrections"]
    report = (ctx.run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "Corrected: the sink is actually at line 44" in report


# --------------------------------------------------------------------------- split
def test_split_replaces_finding_with_children(env, make_scenario):
    fixtures_dir, scen = make_scenario(
        lambda d: _verify_fixture(d, "FULL-001", {
            "finding_id": "FULL-001", "verdict": "split",
            "rationale": "two independently triggerable bugs bundled together",
            "independent_derivation": "traced both fields independently",
            "split_into": [
                {"title": "SQLi via q param", "severity": "High", "confidence": "Confirmed",
                 "cwe": "CWE-89", "affected": ["src/api/search.py:42"],
                 "vulnerable_flow": "q -> query", "why_vulnerable": "no sanitization",
                 "exploit_scenario": "inject via q", "impact": "data exfil",
                 "recommended_fix": "parameterize"},
                {"title": "SQLi via sort param", "severity": "High", "confidence": "Confirmed",
                 "cwe": "CWE-89", "affected": ["src/api/search.py:50"],
                 "vulnerable_flow": "sort -> query", "why_vulnerable": "no sanitization",
                 "exploit_scenario": "inject via sort", "impact": "data exfil",
                 "recommended_fix": "allow-list sort fields"},
            ]}),
        name="split")
    ctx = env(scen, fixtures_dir=fixtures_dir, verify_enabled=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    ids = {f["id"] for f in vf["findings"]}
    assert "FULL-001" not in ids                                  # replaced, not kept alongside
    assert "FULL-001-split-1" in ids and "FULL-001-split-2" in ids
    assert {f["id"] for f in vf["split_originals"]} == {"FULL-001"}
    child = next(f for f in vf["findings"] if f["id"] == "FULL-001-split-1")
    assert child["title"] == "SQLi via q param"
    assert child["verification"]["verdict"] == "reconfirmed"      # each child stands on its own
    report = (ctx.run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "Split at deep-verify" in report and "FULL-001-split-1" in report


# --------------------------------------------------------------------------- merged
def test_merged_folded_into_appendix(env, make_scenario):
    fixtures_dir, scen = make_scenario(
        lambda d: _verify_fixture(d, "FULL-003", {
            "finding_id": "FULL-003", "verdict": "merged",
            "rationale": "same root cause as AUTHZ-002, different call site",
            "independent_derivation": "traced both to the same missing check",
            "merged_into": "AUTHZ-002"}),
        name="merged")
    ctx = env(scen, fixtures_dir=fixtures_dir, verify_enabled=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    assert "FULL-003" not in {f["id"] for f in vf["findings"]}     # folded away, not reported twice
    assert {f["id"] for f in vf["merged_findings"]} == {"FULL-003"}
    report = (ctx.run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "Merged at deep-verify" in report and "AUTHZ-002" in report


# --------------------------------------------------------------------------- refuted
def test_refuted_moves_to_dropped(env, make_scenario):
    fixtures_dir, scen = make_scenario(
        lambda d: _verify_fixture(d, "FULL-003", {
            "finding_id": "FULL-003", "verdict": "refuted",
            "rationale": "egress allow-list on this exact path blocks internal ranges (src/net/fetch.py:70)",
            "independent_derivation": "read fetch.py:60-90, found the allow-list check"}),
        name="refuted")
    ctx = env(scen, fixtures_dir=fixtures_dir, verify_enabled=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    assert "FULL-003" not in {f["id"] for f in vf["findings"]}
    assert any(d["id"] == "FULL-003" for d in vf["dropped"])
    d = next(d for d in vf["dropped"] if d["id"] == "FULL-003")
    assert d["verdict"] == "refuted"


# --------------------------------------------------------------------------- best effort
def test_bad_verdict_coerced_to_inconclusive(env, make_scenario):
    fixtures_dir, scen = make_scenario(
        lambda d: _verify_fixture(d, "FULL-003", {
            "finding_id": "FULL-003", "verdict": "definitely-real"}),  # not a valid verdict
        name="badverdict")
    ctx = env(scen, fixtures_dir=fixtures_dir, verify_enabled=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    f3 = next(f for f in vf["findings"] if f["id"] == "FULL-003")
    assert f3["verification"]["verdict"] == "inconclusive"        # coerced, finding kept


def test_string_split_into_dropped_not_fatal(env, make_scenario):
    """Seen for real on authentik: the model sometimes echoes the prompt's own field description
    back as a placeholder STRING for `split_into` on a verdict where it doesn't apply (e.g.
    `reconfirmed`), instead of omitting it. That must not discard an otherwise well-formed,
    well-evidenced verdict — the bad field is dropped, not the whole verdict."""
    fixtures_dir, scen = make_scenario(
        lambda d: _verify_fixture(d, "FULL-001", {
            "finding_id": "FULL-001", "verdict": "reconfirmed",
            "rationale": "re-derived and stands as written",
            "independent_derivation": "opened src/api/search.py, traced the flow",
            "split_into": "only if verdict == split: a JSON array of ..."}),  # wrong type: str not list
        name="strsplitinto")
    ctx = env(scen, fixtures_dir=fixtures_dir, verify_enabled=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    f1 = next(f for f in vf["findings"] if f["id"] == "FULL-001")
    assert f1["verification"]["verdict"] == "reconfirmed"          # NOT discarded to inconclusive
    assert "re-derived and stands as written" in f1["verification"]["rationale"]


# --------------------------------------------------------------------------- retry-on-infra-failure
def test_retries_once_on_transient_failure_then_succeeds(env, make_scenario):
    """A recoverable session failure (CLI/sandbox crash, no output) on attempt 1 must not doom
    the finding to inconclusive when a retry would have succeeded — real per-session cost for
    verify ($1-4, 1-4M tokens seen on a real run) makes a bare retry worth it, unlike validate/
    corroborate's cheaper sessions."""
    fixtures_dir, scen = make_scenario(lambda d: _fail_once(d, "FULL-001"), name="retryok")
    ctx = env(scen, fixtures_dir=fixtures_dir, verify_enabled=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    f1 = next(f for f in vf["findings"] if f["id"] == "FULL-001")
    assert f1["verification"]["verdict"] == "reconfirmed"          # retry succeeded


def test_exhausts_retries_and_falls_back_to_inconclusive(env, make_scenario):
    """verify_max_attempts=1 means no retry at all: a single failure goes straight to
    inconclusive, same as validate/corroborate's default (no-retry) behavior."""
    fixtures_dir, scen = make_scenario(lambda d: _fail_once(d, "FULL-001"), name="retryfail")
    ctx = env(scen, fixtures_dir=fixtures_dir, verify_enabled=True, verify_max_attempts=1)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    f1 = next(f for f in vf["findings"] if f["id"] == "FULL-001")
    assert f1["verification"]["verdict"] == "inconclusive"
    assert "deep-verify session failed" in f1["verification"]["rationale"]


# --------------------------------------------------------------------------- resumable / --only
def _verify_call_count(ctx) -> int:
    return sum(1 for l in (ctx.run_dir / "llm_log.jsonl").read_text(encoding="utf-8")
               .strip().splitlines() if json.loads(l)["stage"] == "verify")


def test_resumable_skips_already_verified_findings(env):
    """Re-running deep-verify on a run that already has real verdicts must not re-spend on them —
    this is what makes `argo verify` safely re-invokable after a partial failure (credits ran out,
    a rate limit, a crash) without redoing every already-completed, expensive session."""
    from argo.stages import deep_verify

    ctx = env(verify_enabled=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    calls_after_first_pass = _verify_call_count(ctx)
    assert calls_after_first_pass == 3

    deep_verify.run(ctx)  # second invocation, same run, no new fixtures set up
    assert _verify_call_count(ctx) == calls_after_first_pass   # no new sessions launched
    vf = _validated(ctx)
    assert {f["id"] for f in vf["findings"]} == SURVIVORS
    for f in vf["findings"]:
        assert f["verification"]["verdict"] == "reconfirmed"    # unchanged from the first pass


def test_resumable_retries_infra_failure_findings(env, make_scenario):
    """The flip side of resumability: a finding that came out of a prior pass as an
    infra-failure inconclusive (session crash, credits ran out mid-run) is NOT considered "done" —
    it must get a real session on the next invocation, unlike a genuinely-answered finding."""
    from argo.stages import deep_verify

    fixtures_dir, scen = make_scenario(lambda d: _fail_once(d, "FULL-001"), name="resumeretry")
    ctx = env(scen, fixtures_dir=fixtures_dir, verify_enabled=True, verify_max_attempts=1)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    f1 = next(f for f in vf["findings"] if f["id"] == "FULL-001")
    assert f1["verification"]["verdict"] == "inconclusive"
    assert "deep-verify session failed" in f1["verification"]["rationale"]   # infra failure, not genuine

    # The sentinel fails every fresh (non-retry) attempt by design (see MockClaudeRunner's own
    # docstring) — remove it to simulate the transient problem being gone by the next invocation,
    # then confirm the finding gets a real session again rather than being treated as already done.
    (fixtures_dir / scen / "verify" / "FULL-001._fail_once").unlink()
    deep_verify.run(ctx)
    vf = _validated(ctx)
    f1 = next(f for f in vf["findings"] if f["id"] == "FULL-001")
    assert f1["verification"]["verdict"] == "reconfirmed"        # re-attempted and got a real verdict


def test_only_scopes_to_specific_findings(env, make_scenario):
    """--only (config verify_only) re-verifies exactly the given ids and leaves every other
    survivor's existing verification completely untouched, regardless of its state."""
    from argo.stages import deep_verify

    ctx = env(verify_enabled=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    for f in _validated(ctx)["findings"]:
        assert f["verification"]["verdict"] == "reconfirmed"     # baseline from the first pass

    fixtures_dir, scen = make_scenario(
        lambda d: _verify_fixture(d, "FULL-001", {
            "finding_id": "FULL-001", "verdict": "corrected",
            "rationale": "re-derived on the targeted re-verify pass",
            "independent_derivation": "opened src/api/search.py:42, re-traced the flow",
            "corrections": "the sink is actually at line 44, not 42"}),
        name="onlyscope")
    ctx.runner.scenario_dir = fixtures_dir / scen   # mock runner bakes scenario_dir in at
                                                     # construction; point it at the new fixtures
    ctx.config = ctx.config.with_overrides(verify_only=frozenset({"FULL-001"}))

    deep_verify.run(ctx)
    vf = _validated(ctx)
    kept = {f["id"]: f for f in vf["findings"]}
    assert kept["FULL-001"]["verification"]["verdict"] == "corrected"          # re-verified
    assert kept["AUTHZ-002"]["verification"]["verdict"] == "reconfirmed"       # untouched
    assert kept["FULL-003"]["verification"]["verdict"] == "reconfirmed"        # untouched


# --------------------------------------------------------------------------- guardrail
def test_verify_is_offline_with_full_repo_access():
    assert session_policy("verify").network is False
    allowed, disallowed = enforce_session_tools(
        ["Read", "Grep", "Glob", "Write", "Bash", "WebSearch", "Task"], stage="verify")
    assert set(allowed) == {"Read", "Grep", "Glob", "Write"}
    assert "WebSearch" not in allowed and "Bash" not in allowed and "Task" not in allowed
