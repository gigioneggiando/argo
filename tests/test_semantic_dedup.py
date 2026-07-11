"""Cross-focus semantic dedup (validate._semantic_dedup): structural dedup_key merging only
collapses EXACT (file, line, CWE) matches, so the same root-cause bug reported by two different
audit foci at two different call sites survives as two separate findings (this is exactly what
happened on the gguf-tools run: one "general.alignment=0 -> divide by zero" bug was reported 3
times, from 3 different foci, each citing a different exact line). One extra cheap batched session
(summaries only) clusters those before the much more expensive per-finding validate/corroborate
fan-out — gated on a minimum finding count so it never fires on a small run, and failing open
(findings kept separate) on any session/parse failure."""

import json

from argo.orchestrator import run_pipeline

from conftest import BRIEF, REPO

EXTRA_FINDINGS = [
    {
        "id": "EXTRA-001", "title": "Config value X never validated at its source",
        "severity": "Medium", "confidence": "High", "cwe": "CWE-20",
        "affected": ["src/mod/a.py:10"],
        "vulnerable_flow": "config X is read from the request with no bound", "why_vulnerable": "x",
        "exploit_scenario": "x", "impact": "x", "recommended_fix": "validate X at its source",
    },
    {
        "id": "EXTRA-002", "title": "Config value X used unsafely as a divisor downstream",
        "severity": "Medium", "confidence": "High", "cwe": "CWE-369",
        "affected": ["src/mod/b.py:99"],
        "vulnerable_flow": "config X (unchecked) reaches a modulo with no zero-guard", "why_vulnerable": "x",
        "exploit_scenario": "x", "impact": "x", "recommended_fix": "validate X at its source",
    },
]


def _add_extra_findings(scen):
    # The mock's audit stage only serves a fixture for a slug recon actually asked for, so we
    # cannot just drop a new "audit_p3_extra.findings.json" in — append into an EXISTING focus's
    # fixture file instead (same effect: more raw findings feeding validate's structural merge).
    path = scen / "audit" / "audit_p1_full_scope.findings.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["findings"].extend(EXTRA_FINDINGS)
    path.write_text(json.dumps(doc), encoding="utf-8")


def _add_extra_and_dedup_fixture(scen):
    _add_extra_findings(scen)
    (scen / "validate" / "dedup_clusters.json").write_text(json.dumps({
        "clusters": [{"primary_id": "EXTRA-001", "duplicate_ids": ["EXTRA-002"],
                      "reason": "same unchecked config value X, different call site"}]
    }), encoding="utf-8")


def _validated(ctx) -> dict:
    return json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))


def test_semantic_dedup_collapses_a_cross_focus_duplicate(env, make_scenario):
    fixtures_dir, scen = make_scenario(_add_extra_and_dedup_fixture, name="semdedup")
    ctx = env(scen, fixtures_dir=fixtures_dir, semantic_dedup_min_findings=6)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)

    ids = {f["id"] for f in vf["findings"]}
    assert "EXTRA-002" not in ids                       # merged away
    assert "EXTRA-001" in ids                            # kept as the primary

    dup_record = next(d for d in vf["dropped"] if d["id"] == "EXTRA-002")
    assert dup_record["reason"] == "duplicate_of:EXTRA-001 (semantic dedup)"

    # 8 raw (6 happy + 2 extra) -> 7 after structural merge (happy's own 6->5 + 2 new, untouched by
    # structural dedup since they don't share file/line/cwe with anything) -> 6 after semantic dedup.
    assert vf["stats"]["after_dedup"] == 7
    assert vf["stats"]["after_semantic_dedup"] == 6

    # the primary absorbs the duplicate's affected refs (union, like the structural merge does)
    primary = next(f for f in vf["findings"] if f["id"] == "EXTRA-001")
    assert "src/mod/a.py:10" in primary["affected"]
    assert "src/mod/b.py:99" in primary["affected"]


def test_semantic_dedup_skipped_below_threshold(env, make_scenario):
    # Same extra findings, but WITHOUT raising the count past the (higher, non-default) threshold —
    # the dedup session must never even be attempted, so a missing dedup_clusters.json fixture is
    # fine and both EXTRA findings survive untouched.
    fixtures_dir, scen = make_scenario(_add_extra_findings, name="semdedup_below")
    ctx = env(scen, fixtures_dir=fixtures_dir, semantic_dedup_min_findings=100)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    ids = {f["id"] for f in vf["findings"]}
    assert {"EXTRA-001", "EXTRA-002"} <= ids
    assert vf["stats"]["after_dedup"] == vf["stats"]["after_semantic_dedup"] == 7


def test_semantic_dedup_disabled_flag(env, make_scenario):
    fixtures_dir, scen = make_scenario(_add_extra_and_dedup_fixture, name="semdedup_disabled")
    ctx = env(scen, fixtures_dir=fixtures_dir, semantic_dedup_min_findings=6,
              semantic_dedup_enabled=False)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    # disabled -> dedup_clusters.json fixture is never even read; both EXTRA findings survive
    ids = {f["id"] for f in vf["findings"]}
    assert {"EXTRA-001", "EXTRA-002"} <= ids


def test_semantic_dedup_fails_open_on_bad_fixture(env, make_scenario):
    def _bad_fixture(scen):
        _add_extra_findings(scen)
        (scen / "validate" / "dedup_clusters.json").write_text("not json{{{", encoding="utf-8")
    fixtures_dir, scen = make_scenario(_bad_fixture, name="semdedup_bad")
    ctx = env(scen, fixtures_dir=fixtures_dir, semantic_dedup_min_findings=6)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)   # must not raise
    vf = _validated(ctx)
    # malformed dedup output -> fail open, keep everything separate
    ids = {f["id"] for f in vf["findings"]}
    assert {"EXTRA-001", "EXTRA-002"} <= ids
    assert vf["stats"]["after_dedup"] == vf["stats"]["after_semantic_dedup"] == 7
