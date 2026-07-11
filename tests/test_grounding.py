"""Citation grounding (validate._ground_citations + argo.grounding): a deterministic, zero-LLM
pre-validation check that a finding's cited files / project-specific code symbols actually exist in
the repo under audit. Motivated by a real miss — a ds4 report draft carried a `gguf_get_tensor`
divide-by-zero that belongs to the SEPARATE gguf-tools repo (the symbol exists nowhere in ds4). A
hallucinated primary file is dropped; hallucinated symbols downgrade confidence and are surfaced to
the adversarial validator."""

import json

from argo.grounding import RepoIndex, build_index, extract_cited_symbols, ground_finding
from argo.models import Finding
from argo.orchestrator import run_pipeline

from conftest import BRIEF, REPO


# --------------------------------------------------------------------------- unit: symbol extraction
def test_extract_only_project_specific_symbols():
    syms = extract_cited_symbols(
        "the `parse_chat_request` handler calls get_order() and read()",
        "a bare strtod() then json_string() leaves gguf_get_tensor() dangling",
    )
    # project-specific (underscore / long): kept
    assert {"parse_chat_request", "get_order", "json_string", "gguf_get_tensor"} <= syms
    # too-generic / too-short / stopword: never treated as a citation
    assert "read" not in syms and "strtod" not in syms


def test_extract_backticked_identifier():
    syms = extract_cited_symbols("see `agent_kv_read_text` and `format`")
    assert "agent_kv_read_text" in syms
    assert "format" not in syms          # 6 chars, no underscore/interior-cap -> generic


# --------------------------------------------------------------------------- unit: RepoIndex
def test_repo_index_symbol_and_file_presence():
    idx = build_index(REPO, [])                          # no symbols wanted yet
    # a real fixture file is grounded by exact path and by basename-only (path-prefix tolerance)
    assert idx.file_grounded("src/api/orders.py:3")
    assert idx.file_grounded("some/wrong/prefix/orders.py:3")
    # a made-up file is not grounded
    assert not idx.file_grounded("src/api/ghost.py:5")

    idx2 = RepoIndex(REPO, {"get_order", "gguf_get_tensor"})
    assert idx2.symbol_present("get_order")              # really defined in the fixture repo
    assert not idx2.symbol_present("gguf_get_tensor")    # exists nowhere


def _finding(**over) -> Finding:
    base = dict(
        id="F-1", title="t", severity="High", confidence="High", cwe="CWE-20",
        affected=["src/api/orders.py:3"], vulnerable_flow="f", why_vulnerable="w",
        exploit_scenario="e", impact="i", recommended_fix="r",
    )
    base.update(over)
    return Finding.model_validate(base)


def test_ground_finding_flags_missing_file_and_symbol():
    bad = _finding(affected=["src/api/ghost.py:5"], why_vulnerable="calls gguf_get_tensor()")
    good = _finding(why_vulnerable="calls get_order()")
    idx = build_index(REPO, [bad, good])            # index must cover every finding it grounds
    res = ground_finding(idx, bad)
    assert res["missing_files"] == ["src/api/ghost.py:5"]
    assert res["missing_symbols"] == ["gguf_get_tensor"]

    clean = ground_finding(idx, good)               # get_order really exists in the fixture repo
    assert clean["missing_files"] == [] and clean["missing_symbols"] == []


# --------------------------------------------------------------------------- integration: pipeline
_UNGROUNDED_FILE = {
    "id": "GHOST-FILE", "title": "Bug in a file that isn't here",
    "severity": "High", "confidence": "High", "cwe": "CWE-476",
    "affected": ["src/api/ghost.py:5"],
    "vulnerable_flow": "x", "why_vulnerable": "x",
    "exploit_scenario": "x", "impact": "x", "recommended_fix": "x",
}
_UNGROUNDED_SYMBOL = {
    "id": "GHOST-SYM", "title": "Divide-by-zero in gguf_get_tensor",
    "severity": "High", "confidence": "High", "cwe": "CWE-369",
    "affected": ["src/api/orders.py:3"],   # real file
    "vulnerable_flow": "gguf_get_tensor() divides by a header-controlled value",
    "why_vulnerable": "gguf_get_tensor() has no zero guard",
    "exploit_scenario": "x", "impact": "x", "recommended_fix": "guard the divisor",
}


def _inject(scen, finding):
    path = scen / "audit" / "audit_p1_full_scope.findings.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["findings"].append(finding)
    path.write_text(json.dumps(doc), encoding="utf-8")


def _validated(ctx) -> dict:
    return json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))


def test_ungrounded_file_is_dropped_pre_validation(env, make_scenario):
    fixtures_dir, scen = make_scenario(lambda s: _inject(s, _UNGROUNDED_FILE), name="ground_file")
    ctx = env(scen, fixtures_dir=fixtures_dir)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)

    assert "GHOST-FILE" not in {f["id"] for f in vf["findings"]}     # dropped
    rec = next(d for d in vf["dropped"] if d["id"] == "GHOST-FILE")
    assert "ungrounded_citation" in rec["reason"]
    assert vf["stats"]["grounding_dropped"] >= 1


def test_ungrounded_symbol_downgrades_confidence(env, make_scenario):
    fixtures_dir, scen = make_scenario(lambda s: _inject(s, _UNGROUNDED_SYMBOL), name="ground_sym")
    ctx = env(scen, fixtures_dir=fixtures_dir)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)

    ghost = next((f for f in vf["findings"] if f["id"] == "GHOST-SYM"), None)
    if ghost is not None:                                            # kept (validator's call)
        assert ghost["confidence"] == "Medium"                      # High -> one notch down
        assert ghost["grounding"]["status"] == "ungrounded"
        assert "gguf_get_tensor" in ghost["grounding"]["missing_symbols"]
    else:                                                           # or the validator refuted it
        assert "GHOST-SYM" in {d["id"] for d in vf["dropped"]}


def test_grounded_findings_pass_through_untouched(env):
    ctx = env("happy")
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    vf = _validated(ctx)
    # every happy finding cites a real fixture file and only the real symbol get_order -> nothing
    # dropped by grounding, and any attached grounding block reads "grounded".
    assert vf["stats"]["grounding_dropped"] == 0
    for f in vf["findings"]:
        if f.get("grounding"):
            assert f["grounding"]["status"] == "grounded"
