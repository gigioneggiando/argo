"""Phase 7 — benchmark scoring + harness tests (zero tokens on the mock runner)."""

import json
from pathlib import Path

from argo.benchmark import ab_compare, load_suite, run_suite, score_run

SUITE = Path(__file__).resolve().parent.parent / "benchmarks"

# the three confirmed survivors the mock pipeline produces
_F = [
    {"id": "FULL-001", "cwe": "CWE-89", "affected": ["src/api/search.py:42"]},
    {"id": "AUTHZ-002", "cwe": "CWE-639", "affected": ["src/api/orders.py:120"]},
    {"id": "FULL-003", "cwe": "CWE-918", "affected": ["src/net/fetch.py:88"]},
]
_E = [
    {"label": "sqli", "cwe": "CWE-89", "file": "src/api/search.py"},
    {"label": "idor", "cwe": "CWE-639", "file": "src/api/orders.py"},
    {"label": "ssrf", "cwe": "CWE-918", "file": "src/net/fetch.py"},
]


def test_score_perfect():
    s = score_run(_F, _E)
    assert (s["tp"], s["fp"], s["fn"]) == (3, 0, 0)
    assert s["precision"] == 1.0 and s["recall"] == 1.0 and s["f1"] == 1.0


def test_score_false_negative():
    expected = _E + [{"label": "xss", "cwe": "CWE-79", "file": "src/api/util.py"}]
    s = score_run(_F, expected)
    assert (s["tp"], s["fp"], s["fn"]) == (3, 0, 1)
    assert s["recall"] == 0.75 and s["precision"] == 1.0
    assert s["missed"] == ["xss"]


def test_score_false_positive():
    s = score_run(_F, _E[:2])            # only sqli + idor labeled -> ssrf is spurious
    assert (s["tp"], s["fp"], s["fn"]) == (2, 1, 0)
    assert round(s["precision"], 3) == 0.667 and s["recall"] == 1.0
    assert s["spurious"] == ["FULL-003"]


def test_score_cwe_mismatch_is_not_a_match():
    wrong = [{"label": "sqli", "cwe": "CWE-79", "file": "src/api/search.py"}]
    s = score_run([_F[0]], wrong)
    assert (s["tp"], s["fp"], s["fn"]) == (0, 1, 1)


def test_score_alias_matches():
    # finding reports CWE-862, label expects CWE-639 with 862 as an alias
    f = [{"id": "X", "cwe": "CWE-862", "affected": ["src/api/orders.py:120"]}]
    e = [{"label": "idor", "cwe": "CWE-639", "aliases": ["CWE-862"], "file": "src/api/orders.py"}]
    assert score_run(f, e)["tp"] == 1


def test_score_line_tolerance():
    f = [{"id": "X", "cwe": "CWE-89", "affected": ["src/api/search.py:200"]}]
    e_tight = [{"label": "s", "cwe": "CWE-89", "file": "src/api/search.py", "line": 42,
                "line_tolerance": 10}]
    e_loose = [{"label": "s", "cwe": "CWE-89", "file": "src/api/search.py", "line": 42,
                "line_tolerance": 1000}]
    assert score_run(f, e_tight)["tp"] == 0     # 200 is >10 from 42
    assert score_run(f, e_loose)["tp"] == 1


def test_load_suite():
    cases = load_suite(SUITE)
    names = {c.name for c in cases}
    assert "acme-widgets" in names
    acme = next(c for c in cases if c.name == "acme-widgets")
    assert acme.archetype == "web_api_cms" and len(acme.expected) == 3
    assert Path(acme.brief).exists()


def test_run_suite_mock(env):
    cfg = env().config            # a mock PipelineConfig wired to the fixtures
    report = run_suite(cfg, SUITE)
    t = report["totals"]
    assert t["precision"] == 1.0 and t["recall"] == 1.0 and t["f1"] == 1.0 and t["cases"] == 1
    assert "web_api_cms" in report["by_archetype"]
    assert report["by_archetype"]["web_api_cms"]["recall"] == 1.0
    assert "CWE-89" in report["by_cwe"]
    # report persisted under runs_dir
    assert (Path(cfg.runs_dir) / "benchmark_report.json").exists()


def _mock_case(cdir: Path, name: str) -> None:
    """Write a case.json + labels under cdir that the mock 'happy' scenario scores perfectly."""
    fx = Path(__file__).resolve().parent / "fixtures"
    cdir.mkdir(parents=True, exist_ok=True)
    (cdir / "case.json").write_text(json.dumps({
        "name": name, "brief": str(fx / "brief.txt"), "repo": str(fx / "repo"),
        "scenario": "happy", "archetype": "web_api_cms", "expected": "expected_findings.json",
        "corpus_id": "demo-corpus", "cve_ids": ["CVE-2024-0001"], "seeded_from": "acme/widgets@v1",
    }), encoding="utf-8")
    (cdir / "expected_findings.json").write_text(json.dumps(_E), encoding="utf-8")


def test_load_suite_provenance(tmp_path):
    _mock_case(tmp_path / "c1", "c1")
    case = load_suite(tmp_path)[0]
    assert case.corpus_id == "demo-corpus"
    assert case.cve_ids == ["CVE-2024-0001"] and case.seeded_from == "acme/widgets@v1"


def test_run_suite_parallel_cases(env, tmp_path):
    # a 2-case suite the mock scores; parallel_cases must score both, order-preserved, with provenance
    _mock_case(tmp_path / "c1", "c1")
    _mock_case(tmp_path / "c2", "c2")
    cfg = env().config
    report = run_suite(cfg, tmp_path, parallel_cases=2)
    assert report["totals"]["cases"] == 2 and report["totals"]["f1"] == 1.0
    assert [c["name"] for c in report["cases"]] == ["c1", "c2"]          # order preserved
    assert report["cases"][0]["provenance"]["corpus_id"] == "demo-corpus"
    assert report["cases"][0]["provenance"]["cve_ids"] == ["CVE-2024-0001"]


def test_case_brief_optional_for_local_review(tmp_path):
    # a case with no brief => local/general-audit mode (brief is None, repo-only)
    fx = Path(__file__).resolve().parent / "fixtures"
    cdir = tmp_path / "local"; cdir.mkdir()
    (cdir / "case.json").write_text(json.dumps({
        "name": "local", "repo": str(fx / "repo"), "scenario": "happy",
        "expected": "expected_findings.json"}), encoding="utf-8")
    (cdir / "expected_findings.json").write_text(json.dumps(_E), encoding="utf-8")
    case = load_suite(tmp_path)[0]
    assert case.brief is None


def test_run_suite_with_fixes(env):
    cfg = env().config
    report = run_suite(cfg, SUITE, fixes=True)
    assert report["patch_quality"]["patched"] == 3
    assert report["patch_quality"]["verified_rate"] == 1.0


def test_ab_compare_mock(env):
    cfg = env().config
    rep = ab_compare(cfg, SUITE, audit_model_b="claude-opus-4-8")
    # deterministic mock -> identical A and B -> zero delta, but both fully scored
    assert rep["delta_b_minus_a"] == {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    assert rep["a"]["totals"]["f1"] == 1.0 and rep["b"]["totals"]["f1"] == 1.0
