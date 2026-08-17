"""Phase 7 — benchmark scoring + harness tests (zero tokens on the mock runner)."""

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from argo.benchmark import (_aggregate_cross_backend, _cheap_tier, ab_compare, compare_backends,
                            load_suite, run_suite, score_run)

SUITE = Path(__file__).resolve().parent.parent / "benchmarks"
CORPORA = SUITE / "corpora"

needs_git = pytest.mark.skipif(not shutil.which("git"), reason="needs git")

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


def _chmod_writable(root: Path) -> None:
    for p in root.rglob("*"):
        try:
            p.chmod(stat.S_IWRITE | stat.S_IREAD)
        except OSError:
            pass


def test_default_suite_stays_offline():
    """The default `benchmarks/` suite must contain only the offline mock case — real (URL) corpora
    live under `benchmarks/corpora/` so `argo bench --runner mock` never hits the network."""
    names = {c.name for c in load_suite(SUITE)}
    assert names == {"acme-widgets"}


def test_corpora_case_carries_commit_and_labels():
    case = next(c for c in load_suite(CORPORA) if c.name == "gguf-tools-oob")
    assert case.repo == "https://github.com/antirez/gguf-tools"
    assert case.commit == "fdfafbed766d"          # pinned to the vulnerable revision, not HEAD
    assert case.archetype == "cli_desktop"
    assert len(case.expected) >= 5 and all("cwe" in e and "file" in e for e in case.expected)


@needs_git
def test_acquire_repo_pins_commit(tmp_path):
    """`acquire_repo(commit=...)` on a local git repo checks the copy out at that revision, not
    HEAD — the mechanism that makes URL-based CVE corpora reproducible."""
    from argo.stages.ingest import acquire_repo

    src = tmp_path / "src"
    src.mkdir()

    def git(*a):
        subprocess.run(["git", "-C", str(src), *a], check=True, capture_output=True, text=True)

    subprocess.run(["git", "init", "--quiet", str(src)], check=True, capture_output=True, text=True)
    git("config", "user.email", "t@t"); git("config", "user.name", "t")
    (src / "f.txt").write_text("v1\n", encoding="utf-8")
    git("add", "."); git("commit", "--quiet", "-m", "c1")
    sha1 = subprocess.run(["git", "-C", str(src), "rev-parse", "HEAD"],
                          check=True, capture_output=True, text=True).stdout.strip()
    (src / "f.txt").write_text("v2\n", encoding="utf-8")
    git("add", "."); git("commit", "--quiet", "-m", "c2")

    dest = tmp_path / "dest"
    try:
        acquire_repo(str(src), dest, is_url=False, commit=sha1)
        assert (dest / "f.txt").read_text(encoding="utf-8") == "v1\n"   # pinned, not HEAD's "v2"
        # no commit => plain copy at HEAD (unchanged default behaviour)
        dest2 = tmp_path / "dest2"
        acquire_repo(str(src), dest2, is_url=False)
        assert (dest2 / "f.txt").read_text(encoding="utf-8") == "v2\n"
    finally:
        _chmod_writable(dest); _chmod_writable(tmp_path / "dest2")


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


def test_run_suite_re_audit(env, monkeypatch):
    import argo.fixes as fixes_mod
    monkeypatch.setattr(fixes_mod, "_reaudit_patched", lambda ctx, ws, f: {
        "re_audit": {"ran": True, "confirmed_fixed": True, "still_present": False, "findings": 0}})
    cfg = env().config
    report = run_suite(cfg, SUITE, fixes=True, re_audit=True)
    pq = report["patch_quality"]
    assert pq["re_audit_ran"] == 3 and pq["re_audit_confirmed"] == 3
    assert pq["re_audit_confirmed_rate"] == 1.0


def test_ab_compare_mock(env):
    cfg = env().config
    rep = ab_compare(cfg, SUITE, audit_model_b="claude-opus-4-8")
    # deterministic mock -> identical A and B -> zero delta, but both fully scored
    assert rep["delta_b_minus_a"] == {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    assert rep["a"]["totals"]["f1"] == 1.0 and rep["b"]["totals"]["f1"] == 1.0


# ------------------------------------------------------------------- cross-backend (compare_backends)
def test_cheap_tier_sets_codex_model():
    """for_smoke()'s own model-selection logic never touches codex_model (Codex has no per-stage
    tiering to prime) -- _cheap_tier fixes that gap explicitly, or a 'cheap' Codex run would
    silently use whatever ~/.codex/config.toml happens to default to."""
    from argo.config import CODEX_CHEAP, PipelineConfig
    cfg = _cheap_tier(PipelineConfig(runner="codex"))
    assert cfg.codex_model == CODEX_CHEAP


def test_cheap_tier_does_not_import_for_smoke_caps():
    """_cheap_tier borrows ONLY for_smoke()'s model selection, not its budget/max_focuses/timeout
    caps -- a real benchmark run must not artificially starve audit fan-out."""
    from argo.config import PipelineConfig
    base = PipelineConfig(runner="headless", budget_usd=50.0, max_focuses=None)
    cfg = _cheap_tier(base)
    assert cfg.budget_usd == 50.0 and cfg.max_focuses is None


def test_compare_backends_derives_from_base_config_not_a_fresh_one(env):
    """Regression for a bug caught in plan review: an early draft built a fresh PipelineConfig(
    runner=b) per backend, silently dropping budget_usd/credentials the caller configured.
    compare_backends must derive from base_config via with_overrides, exactly like ab_compare
    already does."""
    cfg = env().config
    cfg = cfg.with_overrides(budget_usd=17.5)
    compare_backends(cfg, SUITE, backends=["mock"], tier="cheap")
    # if budget_usd/runs_dir had been dropped (a fresh PipelineConfig() defaults runs_dir to
    # "runs"), the report would land somewhere other than THIS caller-configured runs_dir --
    # proving the derived config carried base_config's settings through rather than defaulting.
    assert (Path(cfg.runs_dir) / "benchmark_crossbackend_report.json").exists()


def test_compare_backends_shape_single_mock_backend(env):
    cfg = env().config
    report = compare_backends(cfg, SUITE, backends=["mock"], tier="cheap")
    assert set(report["backends"].keys()) == {"mock"}
    assert set(report["totals_by_backend"].keys()) == {"mock"}
    tb = report["totals_by_backend"]["mock"]
    assert tb["f1"] == 1.0
    assert tb["cost_usd_total"] == 0.0
    assert "mean_latency_ms" in tb
    assert report["tier"] == "cheap"
    assert (Path(cfg.runs_dir) / "benchmark_crossbackend_report.json").exists()


def test_compare_backends_invalid_tier_raises(env):
    cfg = env().config
    with pytest.raises(ValueError):
        compare_backends(cfg, SUITE, backends=["mock"], tier="bogus")


def test_aggregate_cross_backend_is_genuinely_n_way():
    """Backend-agnostic test of the rollup logic itself, from three HAND-BUILT run_suite-shaped
    dicts -- no real pipeline runs needed (three real 'mock' backends would collide on the same
    dict key, see the plan's own note on why backends=['mock','mock','mock'] doesn't work as a
    shape test). Exercises the actual N-way shape ab_compare's 2-way delta can't express."""
    def _fake(p, r, f, cost, lat):
        return {"totals": {"precision": p, "recall": r, "f1": f, "cost_usd_total": cost,
                           "latency_ms_mean_per_call": lat}}
    reports = {
        "headless": _fake(0.9, 0.8, 0.847, 1.20, 500.0),
        "codex": _fake(0.7, 0.6, 0.646, 0.05, 200.0),
        "gemini": _fake(0.8, 0.75, 0.774, 0.30, 350.0),
    }
    out = _aggregate_cross_backend(reports, suite="demo", tier="top")
    assert set(out["backends"].keys()) == {"headless", "codex", "gemini"}
    assert set(out["totals_by_backend"].keys()) == {"headless", "codex", "gemini"}
    assert out["totals_by_backend"]["codex"]["cost_usd_total"] == 0.05
    assert out["totals_by_backend"]["gemini"]["mean_latency_ms"] == 350.0
    assert out["suite"] == "demo" and out["tier"] == "top"
    assert "generated_at" in out
