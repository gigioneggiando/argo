"""CI integration: SARIF export + severity gate over a finished run (no model calls)."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from argo.ci import gate, normalize_threshold, reportable, to_sarif
from argo.cli import app
from argo.orchestrator import run_pipeline

from conftest import BRIEF, REPO


def _f(fid, sev="High", verdict="confirmed", **over):
    base = {"id": fid, "title": f"{fid} title", "severity": sev, "confidence": "High",
            "cwe": "CWE-89", "affected": ["src/api/orders.py:12"], "dedup_key": f"k-{fid}",
            "why_vulnerable": "user input reaches SQL", "recommended_fix": "parameterize",
            "validation": {"verdict": verdict}}
    base.update(over)
    return base


def test_reportable_matches_the_report_rules():
    assert reportable(_f("A"))
    assert not reportable(_f("B", verdict="needs_runtime_verification"))
    assert reportable(_f("B", verdict="needs_runtime_verification"), include_unverified=True)
    assert not reportable(_f("C", verdict="refuted"))
    assert not reportable(_f("D", corroboration={"verdict": "design_accepted"}))
    assert not reportable(_f("E", corroboration={"verdict": "fixed_upstream"}))
    assert not reportable(_f("F", claim_status="conflicted"))
    assert not reportable(_f("G", validation={"verdict": "confirmed",
                                               "context_revalidation_required": True}))


def test_gate_uses_effective_severity_and_threshold():
    findings = [_f("A", "Medium"), _f("B", "High", validation={"verdict": "confirmed",
                                                               "validated_severity": "Low"}),
                _f("C", "Critical", verdict="needs_runtime_verification")]
    assert [f["id"] for f in gate(findings, "High")] == []          # B downgraded, C unverified
    assert [f["id"] for f in gate(findings, "High", include_unverified=True)] == ["C"]
    assert [f["id"] for f in gate(findings, "medium")] == ["A"]
    assert normalize_threshold("crit") == "Critical"
    with pytest.raises(ValueError):
        normalize_threshold("severe")


def test_sarif_structure_levels_rules_and_locations():
    findings = [
        _f("A", "Critical"),
        _f("B", "Medium", cwe="CWE-79", affected=["web/view.ts:40-48 (render)", "io.x.Foo.bar()"]),
        _f("C", "Low", cwe="", affected=["auth.Session.Check()"]),
        _f("D", "High", verdict="refuted"),
    ]
    doc = to_sarif(findings, run_id="R1")
    assert doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Argo" and run["automationDetails"]["id"] == "argo/R1"
    res = {r["properties"]["argoId"]: r for r in run["results"]}
    assert set(res) == {"A", "B", "C"}                                # refuted D excluded
    assert [r["properties"]["argoId"] for r in run["results"]] == ["A", "B", "C"]   # by severity
    assert (res["A"]["level"], res["B"]["level"], res["C"]["level"]) == ("error", "warning", "note")
    assert res["A"]["locations"][0]["physicalLocation"] == {
        "artifactLocation": {"uri": "src/api/orders.py", "uriBaseId": "%SRCROOT%"},
        "region": {"startLine": 12}}
    # Symbol-style citations never become file URIs.
    assert [l["physicalLocation"]["artifactLocation"]["uri"] for l in res["B"]["locations"]] \
        == ["web/view.ts"]
    assert res["C"]["locations"] == [] and res["C"]["ruleId"] == "argo-finding"
    assert res["A"]["partialFingerprints"] == {"argoDedupKey/v1": "k-A"}
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert rules["CWE-89"]["properties"]["security-severity"] == "9.5"
    assert rules["CWE-79"]["helpUri"].endswith("/79.html")
    assert "parameterize" in res["A"]["message"]["text"]


def test_cli_sarif_and_gate_on_a_mock_run(env, tmp_path):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    runs = str(tmp_path / "runs")
    doc = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))
    expected = [f["id"] for f in doc["findings"] if reportable(f)]
    assert expected, "the happy fixture must have confirmed findings"

    r = CliRunner().invoke(app, ["sarif", "--run", ctx.run_id, "--runs-dir", runs])
    assert r.exit_code == 0, r.output
    sarif = json.loads((ctx.run_dir / "argo.sarif").read_text(encoding="utf-8"))
    assert sorted(x["properties"]["argoId"] for x in sarif["runs"][0]["results"]) == sorted(expected)

    r = CliRunner().invoke(app, ["gate", "--run", ctx.run_id, "--runs-dir", runs, "--fail-on", "Low"])
    assert r.exit_code == 1 and '"passed": false' in r.output
    r = CliRunner().invoke(app, ["gate", "--run", ctx.run_id, "--runs-dir", runs,
                                 "--fail-on", "nope"])
    assert r.exit_code == 2
    r = CliRunner().invoke(app, ["gate", "--run", "missing-run", "--runs-dir", runs])
    assert r.exit_code == 2
