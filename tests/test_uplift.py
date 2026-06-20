"""Precision/depth uplift (ground-truth recon, SCA, completeness-critic, drift-repair, validate
downgrade-don't-delete). Drives the mock runner end-to-end + unit-tests the new helpers."""

import json
from types import SimpleNamespace

from conftest import BRIEF, REPO

from argo.orchestrator import run_pipeline
from argo.stages import sca
from argo.stages.audit import _normalize_findings_doc, _repair_finding
from argo.stages.validate import _format_ground_truth


# --------------------------------------------------------------------- recon ground truth
def test_recon_captures_ground_truth(env):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO), dry_run=True, research_enabled=False)
    assert ctx.ground_truth_path.exists()
    gt = json.loads(ctx.ground_truth_path.read_text(encoding="utf-8"))
    assert "global" in gt and "focuses" in gt
    assert gt["global"]["fp_carveouts"]          # the fixture carve-out survived capture


# ------------------------------------------------------------------------------ SCA flow
def test_sca_findings_flow_into_validation(env):
    ctx = env(sca_enabled=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    doc = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))
    ids = {f["id"] for f in doc["findings"]}
    assert "DEP-001" in ids                       # SCA dep finding reached the validated set
    dep = next(f for f in doc["findings"] if f["id"] == "DEP-001")
    # Confirmed-confidence SCA finding is kept as 'confirmed' without an adversarial session.
    assert dep["validation"]["verdict"] == "confirmed"


def test_sca_extracts_pins_with_file_line(tmp_path):
    (tmp_path / "Directory.Packages.props").write_text(
        '<Project>\n  <ItemGroup>\n'
        '    <PackageVersion Include="System.Net.Http" Version="4.3.4" />\n'
        '  </ItemGroup>\n</Project>\n', encoding="utf-8")
    (tmp_path / "package.json").write_text('{"dependencies": {"lodash": "4.17.20"}}', encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("flask==1.0.0\n# c\nrequests>=2.20.0\n", encoding="utf-8")
    pins = sca._extract_pins(tmp_path, sca._collect_manifests(tmp_path))
    by = {(p["name"], p["version"]) for p in pins}
    assert ("System.Net.Http", "4.3.4") in by
    assert ("lodash", "4.17.20") in by
    assert ("flask", "1.0.0") in by
    sysnet = next(p for p in pins if p["name"] == "System.Net.Http")
    assert "Directory.Packages.props:3" == sysnet["ref"]   # exact file:line


def test_sca_off_by_default_flag(env):
    ctx = env(sca_enabled=False)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    doc = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))
    assert "DEP-001" not in {f["id"] for f in doc["findings"]}


# ------------------------------------------------------------------- completeness critic
def test_critic_pass_adds_nothing_in_mock_and_does_not_duplicate(env):
    """With the mock critic returning an empty findings file, the loop-until-dry stops and no
    finding is duplicated — the dedup path holds."""
    base = env()
    run_pipeline(base, BRIEF, str(REPO), research_enabled=False)
    base_ids = sorted(f["id"] for f in
                      json.loads(base.validated_findings_path.read_text(encoding="utf-8"))["findings"])

    crit = env(audit_critic_passes=2, run_id="TEST-RUN-CRIT")
    run_pipeline(crit, BRIEF, str(REPO), research_enabled=False)
    crit_ids = sorted(f["id"] for f in
                      json.loads(crit.validated_findings_path.read_text(encoding="utf-8"))["findings"])
    assert crit_ids == base_ids                    # critic added nothing (mock) and duplicated nothing
    # The critic round did spend extra audit sessions (depth lever is wired in).
    assert crit.ledger.run_call_count("TEST-RUN-CRIT") > base.ledger.run_call_count(base.run_id)


# ---------------------------------------------------------------- drift-repair (Phase 6)
def test_drift_repair_keeps_finding_instead_of_dropping(env):
    ctx = env()
    scope = SimpleNamespace(program_name="Mock")
    raw_doc = {"findings": [{
        "title": "Drifted finding missing required fields",
        "severity": "moderate", "confidence": "high", "affected": ["a.py:1"],
    }]}
    doc, repaired, unrecoverable, _coerced = _normalize_findings_doc(raw_doc, ctx, scope, "myfocus")
    assert len(doc["findings"]) == 1               # kept, not dropped
    assert unrecoverable == []
    f = doc["findings"][0]
    assert f["schema_repair_failed"] is True
    assert f["severity"] == "Medium"               # 'moderate' coerced
    assert f["recommended_fix"]                     # backfilled (was missing)


def test_repair_finding_synthesizes_id_and_affected():
    rf = _repair_finding({"title": "x", "severity": "High", "confidence": "High"}, "focusx", 7)
    assert rf["id"].startswith("FOCUSX-REPAIR-")
    assert rf["affected"] and isinstance(rf["affected"], list)
    assert rf["schema_repair_failed"] is True


# ----------------------------------------------------------- validate ground-truth helper
def test_format_ground_truth_surfaces_carveouts_and_baseline():
    gt = {
        "global": {"fp_carveouts": ["global carve A"]},
        "focuses": {"F": {
            "fp_carveouts": ["focus carve B"],
            "baseline_correct": [{"pattern": "authz", "reference_impl": "MoveController",
                                  "why_correct": "two checks"}],
        }},
    }
    out = _format_ground_truth(gt, "F")
    assert "global carve A" in out and "focus carve B" in out
    assert "MoveController" in out and "CARVE-OUTS" in out


def test_format_ground_truth_empty_is_safe():
    assert "none" in _format_ground_truth({}, None).lower()
    assert "none" in _format_ground_truth(None, "F").lower()
