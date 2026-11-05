"""Audit normalization: a schema-forbidden ``null`` must not discard an otherwise valid finding.

Regression source (local-model canaries, 2026-11-04/05): Qwen3-Coder-Next 80B emitted
``"validation": null`` and Qwen3.8 27B emitted ``"obligations_satisfied": null`` inside every
evidence record; each finding was dropped as unparseable / failed the whole focus."""

from types import SimpleNamespace

from argo.config import PipelineConfig
from argo.stages.audit import _normalize_findings_doc, _strip_schema_nulls


def _finding(**extra):
    base = {
        "id": "AUTHZ-001", "title": "IDOR in get_order", "severity": "High",
        "confidence": "High", "cwe": "CWE-639", "affected": ["src/api/orders.py:3-5"],
        "vulnerable_flow": "request -> get_order -> repo.find(order_id)",
        "why_vulnerable": "no ownership check", "exploit_scenario": "change the id",
        "impact": "read any order", "recommended_fix": "check ownership",
    }
    base.update(extra)
    return base


def _normalize(finding):
    ctx = SimpleNamespace(assets_dir=PipelineConfig().prompts_dir, timestamp=lambda: "t")
    doc = {"program_name": "Acme", "audit_focus": "x", "generated_at": "t", "findings": [finding]}
    return _normalize_findings_doc(doc, ctx, SimpleNamespace(program_name="Acme"), "audit_x")


def test_optional_null_object_is_dropped_not_the_finding():
    doc, repaired, unrecoverable, _ = _normalize(_finding(owasp=None))
    assert [f["id"] for f in doc["findings"]] == ["AUTHZ-001"]
    assert repaired == [] and unrecoverable == []
    assert "owasp" not in doc["findings"][0]


def test_nested_null_array_in_evidence_is_dropped():
    ev = {"id": "E1", "source": "audit", "kind": "source", "polarity": "supports",
          "summary": "s", "artifact": None, "obligations_satisfied": None}
    doc, repaired, unrecoverable, _ = _normalize(_finding(evidence=[ev]))
    assert unrecoverable == [] and repaired == []
    out = doc["findings"][0]["evidence"][0]
    assert "obligations_satisfied" not in out
    assert out["artifact"] is None          # null is ALLOWED here -> untouched


def test_required_null_text_still_goes_through_flagged_repair():
    doc, repaired, unrecoverable, _ = _normalize(_finding(impact=None))
    assert unrecoverable == [] and repaired == ["AUTHZ-001"]
    assert doc["findings"][0].get("schema_repair_failed") is True


def test_required_null_array_becomes_empty():
    schema = {"type": "object", "required": ["xs"], "properties": {"xs": {"type": "array"}}}
    assert _strip_schema_nulls({"xs": None}, schema) == ({"xs": []}, True)


def test_unknown_keys_and_valid_values_untouched():
    schema = {"type": "object", "properties": {"a": {"type": "string"}}}
    assert _strip_schema_nulls({"a": "x", "zzz": None}, schema) == ({"a": "x", "zzz": None}, False)


def test_audit_drops_stage_owned_verdicts():
    doc, _, unrecoverable, _ = _normalize(_finding(validation={"verdict": "confirmed"},
                                                   corroboration={}))
    f = doc["findings"][0]
    assert unrecoverable == [] and "validation" not in f and "corroboration" not in f


def test_model_treats_empty_stage_object_as_absent():
    from argo.models import Finding
    f = Finding.model_validate(_finding(validation={}, verification={}))
    assert f.validation is None and f.verification is None
