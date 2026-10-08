"""F3 composition is deterministic, exact-context-only, and never alters findings."""

from __future__ import annotations

import json

from argo.orchestrator import pipeline_stages, run_pipeline
from argo.stages import compose, report

from conftest import BRIEF, REPO


_CONTEXT = {
    "principal": "authenticated member",
    "tenant_scope": "same tenant",
    "deployment_scope": "default server deployment",
    "configuration_scope": "default configuration",
}


def _finding(identifier: str, *, capability: str, precondition: str = "", context=None):
    return {
        "id": identifier,
        "title": f"Finding {identifier}",
        "severity": "High",
        "confidence": "High",
        "cwe": "CWE-862",
        "affected": [f"src/{identifier}.py:1"],
        "vulnerable_flow": "request -> handler -> sink",
        "why_vulnerable": "The required authorization boundary is absent.",
        "exploit_scenario": "An authenticated member invokes the endpoint.",
        "impact": f"Impact from {identifier}.",
        "recommended_fix": "Enforce the authorization boundary.",
        "attacker_start": "authenticated member with access to the public API",
        "attack_context": context if context is not None else _CONTEXT,
        "preconditions": [precondition] if precondition else [],
        "capabilities_gained": [capability],
        "validation": {
            "verdict": "confirmed",
            "validated_confidence": "High",
            "validated_severity": "High",
            "surviving_data_flow": "public request -> missing check -> response",
        },
    }


def _write(ctx, findings):
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    ctx.scope_path.write_text(json.dumps({
        "program_name": "acme", "platform": "test", "target_type": "source_only",
        "in_scope": [{"asset": "repo", "type": "source_repo"}], "out_of_scope": [],
        "prohibited_techniques": ["no DoS"],
    }), encoding="utf-8")
    ctx.validated_findings_path.write_text(json.dumps({"findings": findings, "dropped": []}),
                                           encoding="utf-8")


def test_exact_context_capability_binding_emits_review_path_and_report_section(env):
    ctx = env(attack_path_enabled=True)
    _write(ctx, [
        _finding("F1", capability="invoke internal billing endpoint"),
        _finding("F2", capability="read invoices", precondition="invoke internal billing endpoint"),
    ])

    path = compose.run(ctx)
    composed = json.loads(path.read_text(encoding="utf-8"))

    assert composed["stats"] == {
        "eligible_findings": 2, "exact_capability_edges": 1, "paths_emitted": 1,
    }
    chain = composed["paths"][0]
    assert chain["finding_ids"] == ["F1", "F2"]
    assert chain["status"] == "supported"
    assert chain["edges"][0]["evidence_ids"]
    # Composition is a separate review artifact: it never changes an individual claim.
    findings = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))["findings"]
    assert all(f["claim_status"] == "active" for f in findings)
    assert all(f["proof_level"] == "source_supported" for f in findings)
    rendered = report.run(ctx).read_text(encoding="utf-8")
    assert "Evidence-gated attack paths (review required)" in rendered
    assert "`F1` → `F2`" in rendered


def test_mismatched_or_unknown_context_never_forms_an_edge(env):
    ctx = env(attack_path_enabled=True)
    different = {**_CONTEXT, "tenant_scope": "cross-tenant deployment"}
    _write(ctx, [
        _finding("F1", capability="invoke internal billing endpoint"),
        _finding("F2", capability="read invoices", precondition="invoke internal billing endpoint",
                 context=different),
        _finding("F3", capability="read invoices", precondition="invoke internal billing endpoint",
                 context={**_CONTEXT, "deployment_scope": "unknown"}),
    ])

    composed = json.loads(compose.run(ctx).read_text(encoding="utf-8"))

    assert composed["stats"]["eligible_findings"] == 2  # F3 fails closed before comparison.
    assert composed["stats"]["exact_capability_edges"] == 0
    assert composed["paths"] == []


def test_report_omits_stale_composition_artifact(env):
    ctx = env(attack_path_enabled=True)
    _write(ctx, [
        _finding("F1", capability="invoke internal billing endpoint"),
        _finding("F2", capability="read invoices", precondition="invoke internal billing endpoint"),
    ])
    compose.run(ctx)
    doc = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))
    doc["findings"][1]["preconditions"] = ["different prerequisite"]
    ctx.validated_findings_path.write_text(json.dumps(doc), encoding="utf-8")

    rendered = report.run(ctx).read_text(encoding="utf-8")

    assert "Evidence-gated attack paths (review required)" not in rendered


def test_pipeline_places_opt_in_composition_between_evidence_and_report(env):
    ctx = env(attack_path_enabled=True)
    assert pipeline_stages(ctx, research_enabled=False)[-3:] == ["evidence", "compose", "report"]


def test_opt_in_pipeline_tracks_an_empty_safe_composition_artifact(env):
    """Legacy/mock findings without explicit context must yield an empty artifact, not a guess."""
    ctx = env(attack_path_enabled=True)

    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)

    status = json.loads((ctx.run_dir / "status.json").read_text(encoding="utf-8"))
    assert [stage["name"] for stage in status["stages"]][-3:] == ["evidence", "compose", "report"]
    assert status["artifacts"]["attack_paths"] is True
    artifact = json.loads(ctx.attack_paths_path.read_text(encoding="utf-8"))
    assert artifact["paths"] == []
