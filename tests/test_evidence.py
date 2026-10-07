"""F1 unified claim/evidence contract and deterministic consistency gate."""

from __future__ import annotations

import json

import pytest

from argo.stages import evidence, report


def _base(**updates):
    finding = {
        "id": "F1",
        "title": "Missing authorization",
        "severity": "High",
        "confidence": "High",
        "cwe": "CWE-862",
        "affected": ["src/api/orders.py:1"],
        "vulnerable_flow": "request -> order lookup -> response",
        "why_vulnerable": "A caller can read another tenant's order.",
        "exploit_scenario": "A tenant supplies another tenant's id.",
        "impact": "Cross-tenant order disclosure.",
        "recommended_fix": "Enforce ownership.",
        "dedup_key": "same-finding",
        "validation": {
            "verdict": "confirmed",
            "validated_confidence": "High",
            "validated_severity": "High",
            "surviving_data_flow": "request -> lookup -> response",
            "rationale": "The ownership check is absent.",
        },
    }
    finding.update(updates)
    return finding


def _write(ctx, finding):
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    ctx.scope_path.write_text(
        json.dumps(
            {
                "program_name": "acme",
                "platform": "test",
                "target_type": "source_only",
                "in_scope": [{"asset": "repo", "type": "source_repo"}],
                "out_of_scope": [],
                "prohibited_techniques": ["no DoS"],
            }
        ),
        encoding="utf-8",
    )
    ctx.validated_findings_path.write_text(
        json.dumps({"findings": [finding], "dropped": []}), encoding="utf-8"
    )


def _normalized(ctx):
    evidence.run(ctx)
    return json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))[
        "findings"
    ][0]


def test_legacy_finding_is_upgraded_additively_and_idempotently(env):
    ctx = env()
    _write(ctx, _base())
    first = _normalized(ctx)
    first_bytes = ctx.validated_findings_path.read_bytes()
    second = _normalized(ctx)

    assert first["claim"].startswith("Missing authorization:")
    assert first["attacker_start"]
    assert first["capabilities_gained"] == ["Cross-tenant order disclosure."]
    assert first["proof_level"] == "source_supported"
    assert first["evidence"][0]["id"].startswith("argo:")
    assert second == first
    assert ctx.validated_findings_path.read_bytes() == first_bytes


@pytest.mark.parametrize(
    ("extra", "level", "source"),
    [
        ({}, "source_supported", "validation"),
        (
            {
                "verification": {
                    "verdict": "reconfirmed",
                    "rationale": "re-derived",
                    "independent_derivation": "src/api/orders.py:1",
                }
            },
            "independently_rederived",
            "deep_verify",
        ),
        (
            {
                "corroboration": {
                    "verdict": "corroborated",
                    "rationale": "Docs do not contradict it.",
                }
            },
            "source_supported",
            "corroboration",
        ),
        (
            {
                "validation": {
                    **_base()["validation"],
                    "asan_poc": {
                        "verdict": "confirmed",
                        "sanitizer_summary": "heap-buffer-overflow",
                        "crash_trace": "ERROR: AddressSanitizer",
                    },
                }
            },
            "runtime_observed",
            "asan",
        ),
        (
            {
                "validation": {
                    **_base()["validation"],
                    "runtime": {
                        "verdict": "runtime_confirmed",
                        "verdict_source": "model_interpretation",
                        "booted": True,
                        "evidence": "GET /orders/2 -> 200 with tenant B data",
                        "probes": [
                            {"method": "GET", "path": "/orders/2", "status": 200}
                        ],
                    },
                }
            },
            "runtime_observed",
            "runtime",
        ),
        (
            {
                "validation": {
                    **_base()["validation"],
                    "live": {
                        "verdict": "live_confirmed",
                        "evidence": "probe returned 200 while control returned 403",
                        "probes": [
                            {
                                "method": "GET",
                                "url": "https://acme.test/orders/2",
                                "status": 200,
                                "control": {
                                    "method": "GET",
                                    "url": "https://acme.test/denied",
                                    "status": 403,
                                },
                            }
                        ],
                    },
                }
            },
            "runtime_observed",
            "live",
        ),
    ],
)
def test_proof_level_derives_from_native_evidence_sources(env, extra, level, source):
    ctx = env()
    _write(ctx, _base(**extra))
    finding = _normalized(ctx)
    assert finding["proof_level"] == level
    assert any(e["source"] == source for e in finding["evidence"])


def test_audit_only_claim_remains_reportable_hypothesis(env):
    ctx = env()
    _write(ctx, _base(validation=None))
    finding = _normalized(ctx)
    assert finding["proof_level"] == "hypothesis"
    assert any(e["source"] == "audit" for e in finding["evidence"])
    assert any(
        o["id"] == "argo:source_path" and o["status"] == "open"
        for o in finding["proof_obligations"]
    )


def test_confirmed_hypothesis_stays_in_report_without_a_draft(env):
    ctx = env()
    ctx.config = ctx.config.with_overrides(runner="codex")
    validation = {**_base()["validation"], "surviving_data_flow": ""}
    _write(ctx, _base(validation=validation))
    finding = _normalized(ctx)
    assert finding["validation"]["verdict"] == "confirmed"
    assert finding["proof_level"] == "hypothesis"

    rendered = report.run(ctx).read_text(encoding="utf-8")
    assert "F1 - Missing authorization" in rendered
    assert not (ctx.drafts_dir / "F1.md").exists()
    with pytest.raises(ValueError, match="no source-supported proof"):
        report.render_pr_draft(ctx, "F1")


def test_maintainer_feedback_is_current_run_disposition_without_copying_private_comment(env):
    ctx = env()
    _write(ctx, _base())
    ctx.ledger.record_finding(
        program_name="acme",
        run_id=ctx.run_id,
        dedup_key="same-finding",
        title="same",
        verdict="confirmed",
        validated_severity="High",
    )
    ctx.ledger.record_triager_feedback(
        program_name="acme",
        dedup_key="same-finding",
        accepted=True,
        feedback="private GHSA correspondence",
    )
    finding = _normalized(ctx)
    assert finding["proof_level"] == "source_supported"
    assert finding["external_status"] == "accepted"
    serialized = json.dumps(finding)
    assert "private GHSA correspondence" not in serialized


def test_decisive_runtime_refutation_flags_but_does_not_delete(env):
    ctx = env()
    validation = {
        **_base()["validation"],
        "runtime": {
            "verdict": "runtime_refuted",
            "verdict_source": "model_interpretation",
            "booted": True,
            "evidence": "GET /orders/2 -> 403",
            "probes": [{"method": "GET", "path": "/orders/2", "status": 403}],
        },
    }
    _write(ctx, _base(validation=validation))
    ctx.ledger.record_finding(
        program_name="acme",
        run_id=ctx.run_id,
        dedup_key="same-finding",
        title="same",
        verdict="confirmed",
        validated_severity="High",
    )
    ctx.ledger.record_triager_feedback(
        program_name="acme",
        dedup_key="same-finding",
        accepted=True,
        feedback="accepted before the newer contradictory observation",
    )
    finding = _normalized(ctx)
    assert finding["id"] == "F1"
    assert finding["claim_status"] == "conflicted"
    assert any(
        i["code"] == "supporting_and_contradicting_evidence"
        for i in finding["consistency_issues"]
    )
    assert any(
        o["id"] == "argo:contradiction" and o["status"] == "contradicted"
        for o in finding["proof_obligations"]
    )
    rendered = report.run(ctx).read_text(encoding="utf-8")
    assert "Evidence consistency error" in rendered
    assert "F1 - Missing authorization" in rendered
    assert not (ctx.drafts_dir / "F1.md").exists()


def test_later_deep_support_does_not_overwrite_decisive_validation_refutation(env):
    ctx = env()
    verification = {
        "verdict": "reconfirmed",
        "rationale": "A later pass supported the mechanism.",
        "independent_derivation": "src/api/orders.py:1",
    }
    validation = {**_base()["validation"], "verdict": "refuted"}
    _write(ctx, _base(validation=validation, verification=verification))
    finding = _normalized(ctx)
    assert finding["claim_status"] == "conflicted"
    assert any(
        issue["code"] == "supporting_and_contradicting_evidence"
        for issue in finding["consistency_issues"]
    )


def test_runtime_confirmation_requires_a_captured_probe_observation(env):
    ctx = env()
    validation = {
        **_base()["validation"],
        "runtime": {
            "verdict": "runtime_confirmed",
            "evidence": "Model says the request succeeded, but no probe was captured.",
            "probes": [],
        },
    }
    _write(ctx, _base(validation=validation))
    finding = _normalized(ctx)
    assert finding["proof_level"] == "source_supported"
    assert any(
        issue["code"] == "runtime_confirmation_missing_observation"
        for issue in finding["consistency_issues"]
    )


def test_expectation_fallback_cannot_promote_runtime_or_copy_response_body(env):
    ctx = env()
    validation = {
        **_base()["validation"],
        "runtime": {
            "booted": True,
            "verdict": "runtime_confirmed",
            "verdict_source": "expectation_fallback",
            "evidence": "Authorization: Bearer eyJabcdefgh.abcdefgh.abcdefgh",
            "probes": [{"method": "GET", "path": "/orders/2", "status": 200,
                        "body_snippet": "secret-value"}],
        },
    }
    _write(ctx, _base(validation=validation))
    finding = _normalized(ctx)
    assert finding["proof_level"] == "source_supported"
    runtime = next(e for e in finding["evidence"] if e["source"] == "runtime")
    assert runtime["polarity"] == "inconclusive"
    assert "secret-value" not in json.dumps(runtime)
    assert "eyJabcdefgh" not in json.dumps(runtime)


def test_changed_claim_invalidates_unchanged_native_evidence(env):
    ctx = env()
    _write(ctx, _base())
    _normalized(ctx)
    doc = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))
    doc["findings"][0]["title"] = "Changed authorization claim"
    ctx.validated_findings_path.write_text(json.dumps(doc), encoding="utf-8")
    finding = _normalized(ctx)
    validation = next(e for e in finding["evidence"] if e["source"] == "validation")
    assert validation["polarity"] == "inconclusive"
    assert any(issue["code"] == "validation_stale" for issue in finding["consistency_issues"])


def test_old_run_feedback_does_not_apply_to_current_claim(env):
    ctx = env()
    _write(ctx, _base())
    ctx.ledger.record_finding(
        program_name="acme", run_id="OLD-RUN", dedup_key="same-finding", title="same",
        verdict="confirmed", validated_severity="High",
    )
    ctx.ledger.record_triager_feedback(
        program_name="acme", dedup_key="same-finding", accepted=True, run_id="OLD-RUN",
    )
    finding = _normalized(ctx)
    assert finding["external_status"] == "unknown"


def test_report_and_draft_render_proof_and_open_obligations(env):
    ctx = env()
    _write(
        ctx, _base(proof_obligations=["Confirm default deployment exposes the route."])
    )
    evidence.run(ctx)
    path = report.run(ctx)
    rendered = path.read_text(encoding="utf-8")
    draft = (ctx.drafts_dir / "F1.md").read_text(encoding="utf-8")
    assert "Proof level: **source_supported**" in rendered
    assert "Confirm default deployment exposes the route." in rendered
    assert "**Proof level:** source_supported" in draft
    assert "### Unresolved proof obligations" in draft


def test_pipeline_status_places_evidence_immediately_before_report(env):
    from argo.orchestrator import pipeline_stages

    ctx = env()
    stages = pipeline_stages(ctx, research_enabled=False)
    assert stages[-2:] == ["evidence", "report"]
