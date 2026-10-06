"""F5 private context import and non-blocking architecture clarification queue."""

from __future__ import annotations

import json

import pytest

from argo.context import atomic_write_json
from argo.context_pack import load
from argo.orchestrator import do_report, do_review_questions, run_pipeline
from argo.rendering import ensure_context_pack_present
from argo.stages.review_questions import answer

from conftest import BRIEF, REPO


def _pack(path):
    atomic_write_json(path, {
        "schema_version": 1,
        "target": "fixture service",
        "architecture_notes": [{
            "id": "edge-auth",
            "statement": "The production gateway authenticates /api routes.",
            "provenance": "architecture review AR-17",
            "confidence": "claimed",
        }],
        "roles": [{
            "name": "workspace owner",
            "trust": "May administer only its own tenant.",
            "provenance": "role catalogue v2",
        }],
        "services": [],
        "business_invariants": [],
        "iam_facts": [],
        "artifacts": [],
    })
    return path


def test_context_pack_rejects_credentials(tmp_path):
    path = tmp_path / "bad.json"
    atomic_write_json(path, {
        "schema_version": 1,
        "architecture_notes": [{
            "id": "bad",
            "statement": "api_key=super-secret-value",
            "provenance": "operator",
        }],
    })

    with pytest.raises(ValueError, match="credential"):
        load(path)


def test_pipeline_keeps_context_private_and_emits_non_blocking_questions(env, tmp_path):
    ctx = env(review_questions_enabled=True, target_memory_dir=tmp_path / "memory")
    pack = _pack(tmp_path / "context.json")

    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False, context_pack_path=pack)

    assert ctx.context_pack_path.is_file()
    assert not str(pack.resolve()) in ctx.context_pack_path.read_text(encoding="utf-8")
    audit_prompts = "\n".join(p.read_text(encoding="utf-8")
                               for p in ctx.prompts_out_dir.glob("audit_*.md"))
    assert "PRIVATE OPERATOR-PROVIDED CONTEXT PACK" not in audit_prompts
    assert "production gateway authenticates" not in audit_prompts
    runtime_prompt = ensure_context_pack_present("audit", ctx.context_pack_path)
    assert "PRIVATE OPERATOR-PROVIDED CONTEXT PACK" in runtime_prompt
    assert "production gateway authenticates" in runtime_prompt

    questions = json.loads(ctx.review_questions_path.read_text(encoding="utf-8"))["questions"]
    assert questions
    assert all(q["status"] == "needs_context" for q in questions)
    report = (ctx.run_dir / "REPORT.md").read_text(encoding="utf-8")
    # Private question/context prose is never copied into the shareable report.
    assert "production gateway authenticates" not in report
    assert "architecture review AR-17" not in report
    assert "Private context review" in report


def test_answer_requires_provenance_and_blocks_stale_draft(env, tmp_path):
    ctx = env(review_questions_enabled=True, target_memory_dir=tmp_path / "memory")
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    findings = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))
    confirmed = next(f for f in findings["findings"]
                     if (f.get("validation") or {}).get("verdict") == "confirmed")
    confirmed.setdefault("remaining_uncertainty", []).append(
        "Whether the production gateway enforces tenant isolation")
    atomic_write_json(ctx.validated_findings_path, findings)
    do_review_questions(ctx)
    queue = json.loads(ctx.review_questions_path.read_text(encoding="utf-8"))["questions"]
    question = next(q for q in queue if confirmed["id"] in q["affected_finding_ids"])

    with pytest.raises(ValueError, match="provenance"):
        answer(ctx, question["id"], "Yes, for every hosted deployment.", "")

    answer(ctx, question["id"], "Yes, for every hosted deployment.", "owner reply 2026-10-05")
    do_report(ctx)

    queue = json.loads(ctx.review_questions_path.read_text(encoding="utf-8"))["questions"]
    answered = next(q for q in queue if q["id"] == question["id"])
    assert answered["status"] == "answered_pending_revalidation"
    assert answered["answer_provenance"] == "owner reply 2026-10-05"
    updated = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))
    finding = next(f for f in updated["findings"] if f["id"] == confirmed["id"])
    assert finding["validation"]["context_revalidation_required"] is True
    assert not (ctx.drafts_dir / f"{confirmed['id']}.md").exists()
    memory = json.loads(next((tmp_path / "memory").glob("*.json")).read_text(encoding="utf-8"))
    assert any(f["provenance"].startswith(f"review_answer:{question['id']}")
               for f in memory["facts"])

    # A later validation rewrite clears the stale marker; rebuilding the queue then closes it.
    finding["validation"].pop("context_revalidation_required")
    finding["validation"].pop("context_question_ids")
    atomic_write_json(ctx.validated_findings_path, updated)
    do_review_questions(ctx)
    queue = json.loads(ctx.review_questions_path.read_text(encoding="utf-8"))["questions"]
    assert next(q for q in queue if q["id"] == question["id"])["status"] == "resolved"
