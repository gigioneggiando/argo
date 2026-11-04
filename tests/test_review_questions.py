"""F5 private context import and non-blocking architecture clarification queue."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from argo.cli import app
from argo.context import atomic_write_json
from argo.context_pack import load
from argo.models import Validation
from argo.orchestrator import do_report, do_review_questions, run_pipeline
from argo.rendering import ensure_context_pack_present
from argo.stages.review_questions import answer
from argo.stages.validate import revalidate_context

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
    assert str(pack.resolve()) not in ctx.context_pack_path.read_text(encoding="utf-8")
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
    confirmed["validation"]["runtime"] = {"verdict": "observed", "observation": "fixture"}
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

    unrelated_before = {
        f["id"]: f for f in updated["findings"] if f["id"] != confirmed["id"]
    }
    result = revalidate_context(ctx, question_id=question["id"])
    assert result["selected"] == 1
    assert result["revalidated"] == 1
    assert result["still_pending"] == 0
    refreshed = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))
    finding = next(f for f in refreshed["findings"] if f["id"] == confirmed["id"])
    assert "context_revalidation_required" not in finding["validation"]
    assert finding["validation"]["runtime"]["observation"] == "fixture"
    assert {f["id"]: f for f in refreshed["findings"] if f["id"] != confirmed["id"]} == unrelated_before
    do_review_questions(ctx)
    do_report(ctx)
    queue = json.loads(ctx.review_questions_path.read_text(encoding="utf-8"))["questions"]
    assert next(q for q in queue if q["id"] == question["id"])["status"] == "resolved"
    assert (ctx.drafts_dir / f"{confirmed['id']}.md").is_file()


def test_context_revalidation_failure_preserves_old_verdict_and_draft_block(
    env, tmp_path, monkeypatch,
):
    ctx = env(review_questions_enabled=True, target_memory_dir=tmp_path / "memory")
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    findings = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))
    confirmed = next(f for f in findings["findings"]
                     if (f.get("validation") or {}).get("verdict") == "confirmed")
    confirmed.setdefault("remaining_uncertainty", []).append(
        "Whether the hosted gateway enforces workspace permissions")
    atomic_write_json(ctx.validated_findings_path, findings)
    do_review_questions(ctx)
    question = next(q for q in json.loads(ctx.review_questions_path.read_text(encoding="utf-8"))["questions"]
                    if confirmed["id"] in q["affected_finding_ids"])
    answer(ctx, question["id"], "It does in the hosted service.", "owner reply")

    from argo.stages import validate as validate_stage

    def fail_batch(_ctx, _scope, _scope_text, batch, _ground_truth, **_kwargs):
        return {
            f.id: Validation(
                verdict="needs_runtime_verification",
                rationale="validation session failed; see the local LLM log for diagnostics",
            ) for f in batch
        }

    monkeypatch.setattr(validate_stage, "_validate_batch", fail_batch)
    result = revalidate_context(ctx, question_id=question["id"])
    assert result["revalidated"] == 0
    assert result["still_pending"] == 1
    updated = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))
    finding = next(f for f in updated["findings"] if f["id"] == confirmed["id"])
    assert finding["validation"]["verdict"] == "confirmed"
    assert finding["validation"]["context_revalidation_required"] is True


def test_context_revalidation_refute_drops_finding_but_keeps_resolved_question(
    env, tmp_path, monkeypatch,
):
    ctx = env(review_questions_enabled=True, target_memory_dir=tmp_path / "memory")
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    findings = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))
    confirmed = next(f for f in findings["findings"]
                     if (f.get("validation") or {}).get("verdict") == "confirmed")
    confirmed.setdefault("remaining_uncertainty", []).append(
        "Whether an upstream proxy authenticates every deployment")
    atomic_write_json(ctx.validated_findings_path, findings)
    do_review_questions(ctx)
    question = next(q for q in json.loads(ctx.review_questions_path.read_text(encoding="utf-8"))["questions"]
                    if confirmed["id"] in q["affected_finding_ids"])
    answer(ctx, question["id"], "Every deployment has that proxy.", "deployment owner")

    from argo.stages import validate as validate_stage
    monkeypatch.setattr(
        validate_stage, "_validate_batch",
        lambda _ctx, _scope, _scope_text, batch, _ground_truth, **_kwargs: {
            f.id: Validation(verdict="refuted", rationale="The supplied architecture closes it.")
            for f in batch
        },
    )
    result = revalidate_context(ctx, question_id=question["id"])
    assert result["dropped"] == 1
    assert result["still_pending"] == 0
    updated = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))
    assert confirmed["id"] not in {f["id"] for f in updated["findings"]}
    assert any(d["id"] == confirmed["id"] and d["verdict"] == "refuted"
               for d in updated["dropped"])
    do_review_questions(ctx)
    queue = json.loads(ctx.review_questions_path.read_text(encoding="utf-8"))["questions"]
    historical = next(q for q in queue if q["id"] == question["id"])
    assert historical["status"] == "resolved"
    assert historical["answer_provenance"] == "deployment owner"


def test_revalidate_context_cli_refreshes_pending_run(env, tmp_path):
    ctx = env(review_questions_enabled=True, target_memory_dir=tmp_path / "memory")
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    findings = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))
    confirmed = next(f for f in findings["findings"]
                     if (f.get("validation") or {}).get("verdict") == "confirmed")
    confirmed.setdefault("remaining_uncertainty", []).append(
        "Whether the production gateway authenticates external callers")
    atomic_write_json(ctx.validated_findings_path, findings)
    do_review_questions(ctx)
    question = next(q for q in json.loads(ctx.review_questions_path.read_text(encoding="utf-8"))["questions"]
                    if confirmed["id"] in q["affected_finding_ids"])
    answer(ctx, question["id"], "It authenticates all external callers.", "architecture owner")
    do_report(ctx)
    result = CliRunner().invoke(app, [
        "revalidate-context", "--run", ctx.run_id, "--question", question["id"],
        "--runs-dir", str(tmp_path / "runs"),
    ])
    assert result.exit_code == 0, result.output
    json_start = result.output.find("{\n")
    assert json_start >= 0, result.output
    emitted, _end = json.JSONDecoder().raw_decode(result.output[json_start:])
    assert emitted["revalidated"] == 1
    assert emitted["still_pending"] == 0
    assert emitted["report"].endswith("REPORT.md")
