"""F5 over HTTP: list the private review questions, answer one with provenance (no model call),
then re-validate only the affected finding. Mock runner, zero tokens."""

from __future__ import annotations

import json

from argo.config import load_pipeline_config
from argo.context import atomic_write_json
from argo.orchestrator import build_context, do_review_questions

from test_api import _client, _start, _wait


def _run_with_question(client, tmp_path):
    """A finished mock run whose first confirmed finding carries one architecture question."""
    run_id = _start(client, config={"runner": "mock", "review_questions_enabled": True})
    assert _wait(client, run_id)["state"] == "completed"
    run_dir = tmp_path / "runs" / run_id
    ctx = build_context(load_pipeline_config(run_dir / "config.json"), run_id)
    try:
        doc = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))
        confirmed = next(f for f in doc["findings"]
                         if (f.get("validation") or {}).get("verdict") == "confirmed")
        confirmed.setdefault("remaining_uncertainty", []).append(
            "Whether the production gateway authenticates external callers")
        atomic_write_json(ctx.validated_findings_path, doc)
        do_review_questions(ctx)
    finally:
        ctx.ledger.close()
    queue = client.get(f"/runs/{run_id}/questions").json()["questions"]
    question = next(q for q in queue if confirmed["id"] in q["affected_finding_ids"])
    return run_id, confirmed["id"], question


def test_questions_answer_and_targeted_revalidation(tmp_path):
    _app, client = _client(tmp_path)
    run_id, finding_id, question = _run_with_question(client, tmp_path)
    assert question["status"] == "needs_context"

    # Provenance is mandatory and secrets are rejected; neither touches the queue.
    r = client.post(f"/runs/{run_id}/questions/{question['id']}/answer",
                    json={"answer": "Yes.", "provenance": ""})
    assert r.status_code == 422
    r = client.post(f"/runs/{run_id}/questions/{question['id']}/answer",
                    json={"answer": "api_key=super-secret-value", "provenance": "owner"})
    assert r.status_code == 400 and "credential" in r.json()["detail"]
    r = client.post(f"/runs/{run_id}/questions/rq:0000000000000000/answer",
                    json={"answer": "Yes.", "provenance": "owner"})
    assert r.status_code == 400

    r = client.post(f"/runs/{run_id}/questions/{question['id']}/answer",
                    json={"answer": "It authenticates all external callers.",
                          "provenance": "architecture owner"})
    assert r.status_code == 200, r.text
    answered = next(q for q in r.json()["questions"] if q["id"] == question["id"])
    assert answered["status"] == "answered_pending_revalidation"
    findings = client.get(f"/runs/{run_id}/artifacts/validated_findings").json()["findings"]
    stale = next(f for f in findings if f["id"] == finding_id)
    assert stale["validation"]["context_revalidation_required"] is True
    unrelated_before = {f["id"]: f for f in findings if f["id"] != finding_id}

    r = client.post(f"/runs/{run_id}/revalidate-context", json={"question": question["id"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["revalidated"] == 1 and body["still_pending"] == 0
    assert next(q for q in body["questions"]["questions"]
                if q["id"] == question["id"])["status"] == "resolved"
    findings = client.get(f"/runs/{run_id}/artifacts/validated_findings").json()["findings"]
    refreshed = next(f for f in findings if f["id"] == finding_id)
    assert "context_revalidation_required" not in refreshed["validation"]
    assert {f["id"]: f for f in findings if f["id"] != finding_id} == unrelated_before
    # The private answer never reaches the shareable report.
    assert "authenticates all external callers" not in client.get(f"/runs/{run_id}/report").text


def test_questions_absent_and_validation_errors(tmp_path):
    _app, client = _client(tmp_path)
    run_id = _start(client)                                   # questions not enabled
    assert _wait(client, run_id)["state"] == "completed"
    assert client.get(f"/runs/{run_id}/questions").json() is None
    r = client.post(f"/runs/{run_id}/questions/rq:0000000000000000/answer",
                    json={"answer": "Yes.", "provenance": "owner"})
    assert r.status_code == 404
    assert client.post(f"/runs/{run_id}/revalidate-context",
                       json={"question": "not-an-id"}).status_code == 422
    assert client.post(f"/runs/{run_id}/revalidate-context",
                       json={"budget_usd": 0}).status_code == 422
    assert client.get("/runs/nope/questions").status_code == 404

    # Building the queue later (like ``argo questions``) is deterministic and needs no model.
    r = client.post(f"/runs/{run_id}/questions")
    assert r.status_code == 200, r.text
    assert r.json()["schema_version"] == 1 and isinstance(r.json()["questions"], list)
    assert client.get(f"/runs/{run_id}/questions").json() == r.json()
