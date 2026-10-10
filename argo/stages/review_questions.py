"""Deterministic, non-blocking architecture clarification queue (F5)."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..context import RunContext, atomic_write_json
from ..context_pack import (ContextClaim, ContextPack, assert_no_secrets, load_run as load_context_pack)
from ..target_memory import TargetMemoryStore, canonical_target


_CONTEXT = re.compile(
    r"(?i)\b(architecture|business|configuration|configured|deployment|deployed|gateway|proxy|"
    r"load balancer|middleware|role|permission|tenant|trust|boundary|intended|expected|policy|"
    r"operator|administrator|admin|internal|external|production|hosted|cloud|identity|iam)\b"
)
_AUTO_PREFIX = "argo:"


class ReviewQuestion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^rq:[0-9a-f]{16}$")
    question: str = Field(min_length=1, max_length=600)
    subject: str = Field(min_length=1, max_length=1200)
    affected_finding_ids: list[str] = Field(default_factory=list)
    affected_fact_ids: list[str] = Field(default_factory=list)
    why_source_cannot_settle: str = Field(min_length=1, max_length=600)
    status: Literal["needs_context", "answered_pending_revalidation", "resolved"] = "needs_context"
    answer: str | None = Field(default=None, max_length=2000)
    answer_provenance: str | None = Field(default=None, max_length=500)

    @field_validator("affected_finding_ids", "affected_fact_ids")
    @classmethod
    def _unique(cls, value: list[str]) -> list[str]:
        return sorted(set(value))


def _clean(value: str) -> str:
    value = value.removeprefix(_AUTO_PREFIX).strip().strip("- ")
    return " ".join(value.split()).rstrip(".?!:; ")[:1200]


def _key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


def _question(subject: str) -> str:
    return f'What is the intended deployment or trust-boundary behavior for: "{subject}"?'


def input_fingerprint(findings: list[dict], residual_unknowns: list[str]) -> str:
    relevant = [{
        "id": f.get("id"),
        "preconditions": f.get("preconditions") or [],
        "proof_obligations": f.get("proof_obligations") or [],
        "remaining_uncertainty": f.get("remaining_uncertainty") or [],
    } for f in findings]
    payload = {"findings": relevant, "residual_unknowns": residual_unknowns}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _residual_unknowns(ctx: RunContext) -> list[str]:
    try:
        raw = json.loads(ctx.repo_profile_path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return []
    values = raw.get("residual_unknowns") if isinstance(raw, dict) else None
    return [str(item) for item in values or [] if isinstance(item, str)]


def _candidate_rows(findings: list[dict], residual: list[str]) -> list[tuple[str, str, str]]:
    """Return (subject, finding id, fact id); one of the ids may be empty."""
    rows: list[tuple[str, str, str]] = []
    for finding in findings:
        fid = str(finding.get("id") or "")
        for item in finding.get("remaining_uncertainty") or []:
            if isinstance(item, str) and not item.startswith(_AUTO_PREFIX):
                rows.append((item, fid, ""))
        for obligation in finding.get("proof_obligations") or []:
            if not isinstance(obligation, dict) or obligation.get("status") == "satisfied":
                continue
            oid = str(obligation.get("id") or "")
            desc = obligation.get("description")
            if isinstance(desc, str) and not oid.startswith(_AUTO_PREFIX):
                rows.append((desc, fid, oid))
        for item in finding.get("preconditions") or []:
            if isinstance(item, str):
                rows.append((item, fid, ""))
    for idx, item in enumerate(residual, 1):
        rows.append((item, "", f"repo_profile:residual_unknown:{idx}"))
    return rows


def run(ctx: RunContext) -> Path:
    doc = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8-sig"))
    findings = [f for f in doc.get("findings") or [] if isinstance(f, dict)]
    residual = _residual_unknowns(ctx)
    prior: dict[str, dict] = {}
    try:
        old = json.loads(ctx.review_questions_path.read_text(encoding="utf-8-sig"))
        prior = {q["id"]: q for q in old.get("questions") or []
                 if isinstance(q, dict) and isinstance(q.get("id"), str)}
    except (OSError, ValueError):
        pass

    grouped: dict[str, dict] = {}
    for raw, fid, fact_id in _candidate_rows(findings, residual):
        subject = _clean(raw)
        if not subject or not _CONTEXT.search(subject):
            continue
        key = _key(subject)
        row = grouped.setdefault(key, {"subject": subject, "findings": set(), "facts": set()})
        if fid:
            row["findings"].add(fid)
        if fact_id:
            row["facts"].add(fact_id)

    questions: list[ReviewQuestion] = []
    for key, row in sorted(grouped.items()):
        qid = "rq:" + hashlib.sha256(key.encode()).hexdigest()[:16]
        current = ReviewQuestion(
            id=qid,
            question=_question(row["subject"]),
            subject=row["subject"],
            affected_finding_ids=sorted(row["findings"]),
            affected_fact_ids=sorted(row["facts"]),
            why_source_cannot_settle=(
                "The audit artifacts identify this as deployment, policy, or intended-behavior "
                "context that the repository alone does not establish."
            ),
        )
        old = prior.get(qid)
        if old and old.get("status") in {"answered_pending_revalidation", "resolved"}:
            current.answer = old.get("answer")
            current.answer_provenance = old.get("answer_provenance")
            pending = any(
                qid in ((f.get("validation") or {}).get("context_question_ids") or [])
                and (f.get("validation") or {}).get("context_revalidation_required") is True
                for f in findings
            )
            current.status = "answered_pending_revalidation" if pending else "resolved"
        questions.append(current)
        if len(questions) >= ctx.config.review_questions_max:
            break

    payload = {
        "schema_version": 1,
        "run_id": ctx.run_id,
        "generated_at": ctx.timestamp(),
        "input_fingerprint": input_fingerprint(findings, residual),
        "questions": [q.model_dump(mode="json", exclude_none=True) for q in questions],
        "note": ("This is a non-blocking private review queue. An answer is contextual input, not "
                 "technical proof; affected verdicts require re-validation."),
    }
    atomic_write_json(ctx.review_questions_path, payload)
    return ctx.review_questions_path


def _meta(ctx: RunContext) -> dict:
    try:
        raw = json.loads(ctx.meta_path.read_text(encoding="utf-8-sig"))
        return raw if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        return {}


def answer(ctx: RunContext, question_id: str, answer_text: str, provenance: str) -> Path:
    answer_text = " ".join(answer_text.split())
    provenance = " ".join(provenance.split())
    if not answer_text or len(answer_text) > 2000:
        raise ValueError("answer must be 1-2000 characters")
    if not provenance or len(provenance) > 500:
        raise ValueError("provenance must be 1-500 characters")
    assert_no_secrets(answer_text + "\n" + provenance)

    raw = json.loads(ctx.review_questions_path.read_text(encoding="utf-8-sig"))
    questions = [ReviewQuestion.model_validate(q) for q in raw.get("questions") or []]
    selected = next((q for q in questions if q.id == question_id), None)
    if selected is None:
        raise ValueError(f"unknown review question {question_id!r}")
    selected.status = "answered_pending_revalidation"
    selected.answer = answer_text
    selected.answer_provenance = provenance
    raw["questions"] = [q.model_dump(mode="json", exclude_none=True) for q in questions]
    atomic_write_json(ctx.review_questions_path, raw)

    # Make the answer available to validation in this run and future same-revision runs. It remains
    # explicitly provenance-bearing user context, never source evidence.
    pack = load_context_pack(ctx.context_pack_path) or ContextPack()
    claim_id = "answer-" + question_id.removeprefix("rq:")
    claim = ContextClaim(id=claim_id, statement=answer_text, provenance=provenance,
                         confidence="claimed")
    pack_data = pack.model_dump(mode="json")
    pack_data["architecture_notes"] = [
        c.model_dump(mode="json") for c in pack.architecture_notes if c.id != claim_id
    ] + [claim.model_dump(mode="json")]
    pack = ContextPack.model_validate(pack_data)  # re-enforce section caps after insertion
    atomic_write_json(ctx.context_pack_path, pack.model_dump(mode="json", exclude_none=True))

    meta = _meta(ctx)
    identity = canonical_target(str(meta.get("repo_source") or ""), bool(meta.get("repo_is_url")))
    TargetMemoryStore(ctx.target_memory_dir).upsert(identity, meta.get("repo_commit"), [
        ("design_decision", answer_text, f"review_answer:{question_id}:{provenance}",
         ["review_questions.json", "context_pack.json"]),
    ])
    from . import target_memory as target_memory_stage
    target_memory_stage.run(ctx)  # refresh the reviewable same-revision snapshot too

    # Do not silently leave an old submission draft looking current. Keep the verdict itself for
    # auditability, but mark it stale until validation is deliberately rerun with the new context.
    findings_doc = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8-sig"))
    affected = set(selected.affected_finding_ids)
    marked = 0
    for finding in findings_doc.get("findings") or []:
        if finding.get("id") not in affected:
            continue
        validation = finding.setdefault("validation", {})
        validation["context_revalidation_required"] = True
        ids = set(validation.get("context_question_ids") or [])
        ids.add(question_id)
        validation["context_question_ids"] = sorted(ids)
        marked += 1
    findings_doc.setdefault("stats", {})["context_revalidation_required"] = marked
    atomic_write_json(ctx.validated_findings_path, findings_doc)
    return ctx.review_questions_path
