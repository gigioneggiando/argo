"""Deterministic summary of existing evidence, rebuilt before report generation.

Native stage records stay authoritative. This module runs no model, code or probes.
The baseline detects later changes; it cannot authenticate legacy artifact provenance.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from urllib.parse import urlsplit, urlunsplit

from ..context import RunContext, atomic_write_json
from ..models import ConsistencyIssue, EvidenceRecord, Finding, ProofObligation

_AUTO = "argo:"
_LEVELS = ("hypothesis", "source_supported", "independently_rederived",
           "runtime_observed", "end_to_end_proven")
_CLAIM_FIELDS = ("id", "title", "affected", "cwe", "vulnerable_flow", "why_vulnerable",
                 "exploit_scenario", "impact", "claim", "attacker_start", "preconditions",
                 "capabilities_gained")
_SECRET = re.compile(
    r'(?i)\b(authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\r\n]+'
    r'|\b(password|passwd|token|api[_-]?key|client[_-]?secret)\b["\s]*[:=]\s*'
    r'(?:"[^"]*"|\x27[^\x27]*\x27|[^\s,;]+)'
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_SANITIZER = re.compile(r"AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|runtime error:",
                        re.IGNORECASE)


def _text(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _location(value: str) -> str:
    try:
        parsed = urlsplit(value)
        if not parsed.netloc:
            return parsed.path[:300]
        host = parsed.hostname or "unknown"
        port = parsed.port
        if ":" in host:
            host = f"[{host}]"
        if port:
            host += f":{port}"
        return urlunsplit((parsed.scheme, host, parsed.path, "", ""))[:300]
    except ValueError:
        return "<invalid URL omitted>"


def redact_text(value: str, limit: int = 1000) -> str:
    """Best-effort scrubbing, not a promise that arbitrary prose contains no secrets."""
    text = re.sub(r"https?://[^\s<>\x22\x27]+",
                  lambda m: _location(m.group()), _text(value))
    text = _SECRET.sub("<redacted credential>", text)
    text = _JWT.sub("<redacted JWT>", text)
    return re.sub(r"\s+", " ", text)[:limit]


def _observation(native: dict, source: str) -> tuple[str | None, str | None]:
    if source == "runtime" and native.get("booted") is not True:
        return None, None
    for probe in native.get("probes") or []:
        if not isinstance(probe, dict) or any(probe.get(k) for k in
                ("skipped", "error", "redirect_out_of_scope")):
            continue
        status = probe.get("status")
        if type(status) is not int or not 200 <= status < 500:
            continue
        control = probe.get("control")
        control_note = None
        if isinstance(control, dict):
            cstatus = control.get("status")
            if (type(cstatus) is not int or not 200 <= cstatus < 500
                    or control.get("error") or control.get("skipped")):
                continue
            if all(probe.get(k) == control.get(k) for k in
                   ("status", "body_snippet", "response_headers")):
                continue
            control_note = f"Recorded control HTTP {cstatus}; equivalence needs human review."
        # Copy neither bodies nor arbitrary URL paths into the canonical ledger.
        return f"Captured HTTP {status}; response content remains in the native artifact.", control_note
    return None, None


def normalize_finding(ctx: RunContext, finding: Finding, *, commit: str | None = None) -> Finding:
    finding = finding.model_copy(deep=True)
    finding.claim = _text(finding.claim) or f"{finding.title}: {finding.why_vulnerable}"
    finding.attacker_start = _text(finding.attacker_start) or "Unspecified in legacy finding; review required."
    finding.capabilities_gained = finding.capabilities_gained or [finding.impact]
    raw = finding.model_dump(exclude_none=True)
    fingerprint = _digest({k: raw.get(k) for k in _CLAIM_FIELDS})
    old_basis = finding.evidence_basis or {}
    basis = {}
    records: list[EvidenceRecord] = []
    issues: list[ConsistencyIssue] = []
    source_supported = False
    rederived = False
    observed = False

    def issue(code: str, message: str, severity: str = "error"):
        issues.append(ConsistencyIssue(code=code, severity=severity, message=message))

    def record(source: str, native: dict, *, polarity: str = "inconclusive",
               kind: str = "assessment", summary: str = "", decisive: str | None = None,
               control: str | None = None, satisfies=(), artifact: str | None = None) -> bool:
        current = {"claim": fingerprint, "commit": commit, "native": _digest(native)}
        previous = old_basis.get(source)
        stale = (isinstance(previous, dict)
                 and (previous.get("claim") != fingerprint or previous.get("commit") != commit)
                 and previous.get("native") == current["native"])
        basis[source] = previous if stale else current
        if stale:
            issue(f"{source}_stale", f"{source} evidence predates a change to the claim or revision.")
            polarity, satisfies = "inconclusive", ()
        records.append(EvidenceRecord(
            id=f"{_AUTO}{source}", source=source, kind=kind, polarity=polarity,
            summary=redact_text(summary), artifact=artifact or "validated_findings.json",
            decisive_observation=redact_text(decisive) if decisive else None,
            negative_control=control, obligations_satisfied=list(satisfies),
            claim_fingerprint=basis[source]["claim"], source_revision=basis[source]["commit"],
        ))
        return not stale

    record("audit", {k: raw.get(k) for k in _CLAIM_FIELDS}, kind="claim",
           summary="Audit hypothesis; the original claim is not independent supporting evidence.")
    v = finding.validation
    grounded = not finding.grounding or finding.grounding.status == "grounded"
    repaired = bool(raw.get("schema_repair_failed"))
    corrected = bool(finding.verification and finding.verification.verdict == "corrected")
    inherited = bool(raw.get("evidence_requires_review"))
    if inherited:
        issue("split_evidence_requires_review", "Split finding needs its own evidence review.")
    if corrected:
        issue("corrected_claim_requires_review", "Reconcile the source claim with deep-verification corrections.")
    if v:
        native = v.model_dump(exclude_none=True, exclude={"runtime", "live", "asan_poc"})
        valid = (v.verdict == "confirmed" and bool(_text(v.surviving_data_flow))
                 and grounded and not repaired and not corrected and not inherited)
        polarity = "supports" if valid else "contradicts" if v.verdict == "refuted" else "inconclusive"
        fresh = record("validation", native, polarity=polarity, kind="static_trace",
                       summary=v.rationale or f"Validation: {v.verdict}.",
                       decisive=v.surviving_data_flow,
                       satisfies=("argo:source_path",) if valid else ())
        source_supported = valid and fresh
        if v.verdict == "confirmed" and not valid:
            issue("static_support_incomplete", "Confirmation lacks a current supported source trace.",
                  "warning")
        if v.verdict == "out_of_scope":
            issue("out_of_scope", "The validation marks this claim outside the reporting scope.")
    corr = finding.corroboration
    if corr:
        record("corroboration", corr.model_dump(exclude_none=True), kind="context",
               summary=f"Corroboration: {corr.verdict}. {corr.rationale or ''}")
        if corr.verdict in {"design_accepted", "fixed_upstream"}:
            issue("not_reportable", f"Corroboration marks this finding {corr.verdict}.")

    verification = finding.verification
    if verification:
        valid = (verification.verdict == "reconfirmed"
                 and bool(_text(verification.independent_derivation)) and not inherited)
        polarity = ("supports" if valid else "contradicts"
                    if verification.verdict == "refuted" else "inconclusive")
        fresh = record("deep_verify", verification.model_dump(exclude_none=True),
                       polarity=polarity, kind="independent_derivation",
                       summary=verification.rationale or f"Deep verification: {verification.verdict}.",
                       decisive=verification.independent_derivation,
                       satisfies=("argo:source_path",) if valid else ())
        rederived = valid and fresh
        if verification.verdict == "reconfirmed" and not valid:
            issue("deep_verify_support_missing_derivation", "Independent support needs a claim-specific derivation.")

    extra = v.model_extra or {} if v else {}
    asan = extra.get("asan_poc")
    if isinstance(asan, dict):
        trace = _text(asan.get("crash_trace"))
        valid = (asan.get("verdict") == "confirmed" and bool(_SANITIZER.search(trace))
                 and not corrected and not inherited)
        fresh = record("asan", asan, polarity="supports" if valid else "inconclusive",
                       kind="sanitizer_observation",
                       summary=f"Recorded sanitizer result: {asan.get('verdict', 'unknown')}.",
                       decisive="Sanitizer diagnostic captured in native artifact." if valid else None,
                       artifact=f"asan_poc/{finding.id}/outcome.json",
                       satisfies=("argo:runtime",) if valid else ())
        observed |= valid and fresh
        if asan.get("verdict") == "confirmed" and not valid:
            issue("asan_confirmation_missing_observation", "Sanitizer confirmation lacks a current diagnostic.")

    for source in ("runtime", "live"):
        native = extra.get(source)
        if not isinstance(native, dict):
            continue
        observation, control = _observation(native, source)
        explicit = (bool(_text(native.get("evidence")))
                    and native.get("verdict_source") != "expectation_fallback"
                    and not corrected and not inherited)
        verdict = native.get("verdict")
        supports = explicit and observation is not None and verdict == f"{source}_confirmed"
        contradicts = explicit and observation is not None and verdict == f"{source}_refuted"
        fresh = record(source, native, polarity="supports" if supports else
                       "contradicts" if contradicts else "inconclusive",
                       kind="recorded_observation", summary=f"Native {source} assessment: {verdict}.",
                       decisive=observation, control=control, artifact=f"{source}_results.json",
                       satisfies=("argo:runtime",) if supports else ())
        observed |= supports and fresh
        if verdict in {f"{source}_confirmed", f"{source}_refuted"} and not (supports or contradicts):
            issue(f"{source}_confirmation_missing_observation",
                  f"{source} assessment needs review: missing observation, interpretation, or current claim.")

    # Imported feedback is an external disposition, never technical proof or runtime evidence.
    feedback = ctx.ledger.finding_feedback(ctx.load_scope().program_name,
                                          finding.dedup_key or "", run_id=ctx.run_id)
    finding.external_status = "unknown"
    if feedback is not None:
        status = "accepted" if feedback["accepted"] else "rejected"
        fresh = record("maintainer", feedback, kind="external_disposition",
                       summary=f"Imported disposition for this run: {status}.",
                       artifact="private findings ledger")
        if fresh:
            finding.external_status = status
        if status == "rejected":
            issue("maintainer_rejected", "Imported feedback rejects this report; review its disposition.")

    # Author-provided records are retained, but cannot satisfy obligations or promote proof.
    authored = [e.model_copy(deep=True) for e in finding.evidence if not e.id.startswith(_AUTO)]
    for e in authored:
        e.summary = redact_text(e.summary)
        e.decisive_observation = None
        e.negative_control = None
    if authored:
        issue("unverified_authored_evidence", "Author-provided evidence requires provenance review.", "warning")
    support = [e.id for e in records if e.polarity == "supports"]
    contradiction = [e.id for e in records if e.polarity == "contradicts"]
    finding.claim_status = "conflicted" if contradiction and support else "refuted" if contradiction else "active"
    if contradiction:
        issue("supporting_and_contradicting_evidence" if support else "refuted_evidence",
              "A recorded assessment contradicts the claim; retain it for human review.")
    # Categories summarize observed evidence. They are not a universal strength ordering.
    finding.proof_level = ("runtime_observed" if observed else "independently_rederived"
                           if rederived else "source_supported" if source_supported else "hypothesis")
    obligations: list[ProofObligation] = []
    for o in finding.proof_obligations:
        if o.id.startswith(_AUTO):
            continue
        copy = o.model_copy(deep=True)
        copy.status, copy.evidence_ids = "open", []
        copy.reason = "No claim-specific evidence link has been verified."
        obligations.append(copy)
    source_ids = [e.id for e in records if "argo:source_path" in e.obligations_satisfied]
    obligations.append(ProofObligation(
        id="argo:source_path", description="Trace the claimed source path.",
        status="satisfied" if source_ids else "open", evidence_ids=source_ids,
        reason=None if source_ids else "No current supported source trace."))
    preconditions = list(dict.fromkeys([*finding.preconditions,
        *(_text(x) or json.dumps(x, sort_keys=True) for x in (v.unmet_preconditions or []) if x)])) if v else finding.preconditions
    for item in preconditions:
        obligations.append(ProofObligation(
            id=f"argo:precondition:{_digest(item)[:16]}", description=f"Confirm precondition: {item}",
            reason="An explicit assumption is not evidence that it holds."))
    if v and v.verdict == "needs_runtime_verification" or any(s in extra for s in ("runtime", "live", "asan_poc")):
        runtime_ids = [e.id for e in records if "argo:runtime" in e.obligations_satisfied]
        obligations.append(ProofObligation(
            id="argo:runtime", description="Review the recorded runtime behavior and its applicability.",
            status="satisfied" if runtime_ids else "open", evidence_ids=runtime_ids,
            reason=None if runtime_ids else "Runtime behavior remains unresolved."))
    if contradiction:
        obligations.append(ProofObligation(
            id="argo:contradiction", description="Resolve contradictory evidence.",
            status="contradicted", evidence_ids=contradiction))
    uncertainty = [x for x in finding.remaining_uncertainty if not x.startswith(_AUTO)]
    uncertainty += [f"{_AUTO}{o.description}" for o in obligations if o.status != "satisfied"]
    uncertainty += [f"{_AUTO}{i.message}" for i in issues]
    finding.evidence = records + authored
    finding.evidence_basis = basis
    finding.proof_obligations = obligations
    finding.remaining_uncertainty = list(dict.fromkeys(uncertainty))
    finding.consistency_issues = issues
    return finding


def run(ctx: RunContext):
    path = ctx.validated_findings_path
    doc = json.loads(path.read_text(encoding="utf-8-sig"))
    commit = None
    if ctx.meta_path.is_file():
        commit = json.loads(ctx.meta_path.read_text(encoding="utf-8-sig")).get("repo_commit")
    normalized = []
    for raw in doc.get("findings", []):
        finding = normalize_finding(ctx, Finding.model_validate(raw), commit=commit)
        # Preserve native fields, explicit nulls and unknown extensions exactly.
        fields = ("claim", "attacker_start", "capabilities_gained", "evidence", "evidence_basis",
                  "proof_obligations", "remaining_uncertainty", "proof_level", "claim_status",
                  "external_status", "consistency_issues")
        derived = finding.model_dump(include=set(fields), exclude_none=True)
        normalized.append({**raw, **derived})
    doc["findings"] = normalized
    stats = doc.setdefault("stats", {})
    stats["proof_levels"] = {level: sum(f["proof_level"] == level for f in normalized) for level in _LEVELS}
    stats["open_proof_obligations"] = sum(o["status"] in {"open", "contradicted"}
        for f in normalized for o in f["proof_obligations"])
    stats["consistency_issues"] = sum(len(f["consistency_issues"]) for f in normalized)
    doc["evidence_contract"] = {"version": 1, "normalized": True}
    atomic_write_json(path, doc)
    print(f"[evidence] summarized {len(normalized)} finding(s)", file=sys.stderr)
    return path
