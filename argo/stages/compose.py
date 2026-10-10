"""Deterministic, evidence-gated composition of explicitly compatible findings.

This stage deliberately does *not* infer semantic equivalence, reachability, tenant boundaries,
or severity from prose.  An edge exists only when a currently active, source-supported finding's
declared capability exactly matches another active finding's declared precondition and both declare
the same attacker start, identity, tenant, deployment and configuration context.  The resulting
artifact is a review aid, never a new vulnerability or an automatic severity multiplier.
"""

from __future__ import annotations

import hashlib
import json
import re

from ..context import RunContext, atomic_write_json
from . import evidence

_ELIGIBLE_LEVELS = {
    "source_supported", "independently_rederived", "runtime_observed", "end_to_end_proven",
}
_GENERIC_STARTS = {"", "unspecified in legacy finding review required", "unknown", "n/a"}
_CONTEXT_FIELDS = ("principal", "tenant_scope", "deployment_scope", "configuration_scope")


def _key(value: object) -> str:
    """Normalize punctuation/case only; this is intentionally not semantic matching."""
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _eligible(finding: dict) -> bool:
    validation = finding.get("validation") or {}
    if validation.get("verdict") != "confirmed":
        return False
    if finding.get("claim_status", "active") != "active":
        return False
    if finding.get("external_status") == "rejected":
        return False
    if finding.get("proof_level") not in _ELIGIBLE_LEVELS:
        return False
    if any(issue.get("severity") == "error" for issue in finding.get("consistency_issues") or []
           if isinstance(issue, dict)):
        return False
    context = finding.get("attack_context")
    return (_key(finding.get("attacker_start")) not in _GENERIC_STARTS
            and isinstance(context, dict)
            and all(_key(context.get(field)) not in _GENERIC_STARTS for field in _CONTEXT_FIELDS))


def _path_id(ids: list[str]) -> str:
    return "path:" + hashlib.sha256("\x1f".join(ids).encode("utf-8")).hexdigest()[:16]


def _edge(source: dict, target: dict) -> dict | None:
    if source.get("id") == target.get("id"):
        return None
    if _key(source.get("attacker_start")) != _key(target.get("attacker_start")):
        return None
    if any(_key((source.get("attack_context") or {}).get(field))
           != _key((target.get("attack_context") or {}).get(field)) for field in _CONTEXT_FIELDS):
        return None
    target_preconditions = {
        _key(item): str(item).strip() for item in target.get("preconditions") or [] if _key(item)
    }
    for capability in source.get("capabilities_gained") or []:
        normalized = _key(capability)
        if normalized and normalized in target_preconditions:
            source_evidence = [str(item.get("id")) for item in source.get("evidence") or []
                               if isinstance(item, dict) and item.get("polarity") == "supports"
                               and item.get("id")]
            target_evidence = [str(item.get("id")) for item in target.get("evidence") or []
                               if isinstance(item, dict) and item.get("polarity") == "supports"
                               and item.get("id")]
            return {
                "from_finding": source["id"],
                "to_finding": target["id"],
                "capability": str(capability).strip(),
                "required_precondition": target_preconditions[normalized],
                "evidence_ids": sorted(set(source_evidence + target_evidence)),
            }
    return None


def _paths(edges: list[dict], *, max_hops: int, max_paths: int) -> list[dict]:
    """Enumerate bounded simple paths; order and identifiers remain stable across reruns."""
    by_source: dict[str, list[dict]] = {}
    for edge in edges:
        by_source.setdefault(edge["from_finding"], []).append(edge)
    for choices in by_source.values():
        choices.sort(key=lambda e: (e["to_finding"], _key(e["capability"])))

    out: list[dict] = []
    for start in sorted(by_source):
        stack: list[tuple[list[str], list[dict]]] = [([start], [])]
        while stack and len(out) < max_paths:
            ids, taken = stack.pop()
            current = ids[-1]
            for edge in reversed(by_source.get(current, [])):
                target = edge["to_finding"]
                if target in ids:
                    continue
                next_ids, next_edges = [*ids, target], [*taken, edge]
                out.append({"id": _path_id(next_ids), "finding_ids": next_ids, "edges": next_edges})
                if len(next_edges) < max_hops:
                    stack.append((next_ids, next_edges))
                if len(out) >= max_paths:
                    break
    return sorted(out, key=lambda p: (len(p["finding_ids"]), p["finding_ids"]))[:max_paths]


def input_fingerprint(findings: list[dict]) -> str:
    """Return a stable freshness token for the fields composition is allowed to rely on."""
    relevant = [{key: finding.get(key) for key in (
        "id", "attacker_start", "attack_context", "preconditions", "capabilities_gained",
        "proof_level", "claim_status", "external_status", "consistency_issues", "evidence",
        "validation",
    )} for finding in findings if isinstance(finding, dict)]
    raw = json.dumps(sorted(relevant, key=lambda f: str(f.get("id", ""))),
                     sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def run(ctx: RunContext):
    """Write ``attack_paths.json`` without changing findings, proofs, drafts, or severity."""
    evidence.run(ctx)  # standalone-safe and idempotent; composition consumes normalized evidence.
    doc = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8-sig"))
    eligible = [f for f in doc.get("findings") or [] if isinstance(f, dict) and _eligible(f)]
    edges = [edge for source in eligible for target in eligible if (edge := _edge(source, target))]
    edges.sort(key=lambda e: (e["from_finding"], e["to_finding"], _key(e["capability"])))
    paths = _paths(edges, max_hops=ctx.config.attack_path_max_hops,
                   max_paths=ctx.config.attack_path_max_paths)
    by_id = {str(f["id"]): f for f in eligible if f.get("id")}
    for path in paths:
        first, last = by_id[path["finding_ids"][0]], by_id[path["finding_ids"][-1]]
        path["attacker_start"] = first["attacker_start"]
        path["proof_level"] = min(
            (f.get("proof_level") for f in (by_id[item] for item in path["finding_ids"])),
            key=("hypothesis", "source_supported", "independently_rederived", "runtime_observed",
                 "end_to_end_proven").index,
        )
        path["impact"] = last.get("impact", "")
        path["status"] = "supported"
        path["note"] = ("Exact declared capability/precondition match only; review tenant, deployment, "
                        "and runtime assumptions. This does not change severity or prove end-to-end exploitability.")
    payload = {
        "schema_version": 1,
        "status": "evidence_gated",
        "input_fingerprint": input_fingerprint(doc.get("findings") or []),
        "paths": paths,
        "stats": {
            "eligible_findings": len(eligible),
            "exact_capability_edges": len(edges),
            "paths_emitted": len(paths),
        },
        "note": ("Generated deterministically from active, source-supported findings. Only identical "
                 "normalized capability/precondition, attacker-start, identity, tenant, deployment, "
                 "and configuration declarations form an edge; "
                 "no semantic inference, severity change, or submission decision is made."),
    }
    atomic_write_json(ctx.attack_paths_path, payload)
    return ctx.attack_paths_path
