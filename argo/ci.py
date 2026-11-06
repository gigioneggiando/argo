"""CI integration: SARIF export and a severity gate over a finished run (no model calls).

Both read ``validated_findings.json`` and count exactly what ``REPORT.md`` presents as reportable:
the report's effective severity, validation verdict, corroboration verdict and refuted/conflicted
checks are reused, so CI never disagrees with the report a human reads.

* :func:`to_sarif` -> SARIF 2.1.0 for GitHub code scanning (``github/codeql-action/upload-sarif``):
  one rule per CWE, ``level`` + ``security-severity`` from the effective severity, a stable
  ``partialFingerprints`` from the finding's dedup key so alerts survive re-runs.
* :func:`gate` -> the reportable findings at or above a severity threshold (exit non-zero in CI).

By default only ``confirmed`` findings count; ``include_unverified`` adds
``needs_runtime_verification``. Vendor-documented (``design_accepted``), already-fixed
(``fixed_upstream``) and refuted/conflicted/stale claims never count.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import __version__
from .grounding import is_explicit_path
from .ranking import severity_rank, split_ref
from .stages.report import SEVERITY_ORDER, _corr_verdict, _eff_sev, _proof_refuted, _verdict

#: GitHub maps security-severity >= 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.
_SECURITY_SEVERITY = {"Critical": "9.5", "High": "8.0", "Medium": "5.5", "Low": "3.0",
                      "Informational": "0.0"}
_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note",
          "Informational": "note"}
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_ARGO_URI = "https://github.com/gigioneggiando/argo"


def load_findings(run_dir: Path) -> list[dict]:
    path = Path(run_dir) / "validated_findings.json"
    doc = json.loads(path.read_text(encoding="utf-8-sig"))
    return list(doc.get("findings") or [])


def reportable(f: dict, *, include_unverified: bool = False) -> bool:
    allowed = {"confirmed"} | ({"needs_runtime_verification"} if include_unverified else set())
    return (_verdict(f) in allowed
            and _corr_verdict(f) not in {"design_accepted", "fixed_upstream"}
            and not _proof_refuted(f))


def normalize_threshold(value: str) -> str:
    for sev in SEVERITY_ORDER:
        if sev.lower().startswith(value.strip().lower()) and value.strip():
            return sev
    raise ValueError(f"unknown severity {value!r}; choose from {', '.join(SEVERITY_ORDER)}")


def gate(findings: list[dict], fail_on: str, *, include_unverified: bool = False) -> list[dict]:
    """Reportable findings whose effective severity is at least ``fail_on`` (empty = pass)."""
    threshold = severity_rank(normalize_threshold(fail_on))
    return [f for f in findings
            if reportable(f, include_unverified=include_unverified)
            and severity_rank(_eff_sev(f)) >= threshold]


def _rule_id(f: dict) -> str:
    m = re.search(r"(\d+)", str(f.get("cwe") or ""))
    return f"CWE-{m.group(1)}" if m else "argo-finding"


def _locations(f: dict) -> list[dict]:
    out = []
    for ref in f.get("affected") or []:
        # Only repo-relative file paths become locations (symbol-style citations cannot be mapped).
        if not is_explicit_path(str(ref)):
            continue
        file, line = split_ref(str(ref))
        file = file.replace("\\", "/")
        while file.startswith("./"):
            file = file[2:]
        if not file or file.startswith(("/", "../")) or re.match(r"^[A-Za-z]:", file):
            continue
        loc: dict = {"physicalLocation": {"artifactLocation": {"uri": file,
                                                               "uriBaseId": "%SRCROOT%"}}}
        if line and line.isdigit() and int(line) > 0:
            loc["physicalLocation"]["region"] = {"startLine": int(line)}
        out.append(loc)
    return out


def _message(f: dict) -> str:
    parts = [str(f.get("title") or "").strip()]
    why = " ".join(str(f.get("why_vulnerable") or "").split())
    if why:
        parts.append(why[:1500])
    fix = " ".join(str(f.get("recommended_fix") or "").split())
    if fix:
        parts.append("Fix: " + fix[:600])
    return "\n\n".join(p for p in parts if p) or str(f.get("id") or "Argo finding")


def to_sarif(findings: list[dict], *, run_id: str = "", include_unverified: bool = False) -> dict:
    selected = [f for f in findings if reportable(f, include_unverified=include_unverified)]
    rules: dict[str, dict] = {}
    results = []
    for f in sorted(selected, key=lambda f: (-severity_rank(_eff_sev(f)), str(f.get("id")))):
        sev = _eff_sev(f) if _eff_sev(f) in _LEVEL else "Medium"
        rid = _rule_id(f)
        rule = rules.setdefault(rid, {
            "id": rid, "name": rid.replace("-", ""),
            "shortDescription": {"text": rid if rid != "argo-finding" else "Argo security finding"},
            "helpUri": (f"https://cwe.mitre.org/data/definitions/{rid.split('-')[1]}.html"
                        if rid.startswith("CWE-") else _ARGO_URI),
            "properties": {"tags": ["security", rid], "security-severity": "0.0"},
        })
        if float(_SECURITY_SEVERITY[sev]) > float(rule["properties"]["security-severity"]):
            rule["properties"]["security-severity"] = _SECURITY_SEVERITY[sev]
        result = {
            "ruleId": rid, "level": _LEVEL[sev], "message": {"text": _message(f)},
            "locations": _locations(f),
            "partialFingerprints": {"argoDedupKey/v1": str(f.get("dedup_key") or f.get("id"))},
            "properties": {"argoId": f.get("id"), "severity": sev,
                           "security-severity": _SECURITY_SEVERITY[sev],
                           "verdict": _verdict(f), "confidence": f.get("confidence"),
                           "proofLevel": f.get("proof_level") or "hypothesis"},
        }
        results.append(result)
    return {
        "$schema": _SARIF_SCHEMA, "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Argo", "version": __version__,
                                "informationUri": _ARGO_URI, "rules": list(rules.values())}},
            "automationDetails": {"id": f"argo/{run_id}" if run_id else "argo"},
            "results": results,
        }],
    }
