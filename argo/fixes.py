"""Phase 6 — remediation (fix) pipeline. OPT-IN, separate from the detection-only audit.

For each CONFIRMED finding in ``validated_findings.json`` it asks the model to produce a
**reviewable patch as a unified diff** (it reads the repo READ-ONLY and writes a ``fix.diff``
artifact — it never edits the target). Each patch is then handed to :mod:`argo.verify`, which
applies it to an **isolated copy** and confirms it still builds and introduces no new errors.

Outputs (under ``runs/<id>/``):
  * ``patches/<finding_id>.diff`` — the proposed fix, for human review / PR;
  * ``fixes_report.json`` — per-finding verify verdict (applies? compiles? new errors? verified?).

Guardrails: the target ``repo/`` is never modified; nothing is applied in place; no PR is opened.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .config import ARTIFACT_TOOLS
from .context import RunContext, collect_output_files
from .runner import RunnerError
from .verify import verify_patch

_SYSTEM = """You are a senior application-security engineer producing a REMEDIATION for one \
confirmed vulnerability from an AUTHORIZED source-only review. You have READ-ONLY access to the \
repository (Read/Grep/Glob).

HARD RULES (non-negotiable):
- Produce a fix as a UNIFIED DIFF only. NEVER edit the repository in place (it is read-only).
- Do NOT contact, scan, or exercise any live host. Static reasoning only.
- The fix must address the ROOT CAUSE (e.g. parameterize the query, enforce the authz check), be \
minimal, and must NOT change unrelated behavior or break compilation.

OUTPUT: write a single file `fix.diff` in your current working directory containing a unified diff \
that `git apply -p1` can apply from the repository root. Use `a/<path>` and `b/<path>` headers with \
paths relative to the repo root. Include enough context lines (3) for the hunk to apply. After \
writing it, end your reply with a one-line summary of the fix."""


def _primary_file(finding: dict) -> str:
    for ref in finding.get("affected") or []:
        path = str(ref).split(":", 1)[0].strip()
        if path:
            return path
    return ""


def _build_prompt(finding: dict, repo_dir: Path) -> str:
    return "\n\n".join([
        _SYSTEM,
        f"=== REPOSITORY ROOT (read-only) ===\n{repo_dir.resolve()}",
        "=== CONFIRMED FINDING TO FIX ===",
        json.dumps(finding, indent=2),
        f"Primary location: {_primary_file(finding) or '(see affected[])'}",
        "Read the affected file(s), then write `fix.diff` with the minimal root-cause fix.",
    ])


# --------------------------------------------------------------- A3: re-audit the patched copy
_REAUDIT_SYSTEM = """You are a security auditor reviewing specific source files from an AUTHORIZED \
source-only review. You have READ-ONLY access to the repository (Read/Grep/Glob). Audit ONLY the \
file(s) listed below for security vulnerabilities (injection, broken authz / IDOR, SSRF, path \
traversal, unsafe deserialization, weak crypto, hardcoded secrets, etc.).

Report ONLY what you can actually substantiate in the code as it is now — do NOT assume a previously \
reported issue is present, and do NOT invent issues. Detection ONLY: do not patch, do not contact \
any live host.

OUTPUT: write a single file `REAUDIT_FINDINGS.json` in your current working directory:
{"findings": [{"cwe": "CWE-89", "affected": ["path/to/file.py:42"], "title": "..."}]}
If you find no vulnerabilities in these file(s), write {"findings": []}."""


def _norm_cwe(s) -> str:
    m = re.search(r"\d+", str(s or ""))
    return m.group(0) if m else ""


def _file_of(ref: str) -> str:
    return str(ref).split(":", 1)[0].replace("\\", "/").strip().lstrip("./").lower()


def _affected_files(finding: dict) -> list[str]:
    seen: list[str] = []
    for ref in finding.get("affected") or []:
        f = _file_of(ref)
        if f and f not in seen:
            seen.append(f)
    return seen


def _still_present(reaudit_findings: list[dict], orig_cwe: str, orig_files: set[str]) -> bool:
    """Does the re-audit still report the original vuln (same CWE class, same file)? Lenient on
    line numbers — a fix usually shifts them. File+CWE match is the right granularity for
    'is this vulnerability gone'."""
    for f in reaudit_findings:
        fc = _norm_cwe(f.get("cwe"))
        if orig_cwe and fc and fc != orig_cwe:
            continue
        ffiles = {_file_of(r) for r in (f.get("affected") or [])}
        if any(a == b or a.endswith("/" + b) or b.endswith("/" + a) for a in ffiles for b in orig_files):
            return True
    return False


def _build_reaudit_prompt(files: list[str], workspace: Path) -> str:
    listing = "\n".join(f"  - {f}" for f in files)
    return "\n\n".join([
        _REAUDIT_SYSTEM,
        f"=== REPOSITORY ROOT (read-only) ===\n{workspace.resolve()}",
        f"=== FILES TO AUDIT ===\n{listing}",
        "Read the file(s) above and write `REAUDIT_FINDINGS.json` with what you find.",
    ])


def _reaudit_patched(ctx: RunContext, workspace: Path, finding: dict) -> dict:
    """Run one focused, UNBIASED audit session on the patched copy (scoped to the finding's
    affected file(s)) and check whether the original vulnerability is still reported. The prompt
    never names the specific bug, so a 'gone' result means the model no longer detects that vuln
    class in that file — a *signal* the fix worked (pair it with the build check; it is
    probabilistic, not proof)."""
    files = _affected_files(finding)
    if not files:
        return {"re_audit": {"ran": False, "reason": "finding has no affected files"}}
    work = ctx.work_dir("reaudit", finding["id"])
    work.mkdir(parents=True, exist_ok=True)
    try:
        result = ctx.runner.run(
            prompt=_build_reaudit_prompt(files, workspace),
            run_dir=ctx.run_dir,
            work_dir=work,
            model=ctx.config.model_for("audit"),
            stage="audit",
            run_id=ctx.run_id,
            repo_dir=workspace,                # the PATCHED copy, mounted READ-ONLY
            allowed_tools=ARTIFACT_TOOLS,
            label=f"reaudit-{finding['id']}",
        )
        out = collect_output_files(result, "REAUDIT_FINDINGS.json")
    except RunnerError as exc:
        return {"re_audit": {"ran": False, "reason": f"session failed: {exc}"[:300]}}
    rf = next((f for f in out if f.name == "REAUDIT_FINDINGS.json"),
              next((p for p in work.glob("*.json") if p.is_file()), None))
    reaudit_findings: list[dict] = []
    if rf is not None:
        try:
            reaudit_findings = json.loads(rf.read_text(encoding="utf-8")).get("findings", [])
        except (json.JSONDecodeError, AttributeError):
            reaudit_findings = []
    still = _still_present(reaudit_findings, _norm_cwe(finding.get("cwe")), set(files))
    return {"re_audit": {"ran": True, "still_present": still, "confirmed_fixed": not still,
                         "findings": len(reaudit_findings), "files": files}}


def _confirmed_findings(ctx: RunContext) -> list[dict]:
    path = ctx.validated_findings_path
    if not path.exists():
        raise FileNotFoundError(
            f"no validated_findings.json for run {ctx.run_id} — run the audit pipeline first")
    return json.loads(path.read_text(encoding="utf-8")).get("findings", [])


def _generate_one(ctx: RunContext, finding: dict) -> str | None:
    """Run one remediation session; return the unified-diff text, or None if none was produced."""
    work = ctx.work_dir("remediate", finding["id"])
    work.mkdir(parents=True, exist_ok=True)
    result = ctx.runner.run(
        prompt=_build_prompt(finding, ctx.repo_dir),
        run_dir=ctx.run_dir,
        work_dir=work,
        model=ctx.config.model_for("remediate"),
        stage="remediate",
        run_id=ctx.run_id,
        repo_dir=ctx.repo_dir,            # READ-ONLY
        allowed_tools=ARTIFACT_TOOLS,     # read repo + write the diff into the scratch dir
        label=f"remediate-{finding['id']}",
    )
    files = collect_output_files(result, "*")
    diff = next((f for f in files if f.name == "fix.diff"), None)
    if diff is None:  # partial-recovery: glob the scratch dir
        diff = next((p for p in work.glob("*.diff") if p.is_file()), None)
    if diff is None:
        return None
    text = diff.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        return None
    if not text.endswith("\n"):     # a unified diff's final line MUST be newline-terminated
        text += "\n"
    return text


def generate_fixes(ctx: RunContext, *, verify: bool = True, docker: str | None = None,
                   build_cmd: str | None = None, only: set[str] | None = None,
                   re_audit: bool = False) -> dict:
    """Propose + verify a fix for each confirmed finding. Returns the fixes report (also written
    to ``runs/<id>/fixes_report.json``).

    ``re_audit`` (A3) additionally re-audits the **patched copy** per finding and records whether
    the original vulnerability is still detected (``verify.re_audit.confirmed_fixed``). It needs
    ``verify=True`` (the re-audit runs on the verified isolated copy) and costs one extra model
    session per patched finding.
    """
    findings = _confirmed_findings(ctx)
    patches_dir = ctx.run_dir / "patches"
    patches_dir.mkdir(parents=True, exist_ok=True)

    fixes: list[dict] = []
    for finding in findings:
        fid = finding.get("id")
        if not fid or (only and fid not in only):
            continue
        diff = _generate_one(ctx, finding)
        entry: dict = {"finding_id": fid, "title": finding.get("title"),
                       "primary_file": _primary_file(finding)}
        if not diff:
            entry.update(patch=None, verify={"verified": False, "reason": "no patch produced"})
            fixes.append(entry)
            continue
        patch_path = patches_dir / f"{fid}.diff"
        # keep LF so the .diff stays valid for `git apply` (avoid Windows CRLF translation)
        patch_path.write_text(diff.replace("\r\n", "\n"), encoding="utf-8", newline="\n")
        entry["patch"] = patch_path.name
        if verify:
            on_patched = ((lambda ws, _f=finding: _reaudit_patched(ctx, ws, _f))
                          if re_audit else None)
            entry["verify"] = verify_patch(ctx.repo_dir, diff, docker=docker, build_cmd=build_cmd,
                                           on_patched=on_patched)
        fixes.append(entry)

    report = {
        "run_id": ctx.run_id,
        "count": len(fixes),
        "patched": sum(1 for f in fixes if f.get("patch")),
        "verified": sum(1 for f in fixes if (f.get("verify") or {}).get("verified")),
        "verify_enabled": verify,
        "fixes": fixes,
    }
    if re_audit:
        ran = [f for f in fixes if (f.get("verify") or {}).get("re_audit", {}).get("ran")]
        confirmed = sum(1 for f in ran
                        if f["verify"]["re_audit"].get("confirmed_fixed"))
        report["re_audit_enabled"] = True
        report["re_audit_ran"] = len(ran)
        report["re_audit_confirmed"] = confirmed
        report["re_audit_confirmed_rate"] = round(confirmed / len(ran), 4) if ran else 0.0
    (ctx.run_dir / "fixes_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
