"""Phase 6 — remediation (fix) pipeline. OPT-IN, separate from the detection-only audit.

For each CONFIRMED finding in ``validated_findings.json`` it asks the model to rewrite the affected
file(s) IN FULL (into ``FIX.json``, reading the repo READ-ONLY — it never edits the target) and then
**computes the unified diff mechanically** with :mod:`difflib`. The model never writes a diff or
counts ``@@`` line ranges, which removes the dominant failure mode observed on large real repos
(multi-hunk diffs that fail ``git apply`` with "corrupt patch" because the model miscounts hunk
headers). Each computed patch is handed to :mod:`argo.verify`, which applies it to an **isolated
copy** and confirms it still builds and introduces no new errors.

Outputs (under ``runs/<id>/``):
  * ``patches/<finding_id>.diff`` — the proposed fix (Argo-computed), for human review / PR;
  * ``fixes_report.json`` — per-finding verify verdict (applies? compiles? new errors? verified?).

Guardrails: the target ``repo/`` is never modified; nothing is applied in place; no PR is opened.
"""

from __future__ import annotations

import difflib
import json
import re
import sys
from pathlib import Path

from .branding import attribution_trailer, coauthored_by
from .config import ARTIFACT_TOOLS
from .context import RunContext, collect_output_files
from .runner import RunnerError
from .verify import verify_patch

_SYSTEM = """You are a senior application-security engineer producing a REMEDIATION for one \
confirmed vulnerability from an AUTHORIZED source-only review. You have READ-ONLY access to the \
repository (Read/Grep/Glob).

HARD RULES (non-negotiable):
- NEVER edit the repository in place (it is read-only). Do NOT contact, scan, or exercise any live \
host. Static reasoning only.
- The fix must address the ROOT CAUSE (e.g. parameterize the query, enforce the authz check), be \
minimal, and must NOT change unrelated behavior or break compilation.

HOW TO DELIVER THE FIX — write a single file `FIX.json` in your current working directory. For each \
file you change give EITHER a full rewrite OR search/replace edits:
{
  "summary": "<one-line description of the fix>",
  "files": [
    {"path": "<repo-relative path>", "new_content": "<the COMPLETE new file text>"},
    {"path": "<repo-relative path>", "edits": [
      {"search": "<exact snippet copied verbatim from the file>", "replace": "<its replacement>"}
    ]}
  ]
}

- Do NOT write a unified diff and do NOT count line numbers — Argo computes the diff mechanically, so \
a wrong `@@` header can never break the patch.
- `new_content` (preferred for small/medium files): read the file IN FULL, then put its ENTIRE new \
contents here — the whole file, not a snippet. Copy the original exactly and change ONLY what the fix \
requires, preserving every other line, the indentation, and the trailing newline.
- `edits` (use for LARGE files, to avoid re-emitting the whole file): a list of search/replace blocks. \
Each `search` MUST be copied verbatim from the current file (exact whitespace/indentation) and MUST \
match EXACTLY ONE place in it; `replace` is the new text. Include enough surrounding lines to make \
each `search` unique. Argo applies the edits to the original and computes the diff. If a `search` is \
not found or is ambiguous the whole file's edit is rejected — so prefer `new_content` when unsure.
- Give exactly one of `new_content` or `edits` per file; one object per file you change (usually one). \
After writing `FIX.json`, end your reply with the one-line summary."""


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
        "Read the affected file(s) in full, then write `FIX.json` with the minimal root-cause fix "
        "(complete rewritten file contents).",
    ])


def _apply_edits(old: str, edits: list) -> str | None:
    """Apply search/replace blocks to ``old`` and return the new text, or None if any block does not
    match EXACTLY ONCE (ambiguous or missing) — partial application is never returned. This lets the
    model avoid re-emitting a whole large file while Argo still computes the diff mechanically."""
    if not isinstance(edits, list) or not edits:
        return None
    text = old
    for e in edits:
        if not isinstance(e, dict) or "search" not in e or "replace" not in e:
            return None
        search = str(e["search"]).replace("\r\n", "\n")
        replace = str(e["replace"]).replace("\r\n", "\n")
        if not search or text.count(search) != 1:   # must be present and unambiguous
            return None
        text = text.replace(search, replace, 1)
    return text if text != old else None


def _new_content_for(entry: dict, old: str) -> str | None:
    """Resolve an entry's target file text from a full rewrite (``new_content``) or search/replace
    (``edits``). Returns None when the entry is unusable (so the caller skips that file)."""
    if "new_content" in entry:
        return str(entry["new_content"]).replace("\r\n", "\n")
    if "edits" in entry:
        return _apply_edits(old, entry["edits"])
    return None


def _mechanical_diff(repo_dir: Path, files: list) -> str:
    """Build a ``git apply -p1``-able unified diff, computed by difflib so the model never authors
    (and never miscounts) hunk headers. Each entry is ``{"path": <repo-relative>, ...}`` carrying
    either a full ``new_content`` rewrite or a list of ``edits`` (search/replace blocks); a no-op
    rewrite is skipped, and a path with no existing file is emitted as a new-file diff."""
    parts: list[str] = []
    for entry in files or []:
        if not isinstance(entry, dict):
            continue
        rel = str(entry.get("path") or "").replace("\\", "/").strip().lstrip("./")
        if not rel:
            continue
        old_file = repo_dir / rel
        is_new = not old_file.exists()
        old = "" if is_new else old_file.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
        new = _new_content_for(entry, old)
        if new is None:
            continue
        if old == new:
            continue  # the model returned the file unchanged — nothing to patch
        # keep the original file's trailing-newline convention so the hunk stays clean
        if not is_new and old.endswith("\n") and new and not new.endswith("\n"):
            new += "\n"
        body = "".join(difflib.unified_diff(
            old.splitlines(keepends=True), new.splitlines(keepends=True),
            fromfile="/dev/null" if is_new else f"a/{rel}", tofile=f"b/{rel}"))
        if not body:
            continue
        header = f"diff --git a/{rel} b/{rel}\n" + ("new file mode 100644\n" if is_new else "")
        parts.append(header + body)
    return "".join(parts)


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


def _diff_from_fix_json(ctx: RunContext, work: Path, files: list) -> str | None:
    """Read the model's ``FIX.json`` (full-file rewrites) and return the mechanically-computed
    unified diff, or None if there is no usable FIX.json / it yields no change."""
    fj = next((f for f in files if f.name == "FIX.json"), None) \
        or next((p for p in work.glob("FIX.json") if p.is_file()), None)
    if fj is None:
        return None
    try:
        data = json.loads(fj.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return None
    diff = _mechanical_diff(ctx.repo_dir, data.get("files") if isinstance(data, dict) else None)
    return diff or None


def _generate_one(ctx: RunContext, finding: dict) -> str | None:
    """Run one remediation session; return the unified-diff text, or None if none was produced.

    Primary path: the model writes ``FIX.json`` (full rewritten file(s)) and Argo computes the diff
    with difflib. Legacy fallback: a model that wrote a raw ``*.diff`` is still accepted. A single
    session failing (timeout / API error) must NOT abort the whole fix run — we recover any partial
    scratch output and otherwise return None so the caller records this finding as un-patched and
    moves on (mirrors the audit stage's per-focus resilience)."""
    work = ctx.work_dir("remediate", finding["id"])
    work.mkdir(parents=True, exist_ok=True)
    try:
        result = ctx.runner.run(
            prompt=_build_prompt(finding, ctx.repo_dir),
            run_dir=ctx.run_dir,
            work_dir=work,
            model=ctx.config.model_for("remediate"),
            stage="remediate",
            run_id=ctx.run_id,
            repo_dir=ctx.repo_dir,            # READ-ONLY
            allowed_tools=ARTIFACT_TOOLS,     # read repo + write FIX.json into the scratch dir
            label=f"remediate-{finding['id']}",
        )
        files = collect_output_files(result, "*")
    except RunnerError as exc:
        files = sorted(work.glob("*"))        # the session may have written FIX.json before dying
        if not files:
            print(f"[fixes] {finding['id']}: remediation session failed ({exc}); no patch",
                  file=sys.stderr)
            return None
        print(f"[fixes] {finding['id']}: session failed ({exc}); recovered partial from scratch",
              file=sys.stderr)

    # Primary: mechanically compute the diff from the model's full-file rewrite.
    text = _diff_from_fix_json(ctx, work, files)
    if text is None:
        # Legacy fallback: a model (or partial recovery) that produced a raw unified diff.
        diff = next((f for f in files if f.name == "fix.diff"), None) \
            or next((p for p in work.glob("*.diff") if p.is_file()), None)
        text = diff.read_text(encoding="utf-8", errors="replace") if diff is not None else None
    if not text or not text.strip():
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
    if ctx.config.attribution:
        # Provenance for remediation PRs: drop these trailers into the PR body / commit message so the
        # patches are attributable to Argo (the .diff bytes stay untouched, so `git apply` is unaffected).
        report["attribution"] = {
            "generated_with": attribution_trailer(),
            "coauthored_by": coauthored_by(),
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
