"""Phase 6 — verify a proposed fix patch on an ISOLATED COPY of the repo.

Hard guarantees (the target repo is *detection-only* and read-only — a fix is a proposal for a
human, never applied in place):

  * the target repo is **never** mutated — every check runs on a throwaway ``copytree``;
  * a patch is accepted (``verified: true``) only if it **(1) applies**, **(2) still builds /
    compiles**, and **(3) introduces NO NEW errors** vs. a pre-patch baseline of the same copy.

Pre-existing breakage (a repo that doesn't compile, or has no toolchain) does not fail a patch:
we diff the *patched* error set against the *baseline* error set, so only errors the patch
**introduces** count against it.

Build / compile can run two ways:
  * **local** (default) — dependency-free per-file checks auto-detected from the changed files
    (``python -m py_compile``, ``node --check``, ``go build``, ``cargo check`` when the toolchain
    is on PATH); files with no available checker are reported as ``not checked``, never failed;
  * **docker** (``docker="image"``) or an explicit ``build_cmd`` — runs your build command in the
    workspace (in Docker with ``--network=none`` for a clean, isolated, offline toolchain).
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

_PLUS_TARGET = re.compile(r"^\+\+\+ (?:b/)?(.+?)\s*$", re.M)
_LINECOL = re.compile(r":\d+(:\d+)?")
_ERR_HINTS = ("error", "syntaxerror", "cannot", "expected", "undefined",
              "panic", "failed", "unresolved", "traceback")


def patch_targets(patch: str) -> list[str]:
    """Files a unified diff writes to (the ``+++ b/...`` side; skips ``/dev/null`` deletions)."""
    out: list[str] = []
    for m in _PLUS_TARGET.finditer(patch or ""):
        p = m.group(1).strip()
        if p and p != "/dev/null" and p not in out:
            out.append(p)
    return out


@dataclass
class CheckOutcome:
    ran: bool                       # did any checker actually run?
    ok: bool                        # zero errors among the checks that ran
    errors: set[str] = field(default_factory=set)
    tool: str = "none"


def _norm_errors(text: str, workspace: Path) -> set[str]:
    """Reduce compiler output to stable error *signatures* (drop paths + line/col numbers), so
    a patch that merely shifts line numbers does not look like it introduced new errors."""
    ws = str(workspace)
    out: set[str] = set()
    for line in (text or "").splitlines():
        s = line.strip()
        if not s:
            continue
        s = s.replace(ws, "").replace(ws.replace("\\", "/"), "")
        s = _LINECOL.sub(":", s)
        if any(h in s.lower() for h in _ERR_HINTS):
            out.add(s)
    return out


def _run(cmd: list[str], cwd: Path, timeout_s: int) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout_s)


def _copy_repo(repo_dir: Path, dst: Path) -> None:
    shutil.copytree(repo_dir, dst, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(".git", "node_modules", "__pycache__"))
    # The audit repo mount is hardened read-only; copytree preserves those bits. Restore write
    # so the patch tool can modify THE COPY (the original is never touched).
    for root, dirs, files in os.walk(dst):
        for name in dirs + files:
            p = Path(root) / name
            try:
                os.chmod(p, os.stat(p).st_mode | stat.S_IWUSR)
            except OSError:
                pass


def _apply_patch(workspace: Path, patch_file: Path, timeout_s: int) -> tuple[bool, str]:
    """Apply a unified diff to the workspace copy. ``git apply`` works without an initialized
    repo; fall back to GNU ``patch``."""
    git = shutil.which("git")
    if git:
        r = _run([git, "apply", "--whitespace=nowarn", "-p1", str(patch_file)], workspace, timeout_s)
        if r.returncode == 0:
            return True, "git apply"
        first_err = (r.stderr or r.stdout or "").strip()
    else:
        first_err = "git not found"
    patch_bin = shutil.which("patch")
    if patch_bin:
        # --fuzz=0: do not fuzzy-match context (offset is still allowed). Keeps "applies cleanly"
        # strict so a bogus patch is rejected rather than mangled into the file.
        r2 = _run([patch_bin, "-p1", "--fuzz=0", "--no-backup-if-mismatch", "-f", "-i",
                   str(patch_file)], workspace, timeout_s)
        if r2.returncode == 0:
            return True, "patch -p1"
        return False, (first_err + " | " + (r2.stderr or r2.stdout or "")).strip()
    return False, first_err or "no patch tool (git/patch) available"


def _check(workspace: Path, files: list[str], *, docker: str | None,
           build_cmd: str | None, timeout_s: int) -> CheckOutcome:
    """Build/compile check. With ``build_cmd``/``docker`` run that command over the whole
    workspace; otherwise auto-detect dependency-free per-file checks for the changed files."""
    if build_cmd:
        return _check_build_cmd(workspace, build_cmd, docker=docker, timeout_s=timeout_s)

    errors: set[str] = set()
    ran = False
    tools: list[str] = []

    def _exists(group: list[str]) -> list[Path]:
        return [workspace / f for f in group if (workspace / f).is_file()]

    py = _exists([f for f in files if f.endswith(".py")])
    if py:
        ran = True
        tools.append("py_compile")
        r = _run([sys.executable, "-m", "py_compile", *map(str, py)], workspace, timeout_s)
        if r.returncode != 0:
            errors |= _norm_errors(r.stderr + r.stdout, workspace)

    if shutil.which("node"):
        js = _exists([f for f in files if f.endswith((".js", ".mjs", ".cjs"))])
        for f in js:
            ran = True
            r = _run(["node", "--check", str(f)], workspace, timeout_s)
            if r.returncode != 0:
                errors |= _norm_errors(r.stderr + r.stdout, workspace)
        if js:
            tools.append("node --check")

    if shutil.which("go") and any(f.endswith(".go") for f in files):
        ran = True
        tools.append("go build")
        r = _run(["go", "build", "./..."], workspace, timeout_s)
        if r.returncode != 0:
            errors |= _norm_errors(r.stderr + r.stdout, workspace)

    if shutil.which("cargo") and any(f.endswith(".rs") for f in files):
        ran = True
        tools.append("cargo check")
        r = _run(["cargo", "check", "--quiet"], workspace, timeout_s)
        if r.returncode != 0:
            errors |= _norm_errors(r.stderr + r.stdout, workspace)

    return CheckOutcome(ran=ran, ok=not errors, errors=errors, tool="+".join(tools) or "none")


def _check_build_cmd(workspace: Path, build_cmd: str, *, docker: str | None,
                     timeout_s: int) -> CheckOutcome:
    if docker:
        if not shutil.which("docker"):
            return CheckOutcome(ran=False, ok=True, tool=f"docker:{docker} (unavailable)")
        cmd = ["docker", "run", "--rm", "--network=none",
               "-v", f"{workspace}:/src", "-w", "/src", docker, "sh", "-lc", build_cmd]
        cwd = workspace
        tool = f"docker:{docker}"
    else:
        sh = shutil.which("sh") or shutil.which("bash")
        if not sh:
            return CheckOutcome(ran=False, ok=True, tool="build_cmd (no shell)")
        cmd = [sh, "-lc", build_cmd]
        cwd = workspace
        tool = build_cmd
    r = _run(cmd, cwd, timeout_s)
    errors = _norm_errors(r.stdout + r.stderr, workspace) if r.returncode != 0 else set()
    return CheckOutcome(ran=True, ok=r.returncode == 0, errors=errors, tool=tool)


def verify_patch(repo_dir, patch: str, *, docker: str | None = None,
                 build_cmd: str | None = None, timeout_s: int = 180,
                 on_patched=None) -> dict:
    """Apply ``patch`` to an isolated copy of ``repo_dir`` and report whether it builds and
    introduces no new errors. The original ``repo_dir`` is never touched.

    Returns a dict: ``applied``, ``compiles``, ``new_errors`` (introduced), ``verified``,
    ``targets``, ``tool``, plus diagnostic details.

    ``on_patched(workspace) -> dict`` is an optional hook called on the **patched copy** (once the
    patch has applied), before cleanup; its returned dict is merged into the result. Phase-6 uses it
    to re-audit the patched copy (A3 — "is the bug actually gone?"). It never touches the original
    repo and any error in it is captured, never raised.
    """
    repo_dir = Path(repo_dir)
    targets = patch_targets(patch)
    tmp = Path(tempfile.mkdtemp(prefix="argo-verify-"))
    ws = tmp / "ws"
    result: dict = {"targets": targets}
    try:
        _copy_repo(repo_dir, ws)
        baseline = _check(ws, targets, docker=docker, build_cmd=build_cmd, timeout_s=timeout_s)

        patch_file = tmp / "fix.diff"
        # Write with LF preserved (no Windows CRLF translation) — a CRLF-corrupted patch file
        # makes git/patch reject it as "malformed".
        normalized = patch.replace("\r\n", "\n").replace("\r", "\n")
        patch_file.write_text(normalized, encoding="utf-8", newline="\n")
        applied, apply_detail = _apply_patch(ws, patch_file, timeout_s)
        result.update(applied=applied, apply_detail=apply_detail[:600], tool=baseline.tool)
        if not applied:
            result.update(compiles=False, ran_build=False, baseline_ok=baseline.ok,
                          new_errors=[], verified=False,
                          reason="patch did not apply cleanly to a fresh copy")
            return result

        patched = _check(ws, targets, docker=docker, build_cmd=build_cmd, timeout_s=timeout_s)
        new_errors = sorted(patched.errors - baseline.errors)
        compiles = patched.ok or not patched.ran
        verified = applied and not new_errors and compiles
        result.update(
            ran_build=patched.ran,
            tool=patched.tool,
            baseline_ok=baseline.ok,
            compiles=compiles,
            new_errors=new_errors[:20],
            verified=verified,
            reason=("ok" if verified
                    else "introduces new errors" if new_errors
                    else "does not compile" if not compiles
                    else "ok"),
        )
        if on_patched is not None:
            try:
                extra = on_patched(ws)            # ws = the patched copy (still alive here)
                if extra:
                    result.update(extra)
            except Exception as exc:              # never let the hook crash verification
                result["re_audit"] = {"ran": False, "reason": f"re-audit error: {exc}"[:300]}
        return result
    except subprocess.TimeoutExpired:
        result.update(applied=result.get("applied", False), compiles=False, verified=False,
                      new_errors=[], reason=f"verification timed out after {timeout_s}s")
        return result
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
