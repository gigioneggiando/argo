"""Stage ASAN_POC (opt-in, sandboxed, C/C++ only) — turn an already-verified memory-safety finding
into a real AddressSanitizer crash trace.

Runs AFTER verify (or validate, if verify is off): a real crash trace is the most credibility-
boosting artifact a disclosure can carry, so this is only ever spent on findings that already
survived the full triage chain, never raw candidates.

Deliberately narrow V1 (see docs/architecture.md): no attempt to drive an arbitrary third-party
CMake/Autotools/Meson build. The model writes a MINIMAL, single-translation-unit harness that
`#include`s the real vulnerable source directly (never reimplements it) and compiles standalone —
the common shape of a parser/decoder/buffer-handling memory-safety bug. Anything outside that (the
function can't be isolated this way, the finding isn't C/C++, Docker is unavailable) degrades to an
honest, logged, per-finding skip — never a silent failure, and NEVER refutes the finding itself
(a failed harness attempt says nothing definitive either way; downgrade-don't-delete).

Safety model, same shape as the `runtime` stage: build+run happens on a CLONED, isolated copy of
the source inside an EPHEMERAL, EGRESS-BLOCKED (--network=none) Docker container. The compile and
execute steps are FIXED (not model-controlled) — the model only ever writes source text; a plain
subprocess call compiles and runs it, and a plain regex reads the result. No stage in this module
ever hands the model a shell/execution primitive.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ..config import ARTIFACT_TOOLS
from ..context import RunContext, atomic_write_json, collect_output_files
from ..guardrails import assert_prohibited_present
from ..ranking import split_ref
from ..rendering import render_prompt_pair, with_artifact_contract
from ..runner import RunnerError
from ..verify import _copy_repo
from .validate import _build_excerpts

#: CWE ids (normalized "CWE-NNN") this stage will attempt — the classic memory-safety families an
#: ASan/UBSan-instrumented single-function harness can actually catch. Deliberately conservative: a
#: CWE not in this set skips at zero cost rather than spending a harness-authoring session on a bug
#: class no sanitizer can observe (e.g. an authz/logic bug has no sanitizer signal to catch).
_MEMORY_SAFETY_CWES = frozenset({
    "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-125", "CWE-126", "CWE-127",
    "CWE-131", "CWE-190", "CWE-191", "CWE-369", "CWE-415", "CWE-416", "CWE-476", "CWE-590",
    "CWE-680", "CWE-787", "CWE-788", "CWE-823", "CWE-824",
})

_C_CPP_EXTENSIONS = (".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx")
_CPP_EXTENSIONS = (".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx")

#: Length cap on the crash_trace/reason text attached to a finding (the FULL output always lands on
#: disk at runs/<id>/asan_poc/<finding_id>/outcome.json regardless of this cap).
_CRASH_TRACE_CAP = 8000

_ASAN_ERROR_RE = re.compile(
    r"(ERROR: (?:AddressSanitizer|UndefinedBehaviorSanitizer): \S+.*)", re.DOTALL)
_ASAN_SUMMARY_RE = re.compile(r"^(SUMMARY: \S+.*)$", re.MULTILINE)


def _log(msg: str) -> None:
    print(f"[asan_poc] {msg}", file=sys.stderr)


def _docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _normalize_cwe(raw) -> list[str]:
    if isinstance(raw, str):
        raw = [raw]
    return [str(c).strip().upper() for c in (raw or []) if c]


def _applies(finding: dict) -> bool:
    """Zero-cost gate: only CWEs a sanitizer can actually observe, only C/C++ affected files."""
    if not any(c in _MEMORY_SAFETY_CWES for c in _normalize_cwe(finding.get("cwe"))):
        return False
    for ref in finding.get("affected") or []:
        file, _ = split_ref(ref)
        if file.lower().endswith(_C_CPP_EXTENSIONS):
            return True
    return False


# --------------------------------------------------------------------- harness-authoring session
def _harness_session(ctx: RunContext, scope, finding: dict) -> Path | None:
    """One offline LLM session: write harness.c/.cpp + NOTES.md for this finding. Returns the
    session's scratch work_dir on success, or None (logged) on any failure."""
    excerpts = _build_excerpts(
        ctx.repo_dir, finding.get("affected") or [],
        ctx.config.excerpt_context_lines, ctx.config.excerpt_max_bytes,
    )
    mapping = {
        "FINDING_JSON": json.dumps(finding, indent=2),
        "CODE_EXCERPTS": excerpts,
        "REPO_PATH": str(ctx.repo_dir.resolve()),
        "PROHIBITED_TECHNIQUES": "\n".join(f"- {p}" for p in scope.prohibited_techniques),
    }
    rendered, neutral_rendered = render_prompt_pair(
        ctx.assets_dir, "10_asan_harness_prompt.md", mapping)
    assert_prohibited_present(rendered, scope.prohibited_techniques)

    def _finish(text: str) -> str:
        return with_artifact_contract(text, artifacts=[
            {"type": "harness_source", "filename": "harness.c (or harness.cpp)", "schema": None,
             "desc": "the single-file, single-translation-unit ASan PoC harness"},
            {"type": "notes", "filename": "NOTES.md", "schema": None,
             "desc": "audit trail: real file(s) used, fidelity caveats, or why isolation wasn't "
                     "possible"},
        ], extra_rules=["Detection and reproduction ONLY: do not patch, do not contact any live "
                        "host, no network/filesystem access beyond writing the two deliverables."])

    prompt = _finish(rendered)
    neutral_prompt = _finish(neutral_rendered) if neutral_rendered is not None else None
    fid = finding.get("id", "?")
    work = ctx.work_dir("asan_poc", fid)
    try:
        result = ctx.runner.run(
            prompt=prompt, neutral_prompt=neutral_prompt, run_dir=ctx.run_dir, work_dir=work,
            model=ctx.config.model_for("asan_poc"), stage="asan_poc", run_id=ctx.run_id,
            repo_dir=ctx.repo_dir, allowed_tools=ARTIFACT_TOOLS, label=fid,
        )
    except RunnerError as exc:
        _log(f"{fid}: harness-authoring session failed ({exc}); skipping")
        return None
    if not collect_output_files(result, "harness.*"):
        _log(f"{fid}: harness session produced no harness.* file; skipping")
        return None
    return work


def _find_harness_file(work_dir: Path) -> Path | None:
    for name in ("harness.c", "harness.cpp", "harness.cc", "harness.cxx"):
        p = work_dir / name
        if p.is_file():
            return p
    matches = sorted(work_dir.glob("harness.*"))
    return matches[0] if matches else None


# --------------------------------------------------------------- deterministic compile + execute
def _run_in_sandbox(cfg, copy_dir: Path, name: str, shell_cmd: str,
                    timeout_s: int) -> subprocess.CompletedProcess | None:
    """One bounded, network-disabled container invocation. None on timeout (caller decides what
    that means for this phase)."""
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    try:
        return subprocess.run(
            ["docker", "run", "--rm", "--name", name, "--network=none",
             "-v", f"{copy_dir.resolve().as_posix()}:/src", "-w", "/src", cfg.asan_poc_image,
             "sh", "-lc", shell_cmd],
            capture_output=True, text=True, timeout=timeout_s)
    except (subprocess.TimeoutExpired, OSError):
        return None
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def _parse_sanitizer_output(output: str, *, exit_code: int) -> dict:
    """Pure string match, never the model. A clean exit does NOT refute the finding -- it means
    only that this harness attempt didn't trigger it (downgrade-don't-delete)."""
    m = _ASAN_ERROR_RE.search(output)
    if m:
        trace = m.group(1)
        summary_m = _ASAN_SUMMARY_RE.search(trace)
        summary = summary_m.group(1) if summary_m else trace.splitlines()[0]
        return {"verdict": "confirmed", "sanitizer_summary": summary,
                "crash_trace": trace[:_CRASH_TRACE_CAP], "reason": None}
    if exit_code != 0:
        return {"verdict": "crashed_no_sanitizer_output",
                "sanitizer_summary": f"process exited with code {exit_code}, no sanitizer report",
                "crash_trace": output[-_CRASH_TRACE_CAP:], "reason": None}
    return {"verdict": "not_reproduced", "sanitizer_summary": None,
            "crash_trace": output[-_CRASH_TRACE_CAP:] if output else None, "reason": None}


def _compile_and_run(cfg, run_id: str, finding_id: str, copy_dir: Path,
                     harness_path: Path) -> dict:
    """Two SEPARATE sandboxed invocations (compile, then execute) so each gets its own configured
    timeout. Never raises -- every path returns a verdict dict."""
    compiler = "clang++" if harness_path.suffix.lower() in _CPP_EXTENSIONS else "clang"
    name_base = re.sub(r"[^a-zA-Z0-9-]", "-", f"argo-asan-{run_id}-{finding_id}")[:55]

    compile_cmd = f"{compiler} -fsanitize=address,undefined -g -O0 {harness_path.name} -o poc"
    cp = _run_in_sandbox(cfg, copy_dir, name_base + "-cc", compile_cmd,
                        cfg.asan_poc_compile_timeout_s)
    if cp is None:
        return {"verdict": "not_attempted", "sanitizer_summary": None, "crash_trace": None,
                "reason": "compile exceeded the sandbox timeout"}
    if cp.returncode != 0 or not (copy_dir / "poc").exists():
        tail = ((cp.stderr or "") + (cp.stdout or "")).strip()[-_CRASH_TRACE_CAP:]
        return {"verdict": "not_attempted", "sanitizer_summary": None, "crash_trace": None,
                "reason": f"did not compile: {tail}"}

    rp = _run_in_sandbox(cfg, copy_dir, name_base + "-run", "./poc", cfg.asan_poc_run_timeout_s)
    if rp is None:
        return {"verdict": "not_attempted", "sanitizer_summary": None, "crash_trace": None,
                "reason": "execution exceeded the sandbox timeout"}
    return _parse_sanitizer_output((rp.stdout or "") + (rp.stderr or ""), exit_code=rp.returncode)


# ---------------------------------------------------------------------------- per-finding driver
def _run_one(ctx: RunContext, scope, finding: dict) -> dict | None:
    fid = finding.get("id", "?")
    work = _harness_session(ctx, scope, finding)
    if work is None:
        return None
    harness_path = _find_harness_file(work)
    if harness_path is None:
        _log(f"{fid}: session reported a harness file but none is on disk; skipping")
        return None
    notes_path = work / "NOTES.md"
    notes = notes_path.read_text(encoding="utf-8", errors="replace") if notes_path.is_file() else ""

    evidence_dir = ctx.run_dir / "asan_poc" / fid
    evidence_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(harness_path, evidence_dir / harness_path.name)
    if notes:
        (evidence_dir / "NOTES.md").write_text(notes, encoding="utf-8")

    tmp = Path(tempfile.mkdtemp(prefix="argo-asan-"))
    copy_dir = tmp / "src"
    try:
        _copy_repo(ctx.repo_dir, copy_dir)
        # The harness was authored with REPO_PATH == ctx.repo_dir, so it #includes real source
        # using paths relative to THAT root (e.g. "nng/src/.../scram.c") -- placing it at the
        # copy's own root (the same relative structure, mounted at /src for the compile) is what
        # makes those includes resolve inside the sandboxed container.
        shutil.copy2(harness_path, copy_dir / harness_path.name)
        outcome = _compile_and_run(ctx.config, ctx.run_id, fid, copy_dir, harness_path)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    (evidence_dir / "outcome.json").write_text(json.dumps(outcome, indent=2), encoding="utf-8")
    outcome = dict(outcome)
    outcome["harness_path"] = str((evidence_dir / harness_path.name).relative_to(ctx.run_dir))
    outcome["notes"] = notes[:2000] if notes else None
    detail = f" ({outcome['sanitizer_summary']})" if outcome.get("sanitizer_summary") else ""
    _log(f"{fid}: {outcome['verdict']}{detail}")
    return outcome


def _attach_to_findings(ctx: RunContext, outcomes: dict[str, dict]) -> None:
    vf = ctx.validated_findings_path
    if not vf.is_file():
        return
    try:
        doc = json.loads(vf.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return
    for finding in doc.get("findings", []):
        outcome = outcomes.get(finding.get("id"))
        if outcome is not None:
            finding.setdefault("validation", {})["asan_poc"] = outcome
    atomic_write_json(vf, doc)


def run(ctx: RunContext) -> Path | None:
    cfg = ctx.config
    if not cfg.asan_poc_enabled:
        return None
    vf = ctx.validated_findings_path
    if not vf.is_file():
        _log("no validated_findings.json; skipping")
        return None
    try:
        doc = json.loads(vf.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        _log(f"validated_findings.json unreadable ({exc}); skipping")
        return None
    candidates = [f for f in doc.get("findings", []) if _applies(f)]
    if not candidates:
        _log("no C/C++ memory-safety survivor(s); skipping")
        return None
    if cfg.asan_poc_max_findings is not None:
        candidates = candidates[:cfg.asan_poc_max_findings]
    if not _docker_ok():
        _log(f"Docker unavailable; skipping ({len(candidates)} eligible finding(s) not attempted)")
        return None

    scope = ctx.load_scope()
    outcomes: dict[str, dict] = {}
    for finding in candidates:
        fid = finding.get("id", "?")
        try:
            outcome = _run_one(ctx, scope, finding)
        except Exception as exc:  # noqa: BLE001 -- one finding's failure must never abort the run
            _log(f"{fid}: unexpected failure ({type(exc).__name__}: {exc}); skipping")
            outcome = None
        if outcome is not None:
            outcomes[fid] = outcome

    if not outcomes:
        return None
    _attach_to_findings(ctx, outcomes)
    confirmed = sum(1 for o in outcomes.values() if o.get("verdict") == "confirmed")
    _log(f"{confirmed}/{len(outcomes)} finding(s) got a real sanitizer crash trace")
    return vf
