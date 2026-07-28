"""Stage - Freshness check (opt-in; best-effort; runs late before report).

For each surviving finding, look for commits touching the same cited files on:
  * the audited branch after the pinned audit commit, and
  * version-looking sibling release/maintenance branches within a lookback window.

This stage is deliberately informational. A same-file commit is not proof of a fix, so the stage
never changes verdicts/classification/status and never drops findings. It only attaches a
``freshness_flag`` list to findings that a human should verify before sending the report.
"""

from __future__ import annotations

import json
import re
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence

from ..context import RunContext
from ..models import Finding, FreshnessCommit, FreshnessFlag
from ..ranking import split_ref

_BRANCH_RE = re.compile(
    r"(\d+\.\d+|(?:^|/)(?:stable|lts)(?:$|[/-])|(?:^|/)(?:release|maintenance)(?:$|[/-]))",
    re.IGNORECASE,
)
_DOC_BRANCH_RE = re.compile(
    r"(?<![\w./-])(?:v?\d+\.\d+(?:\.\d+)?|(?:release|maintenance|stable|lts)/[\w./-]+|"
    r"stable|lts|main|master)(?![\w./-])",
    re.IGNORECASE,
)
_BRANCH_DOCS = (
    "SECURITY.md",
    "SECURITY",
    "CONTRIBUTING.md",
    "CONTRIBUTING",
    ".github/SECURITY.md",
    ".github/CONTRIBUTING.md",
)
_GIT_TIMEOUT_S = 60
_LOG_FORMAT = "%H%x1f%aI%x1f%s"


def _log(msg: str) -> None:
    print(f"[freshness] {msg}", file=sys.stderr)


def _run_git(repo_dir: Path, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Small subprocess seam for tests. Callers handle every failure best-effort."""
    return subprocess.run(
        ["git", "-c", f"safe.directory={repo_dir.resolve()}", "-C", str(repo_dir), *args],
        capture_output=True,
        text=True,
        timeout=_GIT_TIMEOUT_S,
    )


def _short_err(cp: subprocess.CompletedProcess[str]) -> str:
    msg = (cp.stderr or cp.stdout or "").strip().replace("\n", " ")
    return msg[:240] if msg else f"exit {cp.returncode}"


def _git(repo_dir: Path, args: Sequence[str], desc: str, *, quiet_failure: bool = False
         ) -> subprocess.CompletedProcess[str] | None:
    try:
        cp = _run_git(repo_dir, args)
    except FileNotFoundError as exc:
        if not quiet_failure:
            _log(f"{desc}: git unavailable ({exc})")
        return None
    except (OSError, subprocess.SubprocessError) as exc:
        if not quiet_failure:
            _log(f"{desc}: git failed ({exc})")
        return None
    if cp.returncode != 0:
        if not quiet_failure:
            _log(f"{desc}: git failed ({_short_err(cp)})")
        return None
    return cp


def _make_git_metadata_writable(repo_dir: Path) -> None:
    """The acquired repo copy is defense-in-depth read-only; fetch needs writable git metadata."""
    git_dir = repo_dir / ".git"
    if not git_dir.exists():
        return
    for p in git_dir.rglob("*"):
        if not p.is_file():
            continue
        try:
            p.chmod(p.stat().st_mode | stat.S_IWRITE)
        except OSError:
            pass


def _normalize_path(path: str) -> str:
    path = path.strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def _paths_by_finding(findings: list[Finding]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for f in findings:
        paths: set[str] = set()
        for ref in f.affected:
            file_path, _line = split_ref(ref)
            file_path = _normalize_path(file_path)
            if file_path:
                paths.add(file_path)
        out[f.id] = sorted(paths)
    return out


def _is_candidate_branch(branch: str) -> bool:
    return bool(_BRANCH_RE.search(branch))


def _documented_branch_hints(repo_dir: Path) -> set[str]:
    hints: set[str] = set()
    for rel in _BRANCH_DOCS:
        p = repo_dir / rel
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in _DOC_BRANCH_RE.finditer(text[:200_000]):
            hints.add(match.group(0).strip("`'\".,;:()[]{}"))
    return {h for h in hints if h}


def _discover_candidate_branches(repo_dir: Path) -> list[str] | None:
    cp = _git(repo_dir, ["ls-remote", "--heads", "origin"], "discover remote branches")
    if cp is None:
        return None
    documented = {h.lower() for h in _documented_branch_hints(repo_dir)}
    branches: set[str] = set()
    prefix = "refs/heads/"
    for line in cp.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2 or not parts[1].startswith(prefix):
            continue
        branch = parts[1][len(prefix):]
        if _is_candidate_branch(branch) or branch.lower() in documented:
            branches.add(branch)
    return sorted(branches)


def _remote_head_branch(repo_dir: Path) -> str | None:
    cp = _git(repo_dir, ["ls-remote", "--symref", "origin", "HEAD"], "resolve origin HEAD",
              quiet_failure=True)
    if cp is None:
        return None
    prefix = "ref: refs/heads/"
    for line in cp.stdout.splitlines():
        if line.startswith(prefix) and line.rstrip().endswith("\tHEAD"):
            return line[len(prefix):].split("\t", 1)[0].strip() or None
    return None


_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)


def _audited_branch(repo_dir: Path, requested_ref: str | None = None) -> str | None:
    # A pinned-commit checkout (the common case for reproducible audits) leaves HEAD detached, so
    # `symbolic-ref`/the remote's default branch cannot recover the TRUE audited branch when that
    # branch isn't the remote's default (e.g. auditing `dev` on a repo whose default is `master`).
    # If the original --commit was a non-sha ref (a branch/tag name, not a resolved sha), trust it
    # directly instead of guessing.
    if requested_ref and not _SHA_RE.match(requested_ref.strip()):
        return requested_ref.strip()
    cp = _git(repo_dir, ["symbolic-ref", "--quiet", "--short", "HEAD"], "resolve current branch",
              quiet_failure=True)
    branch = (cp.stdout.strip() if cp is not None else "") if cp else ""
    if branch and branch != "HEAD":
        return branch
    return _remote_head_branch(repo_dir)


def _checked_at(ctx: RunContext) -> str:
    return ctx.timestamp()


def _since_arg(checked_at: str, days: int) -> str:
    days = max(1, int(days or 1))
    try:
        raw = checked_at.replace("Z", "+00:00")
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (dt - timedelta(days=days)).isoformat()
    except ValueError:
        return f"{days} days ago"


def _fetch_branch(repo_dir: Path, branch: str) -> bool:
    cp = _git(repo_dir, ["fetch", "--depth", "50", "origin", branch], f"fetch {branch}")
    return cp is not None


def _parse_commits(stdout: str) -> list[FreshnessCommit]:
    commits: list[FreshnessCommit] = []
    for line in stdout.splitlines():
        sha, sep, rest = line.partition("\x1f")
        if not sep:
            continue
        author_date, sep, subject = rest.partition("\x1f")
        if not sep:
            continue
        commits.append(FreshnessCommit(
            sha=sha.strip(),
            author_date=author_date.strip(),
            subject=subject.strip(),
        ))
    return commits


def _log_for_path(repo_dir: Path, rev: str, path: str, since: str, *,
                  after_commit: str | None = None) -> list[FreshnessCommit] | None:
    target = f"{after_commit}..{rev}" if after_commit else rev
    cp = _git(repo_dir, ["log", target, f"--since={since}", f"--format={_LOG_FORMAT}", "--", path],
              f"log {target} -- {path}")
    if cp is None:
        return None
    return _parse_commits(cp.stdout)


def _collect_flags(ctx: RunContext, paths: list[str], checked_at: str
                   ) -> dict[str, list[FreshnessFlag]]:
    repo_dir = ctx.repo_dir
    if not (repo_dir / ".git").exists():
        _log("repo is not a git checkout; skipping")
        return {}

    _make_git_metadata_writable(repo_dir)

    branches = _discover_candidate_branches(repo_dir)
    if branches is None:
        return {}

    try:
        meta = json.loads(ctx.meta_path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        meta = {}
    repo_commit = (meta.get("repo_commit") or "").strip()
    requested_ref = meta.get("requested_ref")
    audited_branch = _audited_branch(repo_dir, requested_ref)
    since = _since_arg(checked_at, ctx.config.freshness_lookback_days)
    flags_by_path: dict[str, list[FreshnessFlag]] = {p: [] for p in paths}
    checked_branches = 0

    if repo_commit and audited_branch:
        if _fetch_branch(repo_dir, audited_branch):
            checked_branches += 1
            for path in paths:
                commits = _log_for_path(repo_dir, "FETCH_HEAD", path, since,
                                        after_commit=repo_commit)
                if commits:
                    flags_by_path[path].append(FreshnessFlag(
                        branch=audited_branch,
                        relation="audited_branch",
                        file_path=path,
                        commits=commits,
                        checked_at=checked_at,
                    ))
    elif not repo_commit:
        _log("meta.json has no repo_commit; audited-branch post-pin check skipped")

    for branch in branches:
        if audited_branch and branch == audited_branch:
            continue
        if not _fetch_branch(repo_dir, branch):
            continue
        checked_branches += 1
        for path in paths:
            commits = _log_for_path(repo_dir, "FETCH_HEAD", path, since)
            if commits:
                flags_by_path[path].append(FreshnessFlag(
                    branch=branch,
                    relation="sibling_branch",
                    file_path=path,
                    commits=commits,
                    checked_at=checked_at,
                ))

    flagged = sum(len(v) for v in flags_by_path.values())
    _log(f"checked {checked_branches} branch(es), {len(paths)} unique path(s); "
         f"{flagged} same-file freshness flag(s)")
    return {path: flags for path, flags in flags_by_path.items() if flags}


def run(ctx: RunContext) -> Path:
    if not ctx.validated_findings_path.is_file():
        _log("validated_findings.json not found; skipping")
        return ctx.validated_findings_path

    try:
        doc = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8-sig"))
        survivors = [Finding.model_validate(f) for f in doc.get("findings", [])]
    except (OSError, ValueError) as exc:
        _log(f"could not read validated findings; skipping ({exc})")
        return ctx.validated_findings_path

    if not survivors:
        _log("no surviving findings to freshness-check")
        return ctx.validated_findings_path

    paths_by_finding = _paths_by_finding(survivors)
    unique_paths = sorted({p for paths in paths_by_finding.values() for p in paths})
    if not unique_paths:
        _log("no cited file paths to freshness-check")
        return ctx.validated_findings_path

    checked_at = _checked_at(ctx)
    flags_by_path = _collect_flags(ctx, unique_paths, checked_at)
    if not flags_by_path:
        return ctx.validated_findings_path

    flagged_findings = 0
    for f in survivors:
        flags: list[FreshnessFlag] = []
        for path in paths_by_finding.get(f.id, []):
            flags.extend(flags_by_path.get(path, []))
        if flags:
            f.freshness_flag = flags
            flagged_findings += 1

    if flagged_findings == 0:
        return ctx.validated_findings_path

    doc["findings"] = [f.model_dump(exclude_none=True) for f in survivors]
    ctx.validated_findings_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    _log(f"flagged {flagged_findings} finding(s); verdicts unchanged")
    return ctx.validated_findings_path
