import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from argo.config import PipelineConfig
from argo.orchestrator import build_context
from argo.stages import freshness, report

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")

NOW = "2026-07-28T12:00:00+00:00"


def _git(repo: Path, *args: str, env: dict | None = None) -> str:
    cp = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    return cp.stdout.strip()


def _init_origin(path: Path) -> Path:
    path.mkdir(parents=True)
    subprocess.run(["git", "init", str(path)], check=True, capture_output=True, text=True)
    _git(path, "checkout", "-b", "main")
    _git(path, "config", "user.name", "Argo Test")
    _git(path, "config", "user.email", "argo@example.invalid")
    return path


def _commit_env(date: str) -> dict:
    env = os.environ.copy()
    env.update({
        "GIT_AUTHOR_NAME": "Argo Test",
        "GIT_AUTHOR_EMAIL": "argo@example.invalid",
        "GIT_COMMITTER_NAME": "Argo Test",
        "GIT_COMMITTER_EMAIL": "argo@example.invalid",
        "GIT_AUTHOR_DATE": date,
        "GIT_COMMITTER_DATE": date,
    })
    return env


def _write(repo: Path, rel: str, text: str) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _commit(repo: Path, message: str, date: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message, env=_commit_env(date))
    return _git(repo, "rev-parse", "HEAD")


def _ctx(tmp_path: Path, origin: Path, pin: str, *, run_id: str = "FRESH-RUN"):
    cfg = PipelineConfig(
        runner="mock",
        runs_dir=tmp_path / "runs",
        ledger_path=tmp_path / "ledger.sqlite",
        freshness_lookback_days=365,
        attribution=False,
    )
    ctx = build_context(cfg, run_id, now=NOW)
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    ctx.repo_dir.mkdir(parents=True)
    _git(ctx.repo_dir, "init")
    _git(ctx.repo_dir, "remote", "add", "origin", origin.as_posix())
    _git(ctx.repo_dir, "fetch", "--depth", "1", "origin", pin)
    _git(ctx.repo_dir, "checkout", "--quiet", "FETCH_HEAD")
    ctx.meta_path.write_text(json.dumps({
        "run_id": ctx.run_id,
        "repo_source": origin.as_posix(),
        "repo_is_url": False,
        "repo_commit": pin,
    }), encoding="utf-8")
    return ctx


def _finding(fid: str = "FRESH-001", affected: list[str] | None = None) -> dict:
    return {
        "id": fid,
        "title": "Same-file vulnerability",
        "severity": "High",
        "confidence": "High",
        "cwe": "CWE-20",
        "affected": affected or ["src/vuln.c:1"],
        "vulnerable_flow": "input reaches sink",
        "why_vulnerable": "missing validation",
        "exploit_scenario": "send crafted input",
        "impact": "security impact",
        "recommended_fix": "validate input",
        "validation": {"verdict": "confirmed"},
    }


def _write_validated(ctx, findings: list[dict]) -> None:
    ctx.validated_findings_path.write_text(json.dumps({
        "program_name": "Freshness Program",
        "audit_focus": "validated",
        "generated_at": NOW,
        "findings": findings,
        "dropped": [],
    }, indent=2), encoding="utf-8")


def _validated(ctx) -> dict:
    return json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))


def test_sibling_branch_same_file_commit_gets_flagged(tmp_path):
    origin = _init_origin(tmp_path / "origin")
    _write(origin, "src/vuln.c", "int cap = 0;\n")
    pin = _commit(origin, "initial vulnerable file", "2026-07-01T10:00:00+00:00")
    _git(origin, "checkout", "-b", "release/1.4")
    _write(origin, "src/vuln.c", "int cap = 32;\n")
    _commit(origin, "fix publish request cap", "2026-07-10T10:00:00+00:00")
    _git(origin, "checkout", "main")

    ctx = _ctx(tmp_path, origin, pin)
    _write_validated(ctx, [_finding()])

    freshness.run(ctx)

    finding = _validated(ctx)["findings"][0]
    flags = finding["freshness_flag"]
    assert finding["validation"]["verdict"] == "confirmed"
    assert any(f["branch"] == "release/1.4" and f["relation"] == "sibling_branch"
               for f in flags)
    release_flag = next(f for f in flags if f["branch"] == "release/1.4")
    assert release_flag["file_path"] == "src/vuln.c"
    assert "fix publish request cap" in release_flag["commits"][0]["subject"]


def test_audited_branch_post_pin_commit_gets_flagged(tmp_path):
    origin = _init_origin(tmp_path / "origin")
    _write(origin, "src/vuln.c", "int cap = 0;\n")
    pin = _commit(origin, "initial vulnerable file", "2026-07-01T10:00:00+00:00")
    _write(origin, "src/vuln.c", "int cap = 32;\n")
    _commit(origin, "fix cap on main", "2026-07-11T10:00:00+00:00")

    ctx = _ctx(tmp_path, origin, pin)
    _write_validated(ctx, [_finding()])

    freshness.run(ctx)

    flags = _validated(ctx)["findings"][0]["freshness_flag"]
    main_flag = next(f for f in flags if f["branch"] == "main")
    assert main_flag["relation"] == "audited_branch"
    assert "fix cap on main" in main_flag["commits"][0]["subject"]


def test_audited_branch_uses_requested_ref_on_detached_head(tmp_path):
    # Pin the audit on a NON-default branch ("dev") while the remote's default branch is "main".
    # `_ctx` always checks out FETCH_HEAD directly, leaving the local repo on a detached HEAD (the
    # realistic case for any reproducible --commit-pinned audit) -- so without `requested_ref`,
    # `_audited_branch` would fall back to the remote's default branch ("main") and MISS a post-pin
    # commit made on "dev", the branch actually audited.
    origin = _init_origin(tmp_path / "origin")
    _write(origin, "README.md", "unrelated\n")
    _commit(origin, "chore: init", "2026-06-01T10:00:00+00:00")  # gives "main" a real first commit
    _git(origin, "checkout", "-b", "dev")
    _write(origin, "src/vuln.c", "int cap = 0;\n")
    pin = _commit(origin, "initial vulnerable file on dev", "2026-07-01T10:00:00+00:00")
    _write(origin, "src/vuln.c", "int cap = 32;\n")
    _commit(origin, "fix cap on dev", "2026-07-11T10:00:00+00:00")
    _git(origin, "checkout", "main")  # remote default stays "main", never touches src/vuln.c

    ctx = _ctx(tmp_path, origin, pin)
    meta = json.loads(ctx.meta_path.read_text(encoding="utf-8"))
    meta["requested_ref"] = "dev"
    ctx.meta_path.write_text(json.dumps(meta), encoding="utf-8")
    _write_validated(ctx, [_finding()])

    freshness.run(ctx)

    flags = _validated(ctx)["findings"][0]["freshness_flag"]
    dev_flag = next(f for f in flags if f["branch"] == "dev")
    assert dev_flag["relation"] == "audited_branch"
    assert "fix cap on dev" in dev_flag["commits"][0]["subject"]
    assert not any(f["branch"] == "main" and f["relation"] == "audited_branch" for f in flags)


def test_no_matching_commits_leaves_finding_unchanged(tmp_path):
    origin = _init_origin(tmp_path / "origin")
    _write(origin, "src/vuln.c", "int cap = 0;\n")
    _write(origin, "src/other.c", "int other = 0;\n")
    pin = _commit(origin, "initial files", "2025-01-01T10:00:00+00:00")
    _write(origin, "src/other.c", "int other = 1;\n")
    _commit(origin, "touch unrelated file on main", "2026-07-11T10:00:00+00:00")
    _git(origin, "checkout", "-b", "maintenance/1.4")
    _write(origin, "src/other.c", "int other = 2;\n")
    _commit(origin, "touch unrelated file on maintenance", "2026-07-12T10:00:00+00:00")
    _git(origin, "checkout", "main")

    ctx = _ctx(tmp_path, origin, pin)
    _write_validated(ctx, [_finding()])
    before = ctx.validated_findings_path.read_text(encoding="utf-8")

    freshness.run(ctx)

    assert ctx.validated_findings_path.read_text(encoding="utf-8") == before


def test_git_failure_does_not_crash_or_modify_findings(tmp_path, monkeypatch):
    origin = _init_origin(tmp_path / "origin")
    _write(origin, "src/vuln.c", "int cap = 0;\n")
    pin = _commit(origin, "initial vulnerable file", "2026-07-01T10:00:00+00:00")
    ctx = _ctx(tmp_path, origin, pin)
    _write_validated(ctx, [_finding()])
    before = ctx.validated_findings_path.read_text(encoding="utf-8")

    def _boom(_repo_dir, _args):
        raise FileNotFoundError("git")

    monkeypatch.setattr(freshness, "_run_git", _boom)
    freshness.run(ctx)

    assert ctx.validated_findings_path.read_text(encoding="utf-8") == before


def test_report_renders_freshness_appendix(env):
    ctx = env()
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    ctx.scope_path.write_text(json.dumps({
        "program_name": "Freshness Program",
        "platform": "local",
        "target_type": "source_only",
        "in_scope": [{"asset": "repo", "type": "source_repo"}],
        "out_of_scope": [],
        "prohibited_techniques": ["No live testing"],
        "automation_allowed": True,
    }), encoding="utf-8")
    finding = _finding()
    finding["freshness_flag"] = [{
        "branch": "release/1.4",
        "relation": "sibling_branch",
        "file_path": "src/vuln.c",
        "checked_at": NOW,
        "commits": [{
            "sha": "abcdef1234567890",
            "author_date": "2026-07-10T10:00:00+00:00",
            "subject": "fix publish request cap",
        }],
    }]
    _write_validated(ctx, [finding])

    path = report.run(ctx)
    text = path.read_text(encoding="utf-8")

    assert "Freshness check - verify before sending" in text
    assert "release/1.4" in text
    assert "not proof of a fix" in text
