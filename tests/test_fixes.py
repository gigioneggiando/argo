"""Phase 6 — remediation + verify tests (zero tokens; the verify engine uses real local tools).

Covers the user's hard requirement: a proposed fix is accepted ONLY if it applies, still compiles,
and introduces no NEW errors — all on an ISOLATED COPY (the target repo is never mutated).
"""

import difflib
import json
import shutil

import pytest

from argo.fixes import generate_fixes
from argo.orchestrator import run_pipeline
from argo.verify import patch_targets, verify_patch

from conftest import BRIEF, REPO

_HAS_PATCH_TOOL = bool(shutil.which("git") or shutil.which("patch"))
needs_patch = pytest.mark.skipif(not _HAS_PATCH_TOOL, reason="needs git or patch to apply diffs")


def _diff(path, old_lines, new_lines):
    return "".join(difflib.unified_diff(old_lines, new_lines,
                                        fromfile=f"a/{path}", tofile=f"b/{path}"))


def _py_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    return repo


def test_patch_targets_parsing():
    diff = "--- a/x/y.py\n+++ b/x/y.py\n@@ -1 +1,2 @@\n a\n+b\n"
    assert patch_targets(diff) == ["x/y.py"]
    # a deletion (+++ /dev/null) is not a write target
    assert patch_targets("--- a/z\n+++ /dev/null\n") == []


@needs_patch
def test_verify_accepts_compiling_fix(tmp_path):
    repo = _py_repo(tmp_path)
    patch = _diff("pkg/app.py", ["def f():\n", "    return 1\n"],
                  ["def f():\n", "    return 1\n", "# safe comment\n"])
    res = verify_patch(repo, patch)
    assert res["applied"] and res["compiles"] and res["verified"]
    assert res["new_errors"] == []
    # the ORIGINAL repo was not touched
    assert (repo / "pkg" / "app.py").read_text(encoding="utf-8") == "def f():\n    return 1\n"


@needs_patch
def test_verify_rejects_fix_that_breaks_compile(tmp_path):
    repo = _py_repo(tmp_path)
    # introduces a syntax error -> py_compile fails -> new error -> not verified
    patch = _diff("pkg/app.py", ["def f():\n", "    return 1\n"],
                  ["def f():\n", "    return 1\n", "def broken(\n"])
    res = verify_patch(repo, patch)
    assert res["applied"] is True
    assert res["verified"] is False
    assert res["new_errors"]            # at least one introduced error


@needs_patch
def test_verify_rejects_unusable_patch(tmp_path):
    repo = _py_repo(tmp_path)
    # context that doesn't match: git apply rejects it; if a lenient `patch` fuzz-applies it, the
    # resulting file no longer compiles — either way the verdict must be "not verified".
    bad = "--- a/pkg/app.py\n+++ b/pkg/app.py\n@@ -1,2 +1,3 @@\n NONEXISTENT CONTEXT\n MORE BOGUS\n+x\n"
    res = verify_patch(repo, bad)
    assert res["verified"] is False


@needs_patch
def test_verify_ignores_preexisting_errors(tmp_path):
    # a repo that already does NOT compile; a patch to an unrelated, valid file must still pass
    repo = tmp_path / "repo"
    (repo).mkdir()
    (repo / "broken.py").write_text("def oops(\n", encoding="utf-8")     # pre-existing breakage
    (repo / "ok.py").write_text("x = 1\n", encoding="utf-8")
    patch = _diff("ok.py", ["x = 1\n"], ["x = 1\n", "y = 2\n"])
    res = verify_patch(repo, patch)
    assert res["verified"] is True       # the pre-existing error is not attributed to this patch


@needs_patch
def test_generate_fixes_end_to_end(env):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO))
    report = generate_fixes(ctx, verify=True)

    survivors = {"FULL-001", "AUTHZ-002", "FULL-003"}
    assert {f["finding_id"] for f in report["fixes"]} == survivors
    assert report["patched"] == len(survivors)
    # every proposed patch verified (mock appends a harmless comment -> still compiles)
    assert report["verified"] == len(survivors)
    for f in report["fixes"]:
        assert (ctx.run_dir / "patches" / f["patch"]).exists()
        assert f["verify"]["applied"] and f["verify"]["verified"]
    # report persisted, and the target repo copy was never modified by verification
    assert (ctx.run_dir / "fixes_report.json").exists()


def test_generate_fixes_requires_validated_findings(env):
    ctx = env()                      # no pipeline run -> no validated_findings.json
    with pytest.raises(FileNotFoundError):
        generate_fixes(ctx, verify=False)
