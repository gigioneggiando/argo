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


def test_mechanical_diff_noop_and_new_file(tmp_path):
    from argo.fixes import _mechanical_diff
    repo = _py_repo(tmp_path)
    # unchanged content -> no diff
    same = (repo / "pkg" / "app.py").read_text(encoding="utf-8")
    assert _mechanical_diff(repo, [{"path": "pkg/app.py", "new_content": same}]) == ""
    # a path with no existing file -> a new-file diff
    d = _mechanical_diff(repo, [{"path": "pkg/new.py", "new_content": "x = 1\n"}])
    assert "new file mode 100644" in d and "+++ b/pkg/new.py" in d and "--- /dev/null" in d
    # malformed entries are ignored, not crashed on
    assert _mechanical_diff(repo, ["nope", {"path": "", "new_content": "y"}, {"path": "z"}]) == ""
    assert _mechanical_diff(repo, [{"path": "../escape.py", "new_content": "bad\n"}]) == ""
    assert _mechanical_diff(repo, [{"path": "C:/escape.py", "new_content": "bad\n"}]) == ""


@needs_patch
def test_mechanical_diff_multi_hunk_applies_and_compiles(tmp_path):
    """The regression this feature fixes: two edits in *separated* regions of one file. A model
    hand-writing the unified diff often miscounts the second `@@` header ('corrupt patch'); the
    full-file rewrite + difflib computes both hunks correctly, so the patch applies and compiles."""
    from argo.fixes import _mechanical_diff
    repo = tmp_path / "repo"
    repo.mkdir()
    original = "".join(f"a{i} = {i}\n" for i in range(20))
    (repo / "m.py").write_text(original, encoding="utf-8")
    # change line 2 and line 18 -> two well-separated hunks in a single file
    lines = original.splitlines(keepends=True)
    lines[1] = "a1 = 111\n"
    lines[17] = "a17 = 999\n"
    new_content = "".join(lines)

    diff = _mechanical_diff(repo, [{"path": "m.py", "new_content": new_content}])
    assert diff.count("@@ -") == 2, "expected two separate hunks"
    res = verify_patch(repo, diff)
    assert res["applied"] and res["compiles"] and res["verified"]
    assert (repo / "m.py").read_text(encoding="utf-8") == original  # original untouched


def test_apply_edits_unique_missing_ambiguous_noop():
    from argo.fixes import _apply_edits
    text = "a\nb\nb\nc\n"
    assert _apply_edits(text, [{"search": "a\n", "replace": "A\n"}]) == "A\nb\nb\nc\n"  # unique
    assert _apply_edits(text, [{"search": "zzz", "replace": "x"}]) is None              # missing
    assert _apply_edits(text, [{"search": "b\n", "replace": "x\n"}]) is None            # ambiguous (2x)
    assert _apply_edits(text, [{"search": "a\n", "replace": "a\n"}]) is None            # no-op
    assert _apply_edits(text, "not-a-list") is None
    assert _apply_edits(text, [{"replace": "x"}]) is None                               # malformed block


@needs_patch
def test_mechanical_diff_from_search_replace_edits(tmp_path):
    """Large-file optimization: the model may return search/replace `edits` instead of the whole
    file; Argo applies them and still computes the diff mechanically (so it applies + compiles)."""
    from argo.fixes import _mechanical_diff
    repo = tmp_path / "repo"
    repo.mkdir()
    original = "def f():\n    return 1  # bug\n\ndef g():\n    return 2\n"
    (repo / "m.py").write_text(original, encoding="utf-8")

    files = [{"path": "m.py",
              "edits": [{"search": "    return 1  # bug\n", "replace": "    return 0  # fixed\n"}]}]
    diff = _mechanical_diff(repo, files)
    assert "-    return 1  # bug" in diff and "+    return 0  # fixed" in diff
    res = verify_patch(repo, diff)
    assert res["applied"] and res["compiles"] and res["verified"]
    assert (repo / "m.py").read_text(encoding="utf-8") == original   # original untouched
    # an entry whose search can't be applied is skipped, not crashed on
    assert _mechanical_diff(repo, [{"path": "m.py", "edits": [{"search": "nope", "replace": "x"}]}]) == ""


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


@needs_patch
def test_generate_fixes_resilient_to_session_failure(env, monkeypatch):
    """One remediation session failing (e.g. a timeout) must NOT abort the whole fix run: that
    finding is recorded un-patched and the others still get patches + a report."""
    from argo.runner import RunnerError
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO))
    real_run = ctx.runner.run

    def flaky(**kw):
        if kw.get("stage") == "remediate" and kw.get("label") == "remediate-AUTHZ-002":
            raise RunnerError("simulated remediation timeout")
        return real_run(**kw)

    monkeypatch.setattr(ctx.runner, "run", flaky)
    report = generate_fixes(ctx, verify=True)                 # must NOT raise
    by = {f["finding_id"]: f for f in report["fixes"]}
    assert by["AUTHZ-002"]["patch"] is None and by["AUTHZ-002"]["verify"]["verified"] is False
    assert by["FULL-001"]["patch"] and by["FULL-003"]["patch"]      # the others still patched
    assert report["patched"] == 2 and (ctx.run_dir / "fixes_report.json").exists()


def test_generate_fixes_requires_validated_findings(env):
    ctx = env()                      # no pipeline run -> no validated_findings.json
    with pytest.raises(FileNotFoundError):
        generate_fixes(ctx, verify=False)


# --------------------------------------------------------------- A3: re-audit the patched copy
def test_still_present_matcher():
    from argo.fixes import _still_present
    files = {"pkg/app.py"}
    assert _still_present([{"cwe": "CWE-89", "affected": ["pkg/app.py:5"]}], "89", files) is True
    assert _still_present([{"cwe": "CWE-79", "affected": ["pkg/app.py:5"]}], "89", files) is False  # other CWE
    assert _still_present([{"cwe": "CWE-89", "affected": ["other.py:5"]}], "89", files) is False     # other file
    assert _still_present([], "89", files) is False                                                  # gone
    # suffix match (re-audit reports a longer path)
    assert _still_present([{"cwe": "CWE-89", "affected": ["src/pkg/app.py:9"]}], "89", {"app.py"}) is True


@needs_patch
def test_verify_patch_on_patched_hook(tmp_path):
    repo = _py_repo(tmp_path)
    patch = _diff("pkg/app.py", ["def f():\n", "    return 1\n"],
                  ["def f():\n", "    return 1\n", "# c\n"])
    seen = {}

    def hook(ws):
        seen["ws"] = ws
        assert (ws / "pkg" / "app.py").is_file()            # the PATCHED copy is available
        return {"re_audit": {"ran": True, "confirmed_fixed": True}}

    res = verify_patch(repo, patch, on_patched=hook)
    assert res["verified"] and res["re_audit"]["confirmed_fixed"] is True and seen["ws"]
    # a raising hook is captured, never crashes verification
    def boom(ws): raise RuntimeError("kaboom")
    res2 = verify_patch(repo, patch, on_patched=boom)
    assert res2["verified"] and res2["re_audit"]["ran"] is False


@needs_patch
def test_generate_fixes_re_audit(env, monkeypatch):
    import argo.fixes as fixes_mod
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO))
    calls = []

    def fake_reaudit(ctx_, ws, finding):
        calls.append(finding["id"])
        gone = finding["id"] == "FULL-001"      # pretend only FULL-001 is fixed
        return {"re_audit": {"ran": True, "confirmed_fixed": gone, "still_present": not gone,
                             "findings": 0}}

    monkeypatch.setattr(fixes_mod, "_reaudit_patched", fake_reaudit)
    report = generate_fixes(ctx, verify=True, re_audit=True)
    assert report["re_audit_enabled"] is True
    assert report["re_audit_ran"] == 3 and report["re_audit_confirmed"] == 1
    assert report["re_audit_confirmed_rate"] == round(1 / 3, 4)
    assert set(calls) == {"FULL-001", "AUTHZ-002", "FULL-003"}
    for f in report["fixes"]:
        assert f["verify"]["re_audit"]["ran"] is True
