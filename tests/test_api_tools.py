"""Shared, hardened model-facing toolbox for API-native runners (argo/api_tools.py).

The toolbox is the whole security boundary of an API runner: the model only proposes calls and
Argo executes them here. These tests pin the path policy, bounded IO, bounded regex matching,
argument validation and write atomicity. Canary files are checked by content hash, not only by
return codes. No network, no model."""

import hashlib
import os
import re
import threading
import time
import tracemalloc

import pytest

import argo.mistral_api as mistral_api
from argo import api_tools
from argo.api_tools import Toolbox, ToolError


@pytest.fixture
def dirs(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("import os\nSECRET = os.environ['X']\nprint(1)\n",
                                         encoding="utf-8")
    (repo / "README.md").write_text("hello\nHello again\n", encoding="utf-8")
    work = tmp_path / "work" / "audit"
    work.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("do not read", encoding="utf-8")
    return repo, work, outside


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _link_or_skip(src, dst):
    try:
        os.link(src, dst)
    except (OSError, NotImplementedError):
        pytest.skip("hard links not permitted on this filesystem")


def _symlink_or_skip(src, dst, *, directory=False):
    try:
        os.symlink(src, dst, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this platform/user")


def _remove_link(path):
    try:
        os.unlink(path)
    except (IsADirectoryError, PermissionError):
        os.rmdir(path)                       # Windows directory symlink


# ------------------------------------------------------------------------------ extraction
def test_mistral_reuses_the_shared_toolbox():
    assert mistral_api.Toolbox is Toolbox
    assert mistral_api.ToolError is ToolError


def test_schema_surface_is_unchanged(dirs):
    repo, work, _ = dirs
    names = [t["function"]["name"] for t in Toolbox(repo, work, allow_write=True).schemas()]
    assert names == ["read_file", "list_dir", "glob", "grep", "write_file"]
    names = [t["function"]["name"] for t in Toolbox(repo, work, allow_write=False).schemas()]
    assert names == ["read_file", "list_dir", "glob", "grep"]


# ------------------------------------------------------------------------------ write hardening
def test_preexisting_hardlink_at_the_old_predictable_temp_name_is_not_followed(dirs):
    repo, work, outside = dirs
    before = _sha(outside)
    _link_or_skip(outside, work / "artifact.txt.argo-tmp")
    Toolbox(repo, work, allow_write=True).write_file("artifact.txt", "CHANGED")
    assert _sha(outside) == before
    assert (work / "artifact.txt").read_text(encoding="utf-8") == "CHANGED"


def test_hardlinked_final_target_is_replaced_not_written_through(dirs):
    repo, work, outside = dirs
    before = _sha(outside)
    _link_or_skip(outside, work / "report.md")
    Toolbox(repo, work, allow_write=True).write_file("report.md", "NEW")
    assert _sha(outside) == before
    assert (work / "report.md").read_text(encoding="utf-8") == "NEW"


def test_regular_artifact_can_be_rewritten_atomically(dirs):
    repo, work, _ = dirs
    tb = Toolbox(repo, work, allow_write=True)
    tb.write_file("out.json", '{"a": 1}')
    tb.write_file("out.json", '{"a": 2}')
    assert (work / "out.json").read_text(encoding="utf-8") == '{"a": 2}'
    assert sorted(p.name for p in work.iterdir()) == ["out.json"]       # no temp left behind


def test_failed_commit_is_a_tool_error_and_removes_only_its_own_temp(dirs, monkeypatch):
    repo, work, _ = dirs
    unrelated = work / ".keep.argo-tmp"
    unrelated.write_text("someone else's file", encoding="utf-8")

    def boom(*_a, **_k):
        raise PermissionError("synthetic: target locked")

    monkeypatch.setattr(api_tools.os, "replace", boom)
    with pytest.raises(ToolError, match="not written"):
        Toolbox(repo, work, allow_write=True).write_file("a.txt", "x")
    assert sorted(p.name for p in work.iterdir()) == [".keep.argo-tmp"]
    assert unrelated.read_text(encoding="utf-8") == "someone else's file"


def test_write_into_symlinked_parent_dir_is_denied(dirs, tmp_path):
    repo, work, _ = dirs
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _symlink_or_skip(elsewhere, work / "sub", directory=True)
    with pytest.raises(ToolError, match="denied"):
        Toolbox(repo, work, allow_write=True).write_file("sub/x.txt", "x")
    assert list(elsewhere.iterdir()) == []


def test_parent_swapped_after_validation_is_detected_and_cleaned(dirs, tmp_path, monkeypatch):
    """Race inside the threat model: the parent is replaced by a link between path validation
    and temp creation. The write must fail closed and leave nothing outside the scratch."""
    repo, work, _ = dirs
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (work / "sub").mkdir()
    probe = tmp_path / "probe-link"
    _symlink_or_skip(elsewhere, probe, directory=True)        # capability check only
    _remove_link(probe)
    real_mkstemp = api_tools.tempfile.mkstemp

    def swapping_mkstemp(*a, **k):
        os.rmdir(work / "sub")
        os.symlink(elsewhere, work / "sub", target_is_directory=True)
        return real_mkstemp(*a, **k)

    monkeypatch.setattr(api_tools.tempfile, "mkstemp", swapping_mkstemp)
    with pytest.raises(ToolError, match="denied|changed"):
        Toolbox(repo, work, allow_write=True).write_file("sub/x.txt", "x")
    assert list(elsewhere.iterdir()) == []


def test_existing_directory_target_is_refused(dirs):
    repo, work, _ = dirs
    (work / "d").mkdir()
    with pytest.raises(ToolError, match="not a regular file"):
        Toolbox(repo, work, allow_write=True).write_file("d", "x")
    assert (work / "d").is_dir()


def test_write_into_scratch_dot_git_is_denied(dirs):
    repo, work, _ = dirs
    with pytest.raises(ToolError, match="denied"):
        Toolbox(repo, work, allow_write=True).write_file(".git/config", "x")
    assert not (work / ".git").exists()


def test_no_write_after_the_deadline_or_cancel(dirs):
    repo, work, _ = dirs
    late = Toolbox(repo, work, allow_write=True, deadline=time.monotonic() - 1)
    with pytest.raises(ToolError, match="deadline"):
        late.write_file("a.txt", "x")
    ev = threading.Event()
    ev.set()
    with pytest.raises(ToolError, match="cancel"):
        Toolbox(repo, work, allow_write=True, cancel_event=ev).write_file("b.txt", "x")
    assert list(work.iterdir()) == []


# ------------------------------------------------------------------------------ path policy
@pytest.mark.skipif(os.name != "nt", reason="Windows path namespaces")
@pytest.mark.parametrize("bad", [r"\\server\share\x.txt", "//server/share/x.txt",
                                 r"\\?\C:\x.txt", r"\\.\PhysicalDrive0", "CON", "out/NUL.txt",
                                 "com1.log", "README.md:hidden", r"src\app.py::$DATA"])
def test_windows_unc_device_reserved_and_ads_paths_are_denied(dirs, bad):
    repo, work, _ = dirs
    tb = Toolbox(repo, work, allow_write=True)
    with pytest.raises(ToolError, match="denied"):
        tb.read_file(bad)
    with pytest.raises(ToolError, match="denied"):
        tb.write_file(bad, "x")


def test_absolute_paths_inside_the_roots_still_work(dirs):
    repo, work, _ = dirs
    tb = Toolbox(repo, work, allow_write=True)
    assert "SECRET" in tb.read_file(str(repo / "src" / "app.py"))
    assert "wrote" in tb.write_file(str(work / "abs.txt"), "ok")


def test_symlinked_file_inside_repo_pointing_out_is_not_read(dirs):
    repo, work, outside = dirs
    _symlink_or_skip(outside, repo / "evil.txt")
    tb = Toolbox(repo, work, allow_write=False)
    with pytest.raises(ToolError, match="denied"):
        tb.read_file("evil.txt")
    assert "do not read" not in tb.grep("do not read")


# ------------------------------------------------------------------------------ bounded reads
def test_huge_single_line_is_read_with_bounded_memory(dirs):
    repo, work, _ = dirs
    (repo / "min.js").write_bytes(b"x" * (20 * 1024 * 1024))          # 20 MiB, no newline
    tb = Toolbox(repo, work, allow_write=False)
    tracemalloc.start()
    try:
        out = tb.read_file("min.js")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert "line truncated" in out
    assert len(out) < 300_000
    assert peak < 8 * 1024 * 1024


def test_offset_past_the_scan_budget_is_reported_explicitly(dirs, monkeypatch):
    repo, work, _ = dirs
    monkeypatch.setattr(api_tools, "MAX_READ_SCAN_BYTES", 64 * 1024)
    (repo / "long.txt").write_text("line\n" * 100_000, encoding="utf-8")
    out = Toolbox(repo, work, allow_write=False).read_file("long.txt", offset=90_000)
    assert "scan limit" in out
    assert "90000" not in out.split("scan limit")[0]                     # no fabricated line


def test_read_output_format_is_preserved(dirs):
    repo, work, _ = dirs
    assert Toolbox(repo, work, False).read_file("README.md") == "     1\thello\n     2\tHello again"
    assert Toolbox(repo, work, False).read_file("README.md", offset=2) == "     2\tHello again"


def test_read_paging_message_points_at_the_next_offset(dirs):
    repo, work, _ = dirs
    (repo / "many.txt").write_text("".join(f"{i}\n" for i in range(1, 11)), encoding="utf-8")
    out = Toolbox(repo, work, False).read_file("many.txt", limit=3)
    assert out.splitlines()[-1] == "... [truncated at line 3; use offset=4 to continue]"


# ------------------------------------------------------------------------------ bounded regex
def test_pathological_regex_is_stopped_as_a_tool_error(dirs):
    repo, work, _ = dirs
    (repo / "a.txt").write_text(("a" * 36 + "!\n") * 20, encoding="utf-8")   # fails late
    tb = Toolbox(repo, work, allow_write=False)
    started = time.monotonic()
    with pytest.raises(ToolError, match="time limit"):
        tb.grep(r"(a|aa)+$", path="a.txt")
    assert time.monotonic() - started < 5


def test_grep_is_bounded_by_the_remaining_session_time(dirs):
    repo, work, _ = dirs
    for i in range(40):
        (repo / f"f{i}.txt").write_text("a" * 34 + "!\n", encoding="utf-8")
    tb = Toolbox(repo, work, allow_write=False, deadline=time.monotonic() + 0.3)
    started = time.monotonic()
    with pytest.raises(ToolError, match="time limit|deadline"):
        tb.grep(r"(a|aa)+$")
    assert time.monotonic() - started < 3


@pytest.mark.parametrize("bad", ["a" * 2049, "a{1000000}", "(?:ab){2,50000}", "x{5000,}"])
def test_oversized_patterns_are_refused_before_compiling(dirs, bad):
    repo, work, _ = dirs
    with pytest.raises(ToolError, match="pattern"):
        Toolbox(repo, work, allow_write=False).grep(bad)


@pytest.mark.parametrize("pattern,ignore_case", [
    (r"SECRET", False), (r"os\.environ\[", False), (r"^print", False), (r"hello", True),
    (r"\bimport\s+\w+", False), (r"[A-Z]{3,}", False), (r"a{2}", False)])
def test_ordinary_patterns_match_like_the_stdlib(dirs, pattern, ignore_case):
    repo, work, _ = dirs
    flags = re.IGNORECASE if ignore_case else 0
    expected = sum(1 for f in sorted(repo.rglob("*")) if f.is_file()
                   for line in f.read_text(encoding="utf-8").splitlines()
                   if re.search(pattern, line, flags))
    out = Toolbox(repo, work, allow_write=False).grep(pattern, ignore_case=ignore_case)
    got = 0 if out == "(no matches)" else len(out.splitlines())
    assert got == expected


def test_invalid_regex_is_still_a_tool_error(dirs):
    repo, work, _ = dirs
    with pytest.raises(ToolError, match="invalid regex"):
        Toolbox(repo, work, allow_write=False).grep("(")


def test_walk_cap_is_reported_without_an_invented_total(dirs, monkeypatch):
    repo, work, _ = dirs
    for i in range(10):
        (repo / f"z{i}.txt").write_text("needle\n", encoding="utf-8")
    monkeypatch.setattr(api_tools, "MAX_GREP_FILES", 3)
    tb = Toolbox(repo, work, allow_write=False)
    assert "omitted" in tb.grep("nothing-matches-this")
    assert "omitted" in tb.glob("*.none")


# ------------------------------------------------------------------------------ dispatch
@pytest.mark.parametrize("args", [
    {"path": "README.md", "offset": "abc"},
    {"path": "README.md", "offset": True},
    {"path": 5},
    {"path": "README.md", "shell": "id"},
    {},
])
def test_invalid_arguments_are_denied_without_effect(dirs, args):
    repo, work, _ = dirs
    with pytest.raises(ToolError):
        Toolbox(repo, work, allow_write=True).dispatch("read_file", args)


def test_bad_write_arguments_create_nothing(dirs):
    repo, work, _ = dirs
    tb = Toolbox(repo, work, allow_write=True)
    for args in ({"path": "a.txt", "content": 5}, {"path": "a.txt"},
                 {"path": "a.txt", "content": "x", "mode": "a"}):
        with pytest.raises(ToolError):
            tb.dispatch("write_file", args)
    assert list(work.iterdir()) == []


def test_exec_and_network_tools_do_not_exist(dirs):
    repo, work, _ = dirs
    tb = Toolbox(repo, work, allow_write=True)
    for name in ("bash", "shell", "exec", "git", "web_fetch", "web_search", "subagent"):
        with pytest.raises(ToolError, match="unknown tool"):
            tb.dispatch(name, {})
    assert list(work.iterdir()) == []


@pytest.mark.skipif(os.name != "nt", reason="NTFS junctions")
def test_junction_inside_repo_pointing_outside_is_not_walked_or_read(dirs, tmp_path):
    """Junctions need no privilege on Windows and os.walk(followlinks=False) still descends into
    them; grep/glob must not reach files outside the roots through one."""
    import subprocess
    repo, work, _ = dirs
    secret_dir = tmp_path / "secret-dir"
    secret_dir.mkdir()
    (secret_dir / "token.txt").write_text("JUNCTION-CANARY\n", encoding="utf-8")
    made = subprocess.run(["cmd", "/c", "mklink", "/J", str(repo / "jx"), str(secret_dir)],
                          capture_output=True, text=True)
    if made.returncode != 0:
        pytest.skip("cannot create a junction here")
    tb = Toolbox(repo, work, allow_write=True)
    assert "JUNCTION-CANARY" not in tb.grep("JUNCTION-CANARY")
    assert "token.txt" not in tb.glob("**/*.txt")
    with pytest.raises(ToolError, match="denied"):
        tb.read_file("jx/token.txt")
    with pytest.raises(ToolError, match="denied"):
        tb.write_file("../../repo/jx/new.txt", "x")
    assert sorted(p.name for p in secret_dir.iterdir()) == ["token.txt"]
