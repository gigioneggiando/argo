"""Citation grounding distinguishes a MISSING explicit file (hallucinated location -> drop) from an
UNRESOLVED citation (symbol-style or ambiguous -> keep, confidence -1, honest note).

Before this, any citation that was not a resolvable path was dropped pre-validation as "primary
file not in repo": Go/TS/Rust/PHP/Ruby/C++/Swift symbols, Kotlin top-level functions, Java inner
classes, Python packages. Also covers: Java+Kotlin collisions (never resolved by extension order),
``.groovy``/``.kts`` indexing, prefix-truncated paths rewritten to the real file so excerpts read it,
``:L30`` line tails, and root confinement."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from argo.grounding import RepoIndex, is_explicit_path
from argo.models import Finding
from argo.stages.validate import _build_excerpts, _ground_citations, _grounding_note


def _write(root: Path, rel: str, line: str = "// synthetic marker") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text((line + "\n") * 35, encoding="utf-8")
    return path


def _finding(*refs: str, finding_id: str = "F-1") -> Finding:
    return Finding.model_validate({
        "id": finding_id, "title": "Synthetic citation grounding finding", "severity": "High",
        "confidence": "High", "cwe": "CWE-20", "affected": list(refs),
        "vulnerable_flow": "synthetic", "why_vulnerable": "synthetic",
        "exploit_scenario": "synthetic", "impact": "synthetic", "recommended_fix": "synthetic",
    })


def _ground(root: Path, *refs: str):
    return _ground_citations(SimpleNamespace(repo_dir=root), [_finding(*refs)])


# ------------------------------------------------------------------ classification
@pytest.mark.parametrize("ref,explicit", [
    ("src/a.py:7", True), ("Foo.java:12", True), ("src\\x.c:3", True), ("a/b.go", True),
    ("gguf/gguf_tools.c:gguf_get_tensor()", True), ("main.vue:4", True),
    ("io.x.Foo.bar():26", False), ("crate::auth::check():7", False),
    (r"App\Services\Session::check():7", False), ("Auth::Session#valid?:7", False),
    ("auth.Session.Check():7", False), ("res.json()", False), ("README", False), ("", False),
])
def test_is_explicit_path(ref, explicit):
    assert is_explicit_path(ref) is explicit


# ------------------------------------------------------------------ no false drop for symbols
@pytest.mark.parametrize("path,ref", [
    ("src/api/users.ts", "api.users.getUser():7"),
    ("internal/auth/session.go", "auth.Session.Check():7"),
    ("src/auth.rs", "crate::auth::Session::check():7"),
    ("lib/auth/session.rb", "Auth::Session#valid?:7"),
    ("src/Services/Session.php", r"App\Services\Session::check():7"),
    ("src/security/token_validator.cpp", "security::TokenValidator::validate():7"),
    ("Sources/MyApp/AuthService.swift", "MyApp.AuthService.validate():7"),
    ("src/main/kotlin/com/acme/Auth.kt", "com.acme.validate():7"),
])
def test_unresolved_symbolic_primary_is_kept_downgraded_and_noted(tmp_path, path, ref):
    _write(tmp_path, path)
    kept, dropped = _ground(tmp_path, ref)
    assert dropped == [] and len(kept) == 1
    f = kept[0]
    assert f.affected == [ref]                                   # never rewritten to a guess
    assert f.grounding.status == "ungrounded"
    assert f.grounding.unresolved_refs == [ref] and f.grounding.missing_files == []
    assert f.confidence == "Medium"                              # High -> one notch, once
    note = _grounding_note(f)
    assert "NOT evidence the code is absent" in note and "NOT FOUND" not in note


@pytest.mark.parametrize("path,ref,expected", [
    ("src/main/java/pkg/Outer.java", "Outer.Inner.work():7", "src/main/java/pkg/Outer.java:7"),
    ("pkg/__init__.py", "pkg.login():7", "pkg/__init__.py:7"),
    ("src/main/groovy/com/acme/Service.groovy", "com.acme.Service.handle():7",
     "src/main/groovy/com/acme/Service.groovy:7"),
    ("src/main/kotlin/com/acme/Service.kts", "com.acme.Service.handle():7",
     "src/main/kotlin/com/acme/Service.kts:7"),
])
def test_newly_resolvable_qualified_names(tmp_path, path, ref, expected):
    _write(tmp_path, path, "class Outer { class Inner { void work() {} } } def login(): handle()")
    kept, dropped = _ground(tmp_path, ref)
    assert dropped == [] and kept[0].affected == [expected]
    assert kept[0].grounding.status == "grounded" and kept[0].confidence == "High"


def test_pr80_java_qualified_still_resolves_with_excerpt(tmp_path):
    path = "src/main/java/io/moquette/persistence/SerdesUtils.java"
    _write(tmp_path, path, "class SerdesUtils { void readProperties() {} }")
    kept, dropped = _ground(tmp_path, "io.moquette.persistence.SerdesUtils.readProperties():7")
    assert not dropped and kept[0].affected[0] == path + ":7"
    assert "class SerdesUtils" in _build_excerpts(tmp_path, kept[0].affected, 2, 2000)


@pytest.mark.parametrize("ref,expected", [
    ("io.moquette.broker.subscriptions.Topic:L30,L68-L73", "broker/io/moquette/broker/subscriptions/Topic.java:30"),
    ("io.moquette.broker.subscriptions.Topic#L68-L73", "broker/io/moquette/broker/subscriptions/Topic.java:68-73"),
])
def test_line_tail_variants_are_kept(tmp_path, ref, expected):
    _write(tmp_path, "broker/io/moquette/broker/subscriptions/Topic.java")
    assert RepoIndex(tmp_path, set()).normalize_ref(ref) == expected


def test_name_match_needs_the_member_in_the_file(tmp_path):
    # An unrelated ``auth.py`` must not absorb a Go ``auth.Session.Check()`` citation.
    _write(tmp_path, "auth.py", "def unrelated(): pass")
    _write(tmp_path, "internal/auth/session.go", "func (s *Session) Check() {}")
    index = RepoIndex(tmp_path, set())
    assert index.canonical_file("auth.Session.Check():7") is None
    _write(tmp_path, "src/main/java/pkg/Foo.java", "class Foo { void other() {} }")
    assert RepoIndex(tmp_path, set()).canonical_file("pkg.Foo.bar():7") is None


# ------------------------------------------------------------------ anti-hallucination unchanged
def test_explicit_nonexistent_file_is_still_dropped(tmp_path):
    _write(tmp_path, "src/existing.py")
    for ref in ("src/missing/NoSuchFile.py:7", "gguf/gguf_tools.c:gguf_get_tensor()"):
        kept, dropped = _ground(tmp_path, ref)
        assert kept == [] and "ungrounded_citation" in dropped[0]["reason"]


def test_traversal_outside_root_is_not_grounded(tmp_path):
    repo = tmp_path / "repo"
    _write(repo, "src/a.py")
    _write(tmp_path, "outside_secret.py", "LEAK = True")
    kept, dropped = _ground(repo, "../outside_secret.py:1")
    assert kept == [] and dropped                                 # explicit, not inside the root
    assert "LEAK" not in _build_excerpts(repo, ["../outside_secret.py:1"], 1, 2000)


def test_stalwart_style_path_plus_description_is_grounded(tmp_path):
    # Real 2026-07-15 drops: explicit paths that exist upstream, with a ``::`` description tail.
    _write(tmp_path, "crates/types/src/acl.rs")
    kept, dropped = _ground(
        tmp_path, "crates/types/src/acl.rs:25-31 Acl::Modify and Acl::AddItems are distinct grants")
    assert not dropped and kept[0].grounding.status == "grounded"


# ------------------------------------------------------------------ ambiguity and collisions
def test_cross_extension_collision_is_ambiguous(tmp_path):
    _write(tmp_path, "pkg/Foo.java")
    _write(tmp_path, "pkg/Foo.kt")
    index = RepoIndex(tmp_path, set())
    assert index.normalize_ref("pkg.Foo.bar():7") == "pkg.Foo.bar():7"
    assert index.canonical_file("pkg.Foo.bar():7") is None


def test_unique_suffix_is_canonicalized_and_excerpt_reads_it(tmp_path):
    real = "src/main/api/orders.py"
    _write(tmp_path, real, "REAL_ORDER_SOURCE = True")
    kept, dropped = _ground(tmp_path, "api/orders.py:7")
    assert not dropped and kept[0].affected[0] == real + ":7"
    excerpt = _build_excerpts(tmp_path, kept[0].affected, 1, 2000)
    assert "REAL_ORDER_SOURCE = True" in excerpt and "source not found" not in excerpt


def test_ambiguous_basename_is_kept_unresolved_and_never_picked(tmp_path):
    _write(tmp_path, "module_a/orders.py", "MODULE_A_ONLY = True")
    _write(tmp_path, "module_b/orders.py", "MODULE_B_ONLY = True")
    kept, dropped = _ground(tmp_path, "orders.py:7")
    assert not dropped and kept[0].affected == ["orders.py:7"]
    assert kept[0].grounding.unresolved_refs == ["orders.py:7"]
    excerpt = _build_excerpts(tmp_path, kept[0].affected, 1, 2000)
    assert "MODULE_A_ONLY" not in excerpt and "MODULE_B_ONLY" not in excerpt


def test_unresolved_secondary_only_notes_without_downgrade(tmp_path):
    _write(tmp_path, "src/a.py")
    kept, _ = _ground(tmp_path, "src/a.py:3", "auth.Session.Check():9")
    f = kept[0]
    assert f.grounding.status == "grounded" and f.confidence == "High"
    assert f.grounding.unresolved_refs == ["auth.Session.Check():9"]
    assert _grounding_note(f).startswith("NOTE (deterministic pre-check)")


@pytest.mark.parametrize("ext", [".groovy", ".kts"])
def test_qualified_extensions_are_indexed(tmp_path, ext):
    rel = "src/main/com/acme/Service" + ext
    _write(tmp_path, rel)
    assert rel in RepoIndex(tmp_path, set())._paths


def test_symlinked_file_is_not_indexed_or_excerpted(tmp_path):
    external = tmp_path.parent / (tmp_path.name + "_outside_source.py")
    external.write_text("LEAK_THIS_SECRET = True\n", encoding="utf-8")
    try:
        (tmp_path / "outside.py").symlink_to(external)
    except (OSError, NotImplementedError):
        pytest.skip("this platform does not allow creating symlinks")
    try:
        assert "outside.py" not in RepoIndex(tmp_path, set())._paths
        assert "LEAK_THIS_SECRET" not in _build_excerpts(tmp_path, ["outside.py:1"], 1, 2000)
    finally:
        external.unlink(missing_ok=True)


# ---------------------------------------------------------------- existence = complete listing
def test_existing_file_outside_the_content_index_is_never_dropped(tmp_path):
    # .vue is not a scanned source extension, the path is prefix-truncated: it exists -> keep.
    _write(tmp_path, "frontend/src/components/Login.vue", "<template>x</template>")
    kept, dropped = _ground(tmp_path, "components/Login.vue:12")
    assert not dropped and kept[0].affected == ["frontend/src/components/Login.vue:12"]


def test_existing_file_past_the_scan_cap_is_never_dropped(tmp_path, monkeypatch):
    import argo.grounding as g
    monkeypatch.setattr(g, "_SCAN_FILE_CAP", 5)                    # tiny cap, same mechanism
    for i in range(20):
        _write(tmp_path, f"aaa/f{i:02d}.py")
    _write(tmp_path, "zzz/pkg/handlers.py")
    kept, dropped = _ground(tmp_path, "pkg/handlers.py:3")
    assert not dropped and kept[0].affected == ["zzz/pkg/handlers.py:3"]


def test_existing_large_file_is_never_dropped(tmp_path, monkeypatch):
    import argo.grounding as g
    monkeypatch.setattr(g, "_FILE_BYTE_CAP", 100)
    _write(tmp_path, "src/big/generated.py", "x = 1  # padding padding padding")   # > 100 bytes
    kept, dropped = _ground(tmp_path, "big/generated.py:9999")
    assert not dropped and kept[0].affected == ["src/big/generated.py:9999"]
    assert not kept[0].grounding.out_of_range_lines                 # too large to count: never flagged
