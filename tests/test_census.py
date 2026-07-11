"""Cross-file variant census (argo.census): a deterministic pre-scan that enumerates the concrete
extent of a few defect families (native free / copy / alloc sinks, memory-safe panic points) and
injects a closed-ended CENSUS WORKSHEET into every audit prompt — turning the open-ended "enumerate
every sibling" lens into a checklist the auditor clears. Motivated by the #1 recall miss across the
libcsp / halloy / ds4 cross-checks: reporting one member of an enumerable class and moving on."""

from argo.census import (
    _CENSUS_MARKER,
    census_worksheet,
    ensure_variant_census_present,
    scan_families,
)
from argo.orchestrator import run_pipeline

from conftest import BRIEF, REPO


def _write(tmp_path, name, body):
    (tmp_path / name).write_text(body, encoding="utf-8")


# --------------------------------------------------------------------------- unit: scan_families
def test_scan_counts_native_families_per_file(tmp_path):
    _write(tmp_path, "a.c",
           "void a(x *p){ free(p->m); memcpy(d, s, n); p->b = malloc(k); }\n")
    _write(tmp_path, "b.c", "void b(x *p){ free(p->m); }\n")
    fams = scan_families(tmp_path)
    assert fams["free"].count == 2                       # one per file
    assert set(fams["free"].files) == {"a.c", "b.c"}
    assert fams["copy"].count == 1                       # only a.c
    assert fams["alloc"].count == 1


def test_scan_panic_only_in_memsafe_files(tmp_path):
    _write(tmp_path, "m.rs", "fn m(){ let x = f().unwrap(); g().expect(\"n\"); panic!(\"x\"); }\n")
    _write(tmp_path, "n.c", "void n(){ free(p); }\n")     # C -> not a panic-family file
    fams = scan_families(tmp_path)
    assert fams["panic"].count == 3                       # unwrap + expect + panic!
    assert "free" in fams and "panic" in fams


# --------------------------------------------------------------------------- unit: worksheet
def test_worksheet_lists_family_extent(tmp_path):
    _write(tmp_path, "a.c", "void a(){ free(p); free(q); }\n")
    _write(tmp_path, "b.c", "void b(){ free(r); }\n")
    ws = census_worksheet(tmp_path)
    assert _CENSUS_MARKER in ws
    assert "heap free / ownership sites" in ws
    assert "3 sites across 2 files" in ws                 # 2 in a.c + 1 in b.c
    assert "`a.c`" in ws and "`b.c`" in ws


def test_singleton_family_is_not_censused(tmp_path):
    # A family with a single site is just the finding, not a census -> omitted entirely.
    _write(tmp_path, "a.c", "void a(){ free(p); }\n")
    assert census_worksheet(tmp_path) == ""


def test_worksheet_empty_when_no_family(tmp_path):
    _write(tmp_path, "app.py", "x = 1\n")                 # .py is neither native nor a panic-family ext
    assert census_worksheet(tmp_path) == ""


def test_file_list_is_capped(tmp_path):
    for i in range(20):
        _write(tmp_path, f"f{i:02d}.c", "void f(){ free(p); free(q); }\n")
    ws = census_worksheet(tmp_path)
    assert "40 sites across 20 files" in ws
    assert "more files)" in ws                            # tail collapsed past the cap


# --------------------------------------------------------------------------- unit: injector
def test_injector_idempotent(tmp_path):
    _write(tmp_path, "a.c", "void a(){ free(p); free(q); }\n")
    once = ensure_variant_census_present("PROMPT BODY", tmp_path)
    twice = ensure_variant_census_present(once, tmp_path)
    assert once == twice
    assert once.count(_CENSUS_MARKER) == 1
    assert "PROMPT BODY" in once


def test_injector_noop_when_nothing_to_census(tmp_path):
    _write(tmp_path, "app.py", "x = 1\n")
    assert ensure_variant_census_present("PROMPT BODY", tmp_path) == "PROMPT BODY"


# --------------------------------------------------------------------------- integration: pipeline
def test_worksheet_absent_for_non_native_fixture_repo(env):
    # The fixture repo is pure Python (no native / panic-family files) -> no worksheet is injected,
    # and the pipeline runs fine without it.
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    prompts = [p.read_text(encoding="utf-8") for p in ctx.prompts_out_dir.glob("audit_*.md")]
    assert prompts
    for text in prompts:
        assert _CENSUS_MARKER not in text
