"""--links curated reference-link input (additive to LLM-extracted links)."""

import json
import shutil

import pytest

import argo.stages.ingest as ing
from argo.orchestrator import do_ingest
from argo.rendering import render_audit_template
from argo.schemas import validate_scope
from argo.stages.ingest import (_merge_reference_links, _normalize_link, _parse_links_file)

from conftest import BRIEF, FIXTURES, REPO

LINKS = FIXTURES / "links.txt"
# The fixture links.txt contains a line equal to this URL; the safety rule must drop it.
REPO_URL = "https://github.com/acme/widgets"
# extracted reference_links from tests/fixtures/happy/ingest/scope.json:
EXTRACTED = "https://app.acme.test/docs/security"
USER_VALID = "https://acme.example/security"


# --------------------------------------------------------------------------- parsing
def test_parse_links_file_filters_and_counts(tmp_path):
    p = tmp_path / "l.txt"
    p.write_text(
        "# header\nhttps://a.example/x\n\n  https://b.example  \nnot-a-url\nftp://c.example\n",
        encoding="utf-8")
    links, skipped = _parse_links_file(p)
    assert links == ["https://a.example/x", "https://b.example"]   # blank/comment ignored, trimmed
    assert skipped == 2                                            # not-a-url + ftp


def test_parse_links_file_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        _parse_links_file(tmp_path / "nope.txt")


def test_parse_links_file_empty_is_no_error(tmp_path):
    p = tmp_path / "e.txt"
    p.write_text("# only a comment\n\n   \n", encoding="utf-8")
    assert _parse_links_file(p) == ([], 0)


# --------------------------------------------------------------------------- normalization
def test_normalize_link():
    assert _normalize_link("HTTPS://Acme.EXAMPLE/Docs/") == "https://acme.example/Docs"
    assert _normalize_link("https://acme.example/") == "https://acme.example"
    assert _normalize_link("  https://Acme.example/a ") == "https://acme.example/a"


# --------------------------------------------------------------------------- merge logic
def test_merge_order_dedup_and_repo_drop():
    extracted = ["https://e1.example/a/", "https://shared.example/x"]
    user = ["https://u1.example/", "https://shared.example/x", "https://repo.example/code/"]
    merged, stats = _merge_reference_links(extracted, user, "https://repo.example/code")
    # user-first (verbatim, incl. trailing slash), repo-matching dropped, then new extracted.
    assert merged == ["https://u1.example/", "https://shared.example/x", "https://e1.example/a/"]
    assert stats["dropped_repo"] == 1      # https://repo.example/code/ == --repo
    assert stats["deduped"] == 1           # extracted shared.example/x already present
    assert stats["user_added"] == 2 and stats["extracted_added"] == 1


# --------------------------------------------------------------------------- ingest wiring
def _patch_clone(monkeypatch):
    """Avoid a real git clone for URL repos: copy the local fixture repo instead."""
    monkeypatch.setattr(ing, "acquire_repo",
                        lambda source, dest, *, is_url, commit=None: shutil.copytree(REPO, dest))


def test_ingest_merges_links_into_scope(env, monkeypatch):
    _patch_clone(monkeypatch)
    ctx = env()
    scope = do_ingest(ctx, BRIEF, REPO_URL, links_path=LINKS)
    # provided-valid (verbatim, deduped) FIRST, then extracted not already present.
    # malformed skipped; comment/blank ignored; repo-matching line excluded.
    assert scope.reference_links == [USER_VALID, EXTRACTED]
    # and the merged scope survives the authoritative schema gate (written to scope.json)
    raw = json.loads(ctx.scope_path.read_text(encoding="utf-8"))
    assert raw["reference_links"] == [USER_VALID, EXTRACTED]
    validate_scope(raw, ctx.assets_dir)  # no raise


def test_links_omitted_is_backward_compatible(env):
    ctx = env()
    scope = do_ingest(ctx, BRIEF, str(REPO))      # local path, no --links
    assert scope.reference_links == [EXTRACTED]   # extraction only, unchanged


# --------------------------------------------------------------------------- propagation
def _audit_ctx(scope) -> dict:
    return {
        "program_name": scope.program_name, "audit_focus": "Full-scope",
        "tech_stack": "Python/Flask", "repo_path": "/run/repo", "repo_url": REPO_URL,
        "target_type": scope.target_type, "platform": scope.platform,
        "repo_profile_summary": "summary", "reference_links": scope.reference_links,
        "in_scope": [a.asset for a in scope.in_scope], "out_of_scope": scope.out_of_scope,
        "prohibited_techniques": scope.prohibited_techniques,
        "severity_guidance": scope.severity_guidance or "", "role_statement": "role",
        "attack_surfaces": ["s1"], "historical_bug_classes": ["c1"],
        "audit_focus_slug": "full_scope", "extra_deliverables": [],
    }


def test_provided_links_propagate_to_rendered_audit_prompt(env, monkeypatch):
    _patch_clone(monkeypatch)
    ctx = env()
    scope = do_ingest(ctx, BRIEF, REPO_URL, links_path=LINKS)
    rendered = render_audit_template(_audit_ctx(scope), ctx.config.prompts_dir)
    # Isolate the reference-links block (repo_url legitimately appears in the Repository-root
    # line, so only check the reference list itself).
    block = rendered.split("consult before touching code:")[1].split("This is an")[0]
    assert USER_VALID in block                          # curated link reached the prompt
    assert EXTRACTED in block
    assert "github.com/acme/widgets" not in block        # repo is NOT a reference link
