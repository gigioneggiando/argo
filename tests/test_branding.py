"""Argo provenance attribution: the footer on human-facing artifacts + the toggle."""

from argo import __version__
from argo.branding import attribution_footer, attribution_trailer, coauthored_by
from argo.orchestrator import run_pipeline

from conftest import BRIEF, REPO


def test_footer_mentions_argo_version_and_run():
    f = attribution_footer("RUN-9")
    assert "Argo" in f and __version__ in f and "RUN-9" in f
    assert "license" in f.lower()                      # the "attribution only" caveat
    assert f.startswith("\n\n---\n")                   # a markdown rule separates it from the body


def test_trailers():
    assert attribution_trailer().startswith("Generated-with: Argo")
    assert coauthored_by().startswith("Co-authored-by: Argo <")


def test_report_carries_footer_when_enabled(env):
    ctx = env(attribution=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    md = (ctx.run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "Produced by **Argo**" in md and __version__ in md
    # confirmed-finding drafts carry it too
    drafts = list(ctx.drafts_dir.glob("*.md"))
    assert drafts and all("Produced by **Argo**" in d.read_text(encoding="utf-8") for d in drafts)


def test_report_has_no_footer_when_disabled(env):
    ctx = env(attribution=False)                       # the default in tests
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    assert "Produced by **Argo**" not in (ctx.run_dir / "REPORT.md").read_text(encoding="utf-8")
