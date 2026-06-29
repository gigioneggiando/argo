"""Provenance attribution for Argo-produced audit artifacts.

A signature — like Claude Code's ``Co-Authored-By`` trailer — so a reviewer can see that a report,
submission draft, fix report, or remediation PR was produced by **Argo**. It is attribution only: it
does NOT change the target's or Argo's license, and Argo is not claimed as an author of the target's
own code (the fixes are proposals).

The footer ships with the tool and is **on by default**, so the same Argo signature appears on every
user's audit artifacts (not just locally). It can be turned off with ``--no-attribution`` /
``PipelineConfig(attribution=False)`` for anyone who doesn't want it.
"""

from __future__ import annotations

from . import __version__

ARGO_URL = "https://github.com/gigioneggiando/argo"
ARGO_NAME = "Argo"
ARGO_TAGLINE = "LLM-native security auditing"


def attribution_footer(run_id: str | None = None) -> str:
    """Markdown footer appended to human-facing audit artifacts (REPORT.md, submission drafts, …)."""
    rid = f" · run `{run_id}`" if run_id else ""
    return (
        "\n\n---\n"
        f"*Produced by **{ARGO_NAME}** — {ARGO_TAGLINE} · {ARGO_URL} · v{__version__}{rid}. "
        "AI-assisted: findings may include false positives — review before acting. "
        "(Attribution only; does not change the project's license.)*\n"
    )


def attribution_trailer() -> str:
    """Git-trailer form for remediation commits / PR bodies on a TARGET repo — provenance of the
    proposed change, not authorship of the target's code."""
    return f"Generated-with: {ARGO_NAME} ({ARGO_TAGLINE}) {ARGO_URL}"


def coauthored_by() -> str:
    """``Co-authored-by`` trailer (the GitHub-recognized form) for remediation commits/PRs, mirroring
    the convention the user referenced. Renders an "Argo" co-author chip on the PR/commit."""
    return "Co-authored-by: Argo <noreply@github.com>"
