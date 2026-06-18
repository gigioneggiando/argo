"""Stage 0 — web research / threat intelligence (opt-out; the ONLY networked stage).

From the program name, brief, and reference links, the model does **public OSINT** (web search +
fetching public pages: the source repo host, package registries, docs, NVD/CVE/GHSA advisories,
and the provided links) to understand what is being audited and where to focus. It produces a
``research_brief.md`` + ``threat_intel.json`` that recon injects as additional context.

Guardrails (defense in depth):
  * This is the ONLY stage whose session keeps the OSINT tools (``WebSearch``/``WebFetch``); it has
    no shell, no sub-agents, no repo access — see ``guardrails.enforce_session_tools``.
  * It must NEVER contact/fetch/probe the program's **live in-scope hosts** (web/api/mobile assets);
    those are passed as an explicit forbidden list in the prompt.
  * Best-effort: a failure here never fails the run — recon simply proceeds without the brief.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from ..config import RESEARCH_TOOLS
from ..context import RunContext, collect_output_files
from ..rendering import with_artifact_contract
from ..runner import RunnerError

_LIVE_ASSET_TYPES = {"web", "api", "mobile"}

_SYSTEM = """You are a security researcher doing OPEN-SOURCE threat reconnaissance to PREPARE an \
authorized, SOURCE-ONLY code audit. You will NOT see the code in this step — your job is external \
intelligence: understand the target and how an auditor should approach it.

HARD RULES (non-negotiable):
- PUBLIC OSINT ONLY. You may search the web and fetch PUBLIC sources: the source repository host \
(GitHub/GitLab), package registries, the project's docs/site, NVD / CVE / GHSA advisories, \
release notes, and the reference links provided below.
- You MUST NOT contact, fetch, scan, probe, log in to, or otherwise interact with the program's \
LIVE in-scope target hosts or any of its running endpoints/APIs (listed under FORBIDDEN LIVE HOSTS). \
Even though they are "in scope" for the separate human test, touching them here is out of bounds.
- Do not submit forms or send payloads anywhere. Read public information only. No exploitation."""

_FOOTER = """Produce TWO files in your working directory:

1) research_brief.md — a concise brief for the auditor: what the software is; stack/architecture; \
notable security history (CVE/GHSA ids + links); the components/areas most likely to hold bugs; \
the attacker model; and a recommended audit approach (what to prioritize first, and why).

2) threat_intel.json — structured and machine-readable:
{"software": str, "stack": [str],
 "known_cves": [{"id": str, "summary": str, "url": str}],
 "advisories": [{"ref": str, "url": str}],
 "risk_areas": [str], "suspected_vuln_classes": [str],
 "references": [str], "approach_notes": str}

Cite real URLs you actually consulted. If web access is unavailable, say so and produce a \
best-effort brief from the program brief + reference links alone."""

_BRIEF_CAP = 9000


def _repo_url(scope) -> str:
    for a in scope.source_repo_assets:
        return a.asset
    return ""


def _build_prompt(scope) -> str:
    live = [a.asset.strip() for a in scope.in_scope
            if a.type in _LIVE_ASSET_TYPES and a.asset.strip()]
    forbidden = "\n".join(f"  - {h}" for h in live) or "  (none listed in scope)"
    refs = "\n".join(f"  - {link}" for link in scope.reference_links) or "  (none provided)"
    body = with_artifact_contract(
        "\n\n".join([
            _SYSTEM,
            f"PROGRAM: {scope.program_name}   (target_type: {scope.target_type})",
            f"SOURCE REPOSITORY (public — OK to read): {_repo_url(scope) or '(unknown)'}",
            f"REFERENCE LINKS (provided — OK to read):\n{refs}",
            f"FORBIDDEN LIVE HOSTS (NEVER fetch / probe / interact with these):\n{forbidden}",
            "PROGRAM BRIEF:\n" + (scope.program_brief_raw or "(none provided)"),
            _FOOTER,
        ]),
        artifacts=[
            {"type": "research_brief", "filename": "research_brief.md", "schema": None,
             "desc": "auditor-facing external threat brief (markdown)"},
            {"type": "threat_intel", "filename": "threat_intel.json", "schema": None,
             "desc": "structured threat intel (the JSON shape described above)"},
        ],
    )
    return body


def run(ctx: RunContext) -> Path | None:
    scope = ctx.scope or ctx.load_scope()
    work = ctx.work_dir("research")
    try:
        result = ctx.runner.run(
            prompt=_build_prompt(scope),
            run_dir=ctx.run_dir,
            work_dir=work,
            model=ctx.config.model_for("research"),
            stage="research",
            run_id=ctx.run_id,
            repo_dir=None,                 # the networked session never sees the code
            allowed_tools=RESEARCH_TOOLS,  # WebSearch/WebFetch + Write (sanitized by the runner)
            label="research",
        )
        files = collect_output_files(result, "*")
    except RunnerError as exc:
        files = sorted(p for p in work.glob("*") if p.is_file())
        if not files:
            print(f"[research] session failed ({exc}); continuing without threat intel",
                  file=sys.stderr)
            return None

    brief = next((f for f in files if f.name == "research_brief.md"), None)
    intel = next((f for f in files if f.name == "threat_intel.json"), None)
    if brief is not None:
        ctx.research_brief_path.write_text(brief.read_text(encoding="utf-8"), encoding="utf-8")
    if intel is not None:
        text = intel.read_text(encoding="utf-8")
        try:
            json.loads(text)                       # must be valid JSON to be promoted
            ctx.threat_intel_path.write_text(text, encoding="utf-8")
        except ValueError:
            print("[research] threat_intel.json was not valid JSON; keeping the brief only",
                  file=sys.stderr)
    return ctx.research_brief_path if ctx.research_brief_path.exists() else None
