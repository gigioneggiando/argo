"""Design-context input (#1) + impact discipline (#3): the accepted-by-design list and the
anti-over-claim ("IMDS-angle") rules are injected into every audit prompt (and validate/corroborate)
so intended behaviors aren't reported as bugs and SSRF impact isn't reflexively escalated.
"""

import json

from argo.orchestrator import run_pipeline
from argo.rendering import design_context_block, ensure_design_context_present

from conftest import BRIEF, REPO


def _audit_prompts(ctx) -> dict:
    return {p.name: p.read_text(encoding="utf-8") for p in ctx.prompts_out_dir.glob("audit_*.md")}


def test_impact_discipline_in_every_audit_prompt(env):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    prompts = _audit_prompts(ctx)
    assert prompts
    for text in prompts.values():
        assert "IMPACT DISCIPLINE" in text
        assert "IMDS" in text and "169.254.169.254" in text          # the anti-over-claim rule
        assert "Accepted-by-design behaviors" not in text            # only when risks are supplied


def test_accepted_risks_injected_into_scope_and_prompts(env, tmp_path):
    risks = tmp_path / "accepted.md"
    risks.write_text(
        "- Webhooks are admin-gated and may reach internal URLs by design.\n"
        "- Media is served statically and not protected by member access.\n", encoding="utf-8")
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False, accepted_risks_path=risks)
    scope = json.loads(ctx.scope_path.read_text(encoding="utf-8"))
    assert "admin-gated" in scope["accepted_risks"]
    for text in _audit_prompts(ctx).values():
        assert "Accepted-by-design behaviors" in text
        assert "served statically and not protected" in text         # the actual risk text flows in


def test_block_conditional_and_idempotent():
    base = design_context_block()
    assert "169.254.169.254" in base and "Accepted-by-design" not in base   # discipline only
    assert "Severity symmetry" in base                                       # P2: don't under-claim either
    assert "Purpose-is-the-feature" in base                                  # peek/poke = the feature
    assert "Trusted-bus" in base                                             # embedded no-auth is by design
    assert "deprecated, legacy" in base                                      # vestigial mechanism qualifier
    assert "Niche/opt-in component" in base                                  # rebus lesson: don't discount severity
    assert "config→exec" in base or "config-exec" in base or "DATA channel" in base  # legba: config/deser->exec is a finding
    withrisks = design_context_block("- X is intended.")
    assert "Accepted-by-design" in withrisks and "X is intended" in withrisks
    once = ensure_design_context_present("PROMPT BODY", "- X is intended.")
    twice = ensure_design_context_present(once, "- X is intended.")
    assert once == twice                                             # idempotent (marker guard)
    assert once.count("DESIGN CONTEXT & IMPACT DISCIPLINE") == 1
