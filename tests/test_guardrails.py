"""Guardrails enforced in code (not just prompts)."""

import json

import pytest

from argo.config import NETWORK_TOOLS, MUTATION_TOOLS
from argo.guardrails import (GuardrailError, LiveInteractionForbiddenError,
                                 PromptGuardrailError, assert_audit_prompt_wellformed,
                                 assert_no_network_tools, assert_prohibited_present,
                                 ensure_prohibited_present,
                                 enforce_session_tools, out_of_scope_match)
from argo.rendering import fill_placeholders, render_audit_template
from argo.config import PipelineConfig

PROHIBITED = ["no DoS / stress / volumetric testing", "no automated scanning of live hosts"]


def test_enforce_session_tools_strips_network_and_mutation():
    requested = ["Read", "Grep", "Glob", "Write", "Bash", "WebFetch", "Edit", "Task"]
    allowed, disallowed = enforce_session_tools(requested)
    assert set(allowed) == {"Read", "Grep", "Glob", "Write"}
    for t in NETWORK_TOOLS | MUTATION_TOOLS:
        assert t not in allowed
        assert t in disallowed


def test_assert_no_network_tools_raises_on_leak():
    with pytest.raises(LiveInteractionForbiddenError):
        assert_no_network_tools(["Read", "Bash"])
    assert_no_network_tools(["Read", "Grep", "Glob", "Write"])  # no raise


def test_research_stage_keeps_osint_but_not_shell():
    """The research stage is the ONLY stage allowed WebSearch/WebFetch — and even it loses the
    shell and sub-agent tools."""
    from argo.config import OSINT_TOOLS, RESEARCH_TOOLS
    allowed, disallowed = enforce_session_tools(list(RESEARCH_TOOLS) + ["Bash", "Task", "Edit"],
                                                stage="research")
    assert set(allowed) == {"WebSearch", "WebFetch", "Read", "Write"}
    for t in ("Bash", "Task", "Edit"):           # still stripped, even for research
        assert t not in allowed
    assert OSINT_TOOLS.isdisjoint(set(disallowed))  # OSINT not disallowed for research
    assert_no_network_tools(allowed, stage="research")  # no raise


def test_only_research_gets_network():
    """Every non-research stage stays fully offline: OSINT tools are stripped and assertion fires."""
    for stage in ("ingest", "recon", "audit", "validate", "report", "remediate", "chat", None):
        allowed, _ = enforce_session_tools(["Read", "WebSearch", "WebFetch"], stage=stage)
        assert "WebSearch" not in allowed and "WebFetch" not in allowed
        with pytest.raises(LiveInteractionForbiddenError):
            assert_no_network_tools(["Read", "WebFetch"], stage=stage)


def test_prohibited_present_ok_and_missing():
    text = "Rules: no DoS / stress / volumetric testing; no automated scanning of live hosts."
    assert_prohibited_present(text, PROHIBITED)  # all present -> no raise
    with pytest.raises(PromptGuardrailError):
        assert_prohibited_present("nothing here", PROHIBITED)


def test_ensure_prohibited_present_reinserts_missing_under_section():
    # model paraphrased the prohibited away but kept the section header
    paraphrased = "## PROHIBITED TECHNIQUES\n- please be nice to the servers\n## NEXT\n"
    repaired = ensure_prohibited_present(paraphrased, PROHIBITED)
    assert_prohibited_present(repaired, PROHIBITED)            # now passes the hard gate
    for p in PROHIBITED:
        assert p in repaired
    assert "please be nice to the servers" in repaired         # only ADDS, never removes


def test_ensure_prohibited_present_creates_section_when_absent():
    repaired = ensure_prohibited_present("no prohibited block at all\n", PROHIBITED)
    assert "## PROHIBITED TECHNIQUES" in repaired
    assert_prohibited_present(repaired, PROHIBITED)


def test_ensure_prohibited_present_noop_when_all_present():
    text = "x no DoS / stress / volumetric testing y no automated scanning of live hosts z"
    assert ensure_prohibited_present(text, PROHIBITED) == text  # unchanged


def test_prohibited_empty_list_is_rejected():
    with pytest.raises(PromptGuardrailError):
        assert_prohibited_present("anything", [])


def test_prohibited_present_matches_json_escaped_nonascii():
    # A non-ASCII prohibited technique (em dash) embedded via the RAW scope.json text appears as a
    # \uXXXX escape (json ensure_ascii=True), while the parsed list carries the real char. The check
    # must still see it as present — this is the bug that crashed validate on a non-English brief.
    proh = ["No fuzzing loops — only minimal, bounded probes"]
    prompt_with_raw_scope = "SCOPE:\n" + json.dumps({"prohibited_techniques": proh})  # -> —
    assert "\\u2014" in prompt_with_raw_scope                  # sanity: the haystack is escaped
    assert_prohibited_present(prompt_with_raw_scope, proh)     # must NOT raise
    # and a genuinely missing one still fails
    with pytest.raises(PromptGuardrailError):
        assert_prohibited_present(prompt_with_raw_scope, ["No DELETE — destructive operations"])


def test_audit_prompt_wellformed_requires_anchors():
    bad = "SCOPE & RULES OF ENGAGEMENT\nPROHIBITED TECHNIQUES\n" + "\n".join(PROHIBITED)
    # missing REQUIRED PER-FINDING FORMAT + Do NOT patch
    with pytest.raises(PromptGuardrailError):
        assert_audit_prompt_wellformed(bad, PROHIBITED)


def test_out_of_scope_match():
    assert out_of_scope_match(["src/legacy/render.py:10"], ["/legacy/"]) == "/legacy/"
    assert out_of_scope_match(["src/api/search.py:42"], ["/legacy/"]) is None
    # windows-style separators normalize
    assert out_of_scope_match(["src\\legacy\\x.py:1"], ["/legacy/"]) == "/legacy/"


def test_fill_placeholders_unresolved_raises():
    with pytest.raises(ValueError):
        fill_placeholders("hello {{MISSING}}", {"OTHER": "x"})
    assert fill_placeholders("a {{X}} b", {"X": "Z"}) == "a Z b"


def test_render_audit_template_strict_undefined():
    # Missing slots must raise rather than silently emit blanks.
    with pytest.raises(Exception):
        render_audit_template({"program_name": "X"}, PipelineConfig().prompts_dir)
