"""Recon accepts template-conforming audit prompts saved without the `audit_` prefix.

Regression (Qwen3.5-9B moquette replay, 2026-11-05): `authorization_bypass.md` and
`persistence_deserialization.md` were silently ignored; only 1 of 3 planned focuses ran."""

from argo.stages.recon import _canonical_prompt_name, _is_any_audit_prompt

PROMPT = ("# Audit\n## SCOPE & RULES OF ENGAGEMENT\n...\n## PROHIBITED TECHNIQUES\n- x\n"
          "## REQUIRED PER-FINDING FORMAT\n...\nDo NOT patch anything.\n")


def test_unprefixed_template_prompt_is_accepted(tmp_path):
    p = tmp_path / "authorization_bypass.md"
    p.write_text(PROMPT, encoding="utf-8")
    assert _is_any_audit_prompt(p)
    assert _canonical_prompt_name(p.name) == "audit_authorization_bypass.md"


def test_prefixed_names_unchanged():
    assert _canonical_prompt_name("audit_x.md") == "audit_x.md"
    assert _canonical_prompt_name("audit-x.md") == "audit_x.md"


def test_other_markdown_is_not_a_prompt(tmp_path):
    notes = tmp_path / "synthesis_notes.md"
    notes.write_text(PROMPT, encoding="utf-8")                 # even if it quotes the template
    other = tmp_path / "threat_model.md"
    other.write_text("# Threat model\nno template sections\n", encoding="utf-8")
    assert not _is_any_audit_prompt(notes) and not _is_any_audit_prompt(other)
