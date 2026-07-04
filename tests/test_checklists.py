"""Mandatory coverage checklist (recall + anti-drop uplift): a memory-safety / resource-exhaustion /
crypto-primitive sweep + one-finding-per-root-cause is deterministically injected into every audit
prompt, gated on cheap repo signals — so the lenses that a recon model can drop are always present.
"""

from argo.checklists import (
    coverage_checklist_block,
    detect_crypto,
    detect_native,
    ensure_coverage_checklist_present,
)
from argo.orchestrator import run_pipeline

from conftest import BRIEF, REPO


def test_detect_native(tmp_path):
    (tmp_path / "main.c").write_text("int main(void){return 0;}", encoding="utf-8")
    assert detect_native(tmp_path) is True
    assert detect_crypto(tmp_path) is False          # "main.c" carries no crypto hint


def test_detect_crypto(tmp_path):
    (tmp_path / "aes_helper.py").write_text("pass\n", encoding="utf-8")
    assert detect_crypto(tmp_path) is True           # "aes" name hint
    assert detect_native(tmp_path) is False          # .py is not native


def test_detect_none(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    assert detect_native(tmp_path) is False
    assert detect_crypto(tmp_path) is False


def test_block_is_gated_by_signals():
    both = coverage_checklist_block(native=True, has_crypto=True)
    assert "MANDATORY COVERAGE CHECKLIST" in both
    assert "Memory safety on untrusted input" in both
    assert "Cryptographic primitive quality" in both
    assert "resource exhaustion" in both.lower()             # always-on lens
    assert "ONE finding = ONE root cause" in both            # P1 reporting discipline
    assert "Variant-family CENSUS" in both                   # R5 always-on
    assert "Secrets & credentials in sinks" in both          # R6 always-on
    assert "SSRF" in both                                    # R8 always-on
    assert "Substitute-then-parse" in both                   # legba: injection AND panic at the same sink
    assert "Panic / abort census" not in both                # native -> memory-safety, not panic-census

    neither = coverage_checklist_block(native=False, has_crypto=False)
    assert "Memory safety on untrusted input" not in neither  # off-target lens omitted
    assert "Cryptographic primitive quality" not in neither
    assert "resource exhaustion" in neither.lower()           # still present
    assert "ONE finding = ONE root cause" in neither
    assert "Variant-family CENSUS" in neither                 # R5 always-on
    assert "Panic / abort census" in neither                 # R7 memory-safe -> panic census

    native_only = coverage_checklist_block(native=True, has_crypto=False)
    assert "Memory safety on untrusted input" in native_only
    assert "Cryptographic primitive quality" not in native_only


def test_injector_idempotent():
    once = ensure_coverage_checklist_present("PROMPT BODY", native=True, has_crypto=True)
    twice = ensure_coverage_checklist_present(once, native=True, has_crypto=True)
    assert once == twice                                      # marker guard
    assert once.count("MANDATORY COVERAGE CHECKLIST") == 1
    assert "PROMPT BODY" in once


def test_coverage_checklist_in_every_audit_prompt(env):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    prompts = {p.name: p.read_text(encoding="utf-8") for p in ctx.prompts_out_dir.glob("audit_*.md")}
    assert prompts
    for text in prompts.values():
        assert "MANDATORY COVERAGE CHECKLIST" in text
        assert "ONE finding = ONE root cause" in text
        assert "resource exhaustion" in text.lower()
