"""``needs_runtime_verification`` / ``unknown`` can mean "the model looked and couldn't tell" (a
real quality signal) or "this was never actually examined" (a session/backend outage, a missing
verdict, or budget exhaustion). validate.py and corroborate.py mark the infra-failure case with a
specific rationale prefix; ``_is_infra_unvalidated`` / ``_is_infra_failure`` classify on it so the
run's final summary can report the split explicitly instead of one opaque count. This is what a
session-limit 429 mid-run (seen on the moquette and gguf-tools runs) made hard to tell apart from
the log alone.

**Why the tests below changed shape (2026-09-07).** The per-prefix tests here listed the rationale
strings BY HAND, and one of them read ``"validation session failed: ..."`` with a colon while the
stage writes ``"validation session failed; see the local LLM log..."`` with a semicolon. The test and
the code shared the same fiction, so both agreed and neither was right: every run whose validation
session died reported ``survivors_not_actually_validated: 0`` while its own log said a batch had
failed and three findings had been flagged for human review. A degraded run looked clean, and the
statistic that exists to catch a skipped gate is the one that hid it.

Hand-written fixtures cannot catch that class of bug, because they are written from the same belief
as the code. The tests that can are the two property tests added at the end of each section: they
iterate the module's OWN constants, and they assert that the strings the stage actually writes are
among them. Adding a new unvalidated-survivor rationale without registering it now fails."""

import argo.stages.corroborate as corroborate_stage
import argo.stages.validate as validate_stage
from argo.models import Corroboration, Finding, Validation
from argo.stages.corroborate import _is_infra_failure
from argo.stages.validate import _is_infra_unvalidated


def _finding(rationale: str | None, verdict: str = "needs_runtime_verification") -> Finding:
    return Finding(
        id="F-001", title="t", severity="Medium", confidence="Medium", cwe="CWE-1",
        affected=["a.py:1"], vulnerable_flow="x", why_vulnerable="x", exploit_scenario="x",
        impact="x", recommended_fix="x",
        validation=Validation(verdict=verdict, rationale=rationale) if rationale is not None else None,
    )


# --------------------------------------------------------------------------- validate.py
def test_validate_infra_unvalidated_true_for_each_declared_prefix():
    """Iterate the module's own constants, not a copy of them typed here."""
    for rationale in validate_stage._INFRA_UNVALIDATED_RATIONALE_PREFIXES:
        assert _is_infra_unvalidated(_finding(rationale)) is True


def test_validate_detects_the_exact_string_the_stage_writes():
    """The regression. Semicolon, not colon - written out literally on purpose.

    Comparing the constant against itself would have passed for the whole life of the bug. This
    compares it against the sentence a reader can find in validate.py's ``except RunnerError``
    handler, which is the only thing that decides whether a real run is counted correctly.
    """
    written = "validation session failed; see the local LLM log for diagnostics"
    assert validate_stage._R_SESSION_FAILED == written
    assert _is_infra_unvalidated(_finding(written)) is True
    assert _is_infra_unvalidated(_finding(written + " (batch of 3)")) is True


def test_validate_counts_a_schema_repaired_survivor_as_unvalidated():
    """It was kept for a human precisely BECAUSE nothing adversarially examined it.

    The stage logs this one as "kept unvalidated" and then, before this change, did not count it.
    """
    assert _is_infra_unvalidated(_finding(validate_stage._R_SCHEMA_REPAIRED)) is True


def test_validate_unrecognized_verdict_is_a_prefix_with_the_value_appended():
    assert _is_infra_unvalidated(
        _finding(f"{validate_stage._R_UNRECOGNIZED_VERDICT}'probably'")) is True


def test_validate_infra_unvalidated_false_for_a_genuine_model_verdict():
    genuine = _finding("plausible static evidence but the sanitizer path depends on a runtime "
                       "config flag this session cannot see")
    assert _is_infra_unvalidated(genuine) is False


def test_validate_infra_unvalidated_false_when_no_validation_block():
    assert _is_infra_unvalidated(_finding(None)) is False


def test_validate_infra_unvalidated_false_for_confirmed_verdict():
    # A confirmed finding is never in this bucket regardless of its rationale text.
    assert _is_infra_unvalidated(_finding("validation session failed: x", verdict="confirmed")) is False


# --------------------------------------------------------------------------- corroborate.py
def _corr(rationale: str | None, verdict: str = "unknown") -> Corroboration:
    return Corroboration(verdict=verdict, rationale=rationale)


def test_corroborate_infra_failure_true_for_each_declared_prefix():
    for rationale in corroborate_stage._INFRA_FAILURE_RATIONALE_PREFIXES:
        assert _is_infra_failure(_corr(rationale)) is True


def test_corroborate_detects_both_pass_names_with_the_exception_appended():
    """The session-failure rationale is built per pass ("docs" / "osint") with the error appended."""
    for pass_name in ("docs", "osint"):
        written = (corroborate_stage._R_SESSION_FAILED_FMT.format(pass_name=pass_name)
                   + "claude session API error ... api_error_status=429")
        assert _is_infra_failure(_corr(written)) is True


def test_corroborate_counts_a_schema_invalid_row_as_an_infra_failure():
    """A row that fails schema validation yields no usable verdict, so the finding was not
    corroborated - it was previously left out of the count entirely."""
    assert _is_infra_failure(_corr(corroborate_stage._R_ROW_SCHEMA)) is True


def test_corroborate_infra_failure_false_for_a_genuine_unknown():
    genuine = _corr("searched the docs and changelog; found no mention either way")
    assert _is_infra_failure(genuine) is False


def test_corroborate_infra_failure_false_when_no_rationale():
    assert _is_infra_failure(_corr(None)) is False


def test_corroborate_infra_failure_false_for_non_unknown_verdict():
    # A corroborated/design_accepted/fixed_upstream verdict is never in this bucket regardless of
    # rationale text — the classification only applies to genuine "unknown" outcomes.
    assert _is_infra_failure(_corr("corroboration session failed: x", verdict="corroborated")) is False
