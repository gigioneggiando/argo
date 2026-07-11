"""``needs_runtime_verification`` / ``unknown`` can mean "the model looked and couldn't tell" (a
real quality signal) or "this was never actually examined" (a session/backend outage, a missing
verdict, or budget exhaustion). validate.py and corroborate.py mark the infra-failure case with a
specific rationale prefix; ``_is_infra_unvalidated`` / ``_is_infra_failure`` classify on it so the
run's final summary can report the split explicitly instead of one opaque count. This is what a
session-limit 429 mid-run (seen on the moquette and gguf-tools runs) made hard to tell apart from
the log alone."""

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
def test_validate_infra_unvalidated_true_for_each_known_prefix():
    for rationale in [
        "validation session failed: claude session API error ... api_error_status=429",
        "validation session produced no verdict file",
        "no verdict returned for this finding in the batch",
        "not adversarially validated: per-run budget reached",
        "unrecognized verdict 'maybe'",
    ]:
        assert _is_infra_unvalidated(_finding(rationale)) is True


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


def test_corroborate_infra_failure_true_for_each_known_prefix():
    for rationale in [
        "corroboration session failed: claude session API error ... api_error_status=429",
        "corroboration session produced no verdict file",
        "corroboration verdict was not valid JSON",
        "no verdict returned for this finding in the batch",
    ]:
        assert _is_infra_failure(_corr(rationale)) is True


def test_corroborate_infra_failure_false_for_a_genuine_unknown():
    genuine = _corr("searched the docs and changelog; found no mention either way")
    assert _is_infra_failure(genuine) is False


def test_corroborate_infra_failure_false_when_no_rationale():
    assert _is_infra_failure(_corr(None)) is False


def test_corroborate_infra_failure_false_for_non_unknown_verdict():
    # A corroborated/design_accepted/fixed_upstream verdict is never in this bucket regardless of
    # rationale text — the classification only applies to genuine "unknown" outcomes.
    assert _is_infra_failure(_corr("corroboration session failed: x", verdict="corroborated")) is False
