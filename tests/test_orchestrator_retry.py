"""Orchestrator-level auto-retry: a stage exception classified as transient/retryable gets a
bounded number of automatic in-process retries (real sleep, mocked in these tests) before
propagating -- so a rate limit, a moderation-flag cooldown, or a timeout doesn't necessarily
require a human to notice the run stopped and invoke `argo resume` themselves. Deliberately
excludes credits_exhausted (waiting doesn't fix an empty account) and caps how long it will wait
for a specific reset hint (an unattended run must not silently sleep for hours).
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

import argo.orchestrator as orch
from argo.orchestrator import PipelineCancelled, _run_stage_sequence
from argo.progress import ProgressReporter
from argo.runner import RunnerCancelled, RunnerError


def _never_sleep(monkeypatch):
    """A retry that shouldn't happen at all must not sleep -- fail loudly if it tries to."""
    def _boom(_s):
        raise AssertionError("should not have auto-retried (and therefore not slept)")
    monkeypatch.setattr(orch.time, "sleep", _boom)


def _ctx(tmp_path, run_id="R1"):
    return SimpleNamespace(run_id=run_id, run_dir=tmp_path,
                           runner=SimpleNamespace(cancel_event=None))


def _reporter(ctx):
    return ProgressReporter(ctx, ["stageA", "stageB"])


def test_a_retryable_failure_is_retried_and_can_still_succeed(tmp_path, monkeypatch):
    slept = []
    monkeypatch.setattr(orch.time, "sleep", lambda s: slept.append(s))

    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 2:
            raise RunnerError("recoverable is_error session", retryable=True,
                              failure_kind="rate_limited")
        return "OK"

    ctx = _ctx(tmp_path)
    results = _run_stage_sequence(ctx, [("stageA", flaky)], _reporter(ctx))
    assert results == {"stageA": "OK"}
    assert calls["n"] == 2
    assert len(slept) == 1               # exactly one auto-retry, one sleep


def test_retries_are_bounded_then_propagate(tmp_path, monkeypatch):
    monkeypatch.setattr(orch.time, "sleep", lambda s: None)
    calls = {"n": 0}

    def always_fails():
        calls["n"] += 1
        raise RunnerError("recoverable is_error session", retryable=True,
                          failure_kind="rate_limited")

    ctx = _ctx(tmp_path)
    with pytest.raises(RunnerError):
        _run_stage_sequence(ctx, [("stageA", always_fails)], _reporter(ctx))
    # 1 initial attempt + _MAX_STAGE_AUTO_RETRIES auto-retries, then genuinely give up
    assert calls["n"] == 1 + orch._MAX_STAGE_AUTO_RETRIES


def test_credits_exhausted_is_never_auto_retried(tmp_path, monkeypatch):
    """Waiting doesn't fix a genuinely empty account -- must surface immediately rather than burn
    the bounded retry budget pretending time alone will fix it."""
    _never_sleep(monkeypatch)
    calls = {"n": 0}

    def credits_out():
        calls["n"] += 1
        raise RunnerError("all fallback backends exhausted", retryable=True,
                          failure_kind="credits_exhausted")

    ctx = _ctx(tmp_path)
    with pytest.raises(RunnerError):
        _run_stage_sequence(ctx, [("stageA", credits_out)], _reporter(ctx))
    assert calls["n"] == 1               # no retry attempted at all


def test_non_retryable_failure_is_never_auto_retried(tmp_path, monkeypatch):
    _never_sleep(monkeypatch)
    calls = {"n": 0}

    def deterministic_bug():
        calls["n"] += 1
        raise RunnerError("findings file is not valid JSON")   # retryable=False (the default)

    ctx = _ctx(tmp_path)
    with pytest.raises(RunnerError):
        _run_stage_sequence(ctx, [("stageA", deterministic_bug)], _reporter(ctx))
    assert calls["n"] == 1


def test_a_reset_hint_too_far_out_is_not_auto_waited_for(tmp_path, monkeypatch):
    """A retry_after several hours out would silently hang an unattended run for that whole
    stretch -- give up on auto-retry (surface the failure normally, same as before this feature
    existed) rather than sleep for hours inside the pipeline process."""
    _never_sleep(monkeypatch)
    far_future = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    calls = {"n": 0}

    def far_out_reset():
        calls["n"] += 1
        raise RunnerError("session limit", retryable=True, failure_kind="rate_limited",
                          retry_after=far_future)

    ctx = _ctx(tmp_path)
    with pytest.raises(RunnerError):
        _run_stage_sequence(ctx, [("stageA", far_out_reset)], _reporter(ctx))
    assert calls["n"] == 1


def test_persisted_retry_after_is_an_absolute_timestamp_not_a_raw_hint(tmp_path, monkeypatch):
    """Regression test for a real bug caught live (Argo self-audit session, 2026-08-18): a raw
    human hint like "1:50pm (Europe/Kyiv)" written verbatim into status.json's retry_after is
    ambiguous when `argo resume --wait` re-parses it later -- if resume runs even a few minutes
    AFTER that clock time has already passed today, parse_retry_after's "already past -> must mean
    tomorrow" fallback kicks in and wrongly adds a full day, turning a ~1h wait into a ~24h one.
    The fix: resolve the hint to an absolute ISO timestamp at the moment of failure (when "now" is
    unambiguous), and persist THAT -- re-parsing an ISO timestamp is never ambiguous. The raw hint
    is kept separately, display-only, in retry_after_hint."""
    _never_sleep(monkeypatch)
    hint = "1:50pm (Europe/Kyiv)"

    def hits_session_limit():
        raise RunnerError("session limit", retryable=True, failure_kind="rate_limited",
                          retry_after=hint)

    ctx = _ctx(tmp_path)
    reporter = _reporter(ctx)
    with pytest.raises(RunnerError):
        _run_stage_sequence(ctx, [("stageA", hits_session_limit)], reporter)

    status = reporter.snapshot()
    assert status["retry_after_hint"] == hint
    # Must be an absolute, parseable ISO timestamp -- not the raw hint string itself.
    assert status["retry_after"] != hint
    persisted = datetime.fromisoformat(status["retry_after"])
    # Re-parsing that persisted value later (simulating a delayed `resume --wait`) must return the
    # SAME instant every time, regardless of how much later "now" has moved on -- unlike the raw
    # hint, which orch.parse_retry_after would reinterpret differently depending on the clock.
    much_later = persisted + timedelta(days=3)
    assert orch.parse_retry_after(status["retry_after"], now=much_later) == persisted


def test_a_cancelled_run_is_never_retried(tmp_path, monkeypatch):
    _never_sleep(monkeypatch)

    def cancelled():
        raise RunnerCancelled("session cancelled mid-stage")

    ctx = _ctx(tmp_path)
    with pytest.raises(PipelineCancelled):
        _run_stage_sequence(ctx, [("stageA", cancelled)], _reporter(ctx))
