"""AgentRunner.run()'s same-backend retry with a caller-supplied neutral-register prompt variant
on a moderation-flagged failure (see runner.py: run()/_run_attempt()/_NEUTRAL_RETRY_DELAY_S).

This is deliberately independent of FallbackRunner's cross-backend retry (test_fallback.py) and
the orchestrator's whole-stage auto-retry (test_orchestrator_retry.py) -- three separate layers.
"""

import argo.runner as runner_mod
import pytest

from argo.config import PipelineConfig
from argo.ledger import Ledger
from argo.runner import LLMResult, MockClaudeRunner, RunnerError


def _runner(tmp_path):
    return MockClaudeRunner(PipelineConfig(runner="mock"), Ledger(tmp_path / "l.sqlite"))


def _kwargs(tmp_path, **overrides):
    kw = dict(prompt="normal prompt", run_dir=tmp_path, work_dir=tmp_path / "work",
              model="m", stage="audit", run_id="R", label="x")
    kw.update(overrides)
    return kw


def _flag(msg="flagged"):
    raise RunnerError(msg, retryable=True, failure_kind="moderation_flagged")


def test_retries_once_with_neutral_prompt_on_moderation_flag(tmp_path, monkeypatch):
    r = _runner(tmp_path)
    calls, slept = [], []

    def fake_attempt(self, *, prompt, **kw):
        calls.append(prompt)
        if prompt == "normal prompt":
            _flag()
        return LLMResult(text="ok", model="m", prompt_sha256="h", work_dir=tmp_path)

    monkeypatch.setattr(MockClaudeRunner, "_run_attempt", fake_attempt)
    monkeypatch.setattr(runner_mod.time, "sleep", lambda s: slept.append(s))
    result = r.run(**_kwargs(tmp_path, neutral_prompt="neutral prompt"))
    assert result.text == "ok"
    assert calls == ["normal prompt", "neutral prompt"]
    # short, reasoned delay -- NOT FallbackRunner's 90s same-provider cooldown (see
    # runner._MODERATION_RETRY_DELAY's own docstring for why the two are deliberately different).
    assert slept == [runner_mod._NEUTRAL_RETRY_DELAY_S]
    r.ledger.close()


def test_no_retry_when_no_neutral_prompt_supplied(tmp_path, monkeypatch):
    r = _runner(tmp_path)
    calls = []

    def fake_attempt(self, *, prompt, **kw):
        calls.append(prompt)
        _flag()

    monkeypatch.setattr(MockClaudeRunner, "_run_attempt", fake_attempt)
    with pytest.raises(RunnerError):
        r.run(**_kwargs(tmp_path))   # neutral_prompt defaults to None
    assert calls == ["normal prompt"]   # exactly one attempt -- byte-identical to pre-change behavior
    r.ledger.close()


def test_no_retry_for_a_different_failure_kind(tmp_path, monkeypatch):
    r = _runner(tmp_path)
    calls = []

    def fake_attempt(self, *, prompt, **kw):
        calls.append(prompt)
        raise RunnerError("rate limited", retryable=True, failure_kind="rate_limited")

    monkeypatch.setattr(MockClaudeRunner, "_run_attempt", fake_attempt)
    with pytest.raises(RunnerError):
        r.run(**_kwargs(tmp_path, neutral_prompt="neutral prompt"))
    assert calls == ["normal prompt"]   # neutral_prompt is only ever used for moderation_flagged
    r.ledger.close()


def test_bounded_to_one_retry_even_if_the_neutral_variant_also_flags(tmp_path, monkeypatch):
    r = _runner(tmp_path)
    calls = []

    def fake_attempt(self, *, prompt, **kw):
        calls.append(prompt)
        _flag()

    monkeypatch.setattr(MockClaudeRunner, "_run_attempt", fake_attempt)
    monkeypatch.setattr(runner_mod.time, "sleep", lambda s: None)
    with pytest.raises(RunnerError) as exc_info:
        r.run(**_kwargs(tmp_path, neutral_prompt="neutral prompt"))
    assert calls == ["normal prompt", "neutral prompt"]   # no recursion / infinite loop
    assert exc_info.value.failure_kind == "moderation_flagged"
    r.ledger.close()
