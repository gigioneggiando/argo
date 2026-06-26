"""Resilience: the FallbackRunner chains backends, retrying a session/rate-limited call on the next
backend (Claude -> Codex -> local), with a circuit breaker and per-backend model selection."""

import pytest

from argo.config import PipelineConfig
from argo.runner import FallbackRunner, RunnerError, _is_retryable, build_runner


class _Fake:
    """A duck-typed backend: its run() either returns a marker or raises."""
    def __init__(self, name, behavior):
        self.config = PipelineConfig(runner=name)
        self.cancel_event = None
        self._behavior = behavior
        self.calls = 0
        self.models = []

    def run(self, **kw):
        self.calls += 1
        self.models.append(kw.get("model"))
        return self._behavior(kw)


def _raise(msg):
    def b(kw):
        raise RunnerError(msg)
    return b


def _return(val):
    def b(kw):
        return val
    return b


_KW = dict(prompt="x", run_dir=None, work_dir=None, model="m", stage="validate", run_id="r")


def test_is_retryable():
    assert _is_retryable(RunnerError("You've hit your session limit · resets 5pm"))
    assert _is_retryable(RunnerError("api_error_status=429, ..."))
    assert _is_retryable(RunnerError("model overloaded"))
    assert not _is_retryable(RunnerError("findings file is not valid JSON"))
    assert not _is_retryable(RunnerError("codex CLI not found on PATH"))


def test_falls_back_on_retryable_limit():
    p = _Fake("headless", _raise("You've hit your session limit"))
    f = _Fake("codex", _return("CODEX-RESULT"))
    fr = FallbackRunner(PipelineConfig(), None, [p, f])
    assert fr.run(**_KW) == "CODEX-RESULT"
    assert p.calls == 1 and f.calls == 1


def test_non_retryable_propagates_without_fallback():
    p = _Fake("headless", _raise("findings file is not valid JSON"))
    f = _Fake("codex", _return("CODEX-RESULT"))
    fr = FallbackRunner(PipelineConfig(), None, [p, f])
    with pytest.raises(RunnerError):
        fr.run(**_KW)
    assert f.calls == 0                       # the deterministic error never reached the fallback


def test_circuit_breaker_skips_walled_backend():
    p = _Fake("headless", _raise("session limit"))
    f = _Fake("codex", _return("CODEX-RESULT"))
    fr = FallbackRunner(PipelineConfig(), None, [p, f])
    assert fr.run(**_KW) == "CODEX-RESULT"     # first call: primary fails -> fallback
    assert fr.run(**_KW) == "CODEX-RESULT"     # second call: primary is disabled, skipped
    assert p.calls == 1 and f.calls == 2


def test_each_backend_picks_its_own_model():
    # primary (headless) fails -> codex child should be called with the codex model, not opus
    p = _Fake("headless", _raise("session limit"))
    f = _Fake("codex", _return("ok"))
    fr = FallbackRunner(PipelineConfig(), None, [p, f])
    fr.run(**_KW)
    assert p.models[0] == PipelineConfig(runner="headless").model_for("validate")
    assert f.models[0] == PipelineConfig(runner="codex").model_for("validate")


class _Always429(__import__("argo.runner", fromlist=["AgentRunner"]).AgentRunner):
    """A real AgentRunner whose every session raises a retryable session-limit error."""
    def _invoke(self, **kwargs):
        raise RunnerError("You've hit your session limit · resets later")


def test_full_pipeline_self_heals_onto_fallback(env):
    """End-to-end: a primary backend that ALWAYS 429s -> the whole pipeline transparently runs on
    the (mock) fallback and completes. Proves no data loss + automatic recovery across the wall."""
    from conftest import BRIEF, REPO
    from argo.orchestrator import run_pipeline
    from argo.runner import MockClaudeRunner

    ctx = env()
    primary = _Always429(ctx.config, ctx.ledger)
    fallback = MockClaudeRunner(ctx.config, ctx.ledger)
    ctx.runner = FallbackRunner(ctx.config, ctx.ledger, [primary, fallback])
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    assert (ctx.run_dir / "REPORT.md").is_file()                 # the run completed via the fallback
    assert (ctx.run_dir / "validated_findings.json").is_file()


def test_build_runner_wraps_in_fallback(tmp_path):
    from argo.ledger import Ledger
    ledger = Ledger(tmp_path / "l.sqlite")
    try:
        plain = build_runner(PipelineConfig(runner="mock"), ledger)
        assert not isinstance(plain, FallbackRunner)
        chained = build_runner(PipelineConfig(runner="mock", runner_fallbacks=["mock"]), ledger)
        assert isinstance(chained, FallbackRunner) and len(chained._runners) == 2
    finally:
        ledger.close()
