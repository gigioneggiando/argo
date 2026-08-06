"""Resilience: the FallbackRunner chains backends, retrying a session/rate-limited call on the next
backend (Claude -> Codex -> local), with a circuit breaker and per-backend model selection."""

import pytest

from argo.config import PipelineConfig
from argo.runner import (FallbackRunner, RunnerError, _extract_session_reset_hint,
                         _is_retryable, build_runner)


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


def test_extract_session_reset_hint():
    # The real detail text seen in production (moquette + gguf-tools runs): a human/resume-script
    # should be able to grep the run log for this instead of re-reading the raw API error text.
    assert _extract_session_reset_hint(
        "You've hit your session limit · resets 12:50am (Europe/Rome)") == "12:50am (Europe/Rome)"
    assert _extract_session_reset_hint("You've hit your session limit · resets 5pm") == "5pm"
    assert _extract_session_reset_hint("model overloaded, try again later") is None
    assert _extract_session_reset_hint(None) is None
    assert _extract_session_reset_hint("") is None


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


def _raise_hintless_retryable(msg="recoverable is_error session (stage=audit): stop_reason='exit_1'"):
    """Mirrors the real shape of AgentRunner.run()'s final `raise RunnerError(..., retryable=True)`
    for a Codex exit_1/0-token crash: retryable, but with NO parseable reset hint (retry_after is
    never set on that path unless the error text itself carried a "resets HH:MM"-style hint, which
    Codex's crash signature never does)."""
    def b(kw):
        raise RunnerError(msg, retryable=True)
    return b


def test_hintless_retryable_error_gets_bounded_cooldown_not_permanent():
    # Reproduces a real production failure (livekit run 20260804-170931-d90733, 2026-08-04): a
    # single transient Codex sandbox flake (exit_1, 0 tokens, no api_error_status -- indistinguishable
    # from real credit exhaustion by message text alone) hit right after `ingest`. Before this fix,
    # a retryable error with no parseable reset hint disabled the backend FOREVER for the rest of
    # the process (retry_at stayed None) -- so every subsequent call for the rest of that ~9-hour
    # run skipped Codex entirely and went straight to the Claude fallback, which then burned
    # through its OWN real session-limit quota covering for what should have been one retry.
    from datetime import datetime, timedelta, timezone
    import argo.runner as runner_mod

    p = _Fake("codex", _raise_hintless_retryable())
    f = _Fake("headless", _return("CLAUDE-RESULT"))
    fr = FallbackRunner(PipelineConfig(), None, [p, f])

    assert fr.run(**_KW) == "CLAUDE-RESULT"        # codex fails hint-less -> falls back to claude
    assert p.calls == 1 and f.calls == 1

    disabled_until = fr._disabled[0]
    assert disabled_until is not None              # bounded now, NOT the old "disabled forever" None
    now = datetime.now(timezone.utc)
    assert now < disabled_until <= now + runner_mod._NO_HINT_RETRY_COOLDOWN

    # second call, still within the cooldown window: codex stays skipped (same as before the fix)
    fr.run(**_KW)
    assert p.calls == 1 and f.calls == 2

    # simulate the cooldown having elapsed: codex must be RETRIED, not permanently benched
    fr._disabled[0] = now - timedelta(seconds=1)
    fr.run(**_KW)
    assert p.calls == 2 and f.calls == 3           # codex was tried again (and failed again -> fallback)


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


def test_build_runner_multi_account_claude_chain(tmp_path):
    from argo.ledger import Ledger
    from argo.runner import HeadlessClaudeRunner
    ledger = Ledger(tmp_path / "l.sqlite")
    try:
        cfg = PipelineConfig(runner="headless", claude_accounts=["/acct/a", "/acct/b"])
        r = build_runner(cfg, ledger)
        assert isinstance(r, FallbackRunner) and len(r._runners) == 2
        assert all(isinstance(x, HeadlessClaudeRunner) for x in r._runners)
        assert [x.config.claude_config_dir for x in r._runners] == ["/acct/a", "/acct/b"]
    finally:
        ledger.close()


def test_build_runner_cross_backend_multi_account_sets_correct_runner(tmp_path):
    # Reproduces a real production failure (livekit run, 2026-08-02): primary=codex (single
    # account -> _build_one), fallback=headless with MULTIPLE claude_accounts -> _expand_backend's
    # multi-account branch. Each expanded HeadlessClaudeRunner's own config.runner must say
    # "headless", NOT inherit "codex" from the top-level config - otherwise model_for(stage)
    # resolves to the Codex model id (e.g. "gpt-5.5") even on the Claude CLI call, which then
    # fails with a hard "model not found" 404, defeating the whole point of the fallback chain.
    from argo.ledger import Ledger
    from argo.runner import HeadlessClaudeRunner
    ledger = Ledger(tmp_path / "l.sqlite")
    try:
        cfg = PipelineConfig(runner="codex", runner_fallbacks=["headless"],
                             claude_accounts=["/acct/a", "/acct/b"])
        r = build_runner(cfg, ledger)
        assert isinstance(r, FallbackRunner) and len(r._runners) == 3   # codex -> acctA -> acctB
        fallback_runners = r._runners[1:]
        assert all(isinstance(x, HeadlessClaudeRunner) for x in fallback_runners)
        assert all(x.config.runner == "headless" for x in fallback_runners)
        # the model resolution that actually broke in production: with the bug, config.runner
        # stayed "codex" on the fallback runners, so model_for() returned the Codex model id
        # (e.g. "gpt-5.5") even though the CLI being invoked was `claude`, not `codex`.
        assert all(x.config.model_for("validate") ==
                   PipelineConfig(runner="headless").model_for("validate")
                   for x in fallback_runners)
    finally:
        ledger.close()


def test_build_runner_accounts_then_backend_fallback(tmp_path):
    from argo.ledger import Ledger
    ledger = Ledger(tmp_path / "l.sqlite")
    try:
        cfg = PipelineConfig(runner="headless", claude_accounts=["/a", "/b"],
                             runner_fallbacks=["codex"])
        r = build_runner(cfg, ledger)
        assert isinstance(r, FallbackRunner) and len(r._runners) == 3   # acctA -> acctB -> codex
        assert r._runners[2].config.runner == "codex"
    finally:
        ledger.close()


def test_build_runner_multi_account_codex_chain(tmp_path):
    from argo.ledger import Ledger
    from argo.runner import CodexRunner
    ledger = Ledger(tmp_path / "l.sqlite")
    try:
        cfg = PipelineConfig(runner="codex", codex_accounts=["/cdx/a", "/cdx/b"])
        r = build_runner(cfg, ledger)
        assert isinstance(r, FallbackRunner) and len(r._runners) == 2
        assert all(isinstance(x, CodexRunner) for x in r._runners)
        assert [x.config.codex_home for x in r._runners] == ["/cdx/a", "/cdx/b"]
    finally:
        ledger.close()


def test_build_runner_mixed_claude_and_codex_accounts(tmp_path):
    from argo.ledger import Ledger
    from argo.runner import HeadlessClaudeRunner, CodexRunner
    ledger = Ledger(tmp_path / "l.sqlite")
    try:
        cfg = PipelineConfig(runner="headless", claude_accounts=["/cl/a", "/cl/b"],
                             runner_fallbacks=["codex"], codex_accounts=["/cx/a", "/cx/b"])
        r = build_runner(cfg, ledger)
        # claude A -> claude B -> codex A -> codex B  (the codex fallback also expands per-account)
        assert len(r._runners) == 4
        assert [type(x).__name__ for x in r._runners] == \
            ["HeadlessClaudeRunner", "HeadlessClaudeRunner", "CodexRunner", "CodexRunner"]
    finally:
        ledger.close()
