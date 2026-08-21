"""Resilience: the FallbackRunner chains backends, retrying a session/rate-limited call on the next
backend (Claude -> Codex -> local), with a circuit breaker and per-backend model selection."""

import pytest

from argo.config import PipelineConfig
from argo.runner import (FallbackRunner, RunnerError, _classify_failure_text,
                         _extract_session_reset_hint, _is_retryable, build_runner)


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
    assert not _is_retryable(RunnerError(
        "bootstrap failed: provider stderr mentioned quota 429",
        failure_kind="credential_bootstrap"))


def test_extract_session_reset_hint():
    # The real detail text seen in production (moquette + gguf-tools runs): a human/resume-script
    # should be able to grep the run log for this instead of re-reading the raw API error text.
    assert _extract_session_reset_hint(
        "You've hit your session limit · resets 12:50am (Europe/Rome)") == "12:50am (Europe/Rome)"
    assert _extract_session_reset_hint("You've hit your session limit · resets 5pm") == "5pm"
    assert _extract_session_reset_hint("model overloaded, try again later") is None
    assert _extract_session_reset_hint(None) is None
    assert _extract_session_reset_hint("") is None


def test_classify_failure_text():
    # The real observed shapes (see codex-moderation-cybersecurity-flag / argo-run-pacing-limits
    # campaign notes) -- case-insensitive substring match, not the whole sentence, since wording
    # around the load-bearing phrase could shift.
    assert _classify_failure_text(
        "ERROR: This content was flagged for possible cybersecurity risk. If this seems wrong, "
        "try rephrasing your request. To get authorized for security work, join the Trusted "
        "Access for Cyber program: https://chatgpt.com/cyber") == "moderation_flagged"
    assert _classify_failure_text("FLAGGED FOR POSSIBLE CYBERSECURITY RISK") == "moderation_flagged"
    # Claude's OWN refusal wording (confirmed live 2026-08-12 on a real asan_poc harness-authoring
    # session, an authorized security-research call, not just Codex) -- same failure_kind, since
    # it's the same category of failure (a safety classifier refusing legitimate content) on a
    # different backend.
    assert _classify_failure_text(
        "API Error: Opus 4.8's safeguards flagged this message. Our intentionally broad "
        "safeguards allow us to deliver more capabilities faster, but can sometimes flag "
        "legitimate cybersecurity work. Apply to the Cyber Verification Program to reduce these "
        "interruptions.") == "moderation_flagged"
    assert _classify_failure_text(
        "ERROR: Your workspace is out of credits. Please contact your administrator."
    ) == "credits_exhausted"
    assert _classify_failure_text("You've hit your session limit · resets 5pm") == "rate_limited"
    assert _classify_failure_text("api_error_status=429, retry later") == "rate_limited"
    # generic/unrelated text and empty input match nothing specific
    assert _classify_failure_text("codex produced no output; likely auth/startup failure") is None
    assert _classify_failure_text(None) is None
    assert _classify_failure_text("") is None


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


# --------------------------------------------------------------- failure-kind-aware cooldown/backoff
def _raise_kind(kind, msg="recoverable is_error session"):
    def b(kw):
        raise RunnerError(msg, retryable=True, failure_kind=kind)
    return b


def test_credits_exhausted_gets_a_longer_cooldown_than_the_hintless_default():
    """Retrying every 5 minutes against a genuinely empty account is pointless -- once the failure
    is POSITIVELY classified as credits_exhausted (not just an ambiguous hint-less failure), it
    should be benched longer so the run spends that time productively on a different backend."""
    import argo.runner as runner_mod
    from datetime import datetime, timezone

    from datetime import timedelta

    p = _Fake("codex", _raise_kind("credits_exhausted"))
    f = _Fake("headless", _return("CLAUDE-RESULT"))
    fr = FallbackRunner(PipelineConfig(), None, [p, f])
    assert fr.run(**_KW) == "CLAUDE-RESULT"

    now = datetime.now(timezone.utc)
    disabled_until = fr._disabled[0]
    expected = runner_mod._COOLDOWN_BY_FAILURE_KIND["credits_exhausted"]
    assert expected > runner_mod._NO_HINT_RETRY_COOLDOWN  # sanity: it really is the longer one
    assert now + expected - timedelta(seconds=5) <= disabled_until <= now + expected


def test_unrecognized_failure_kind_falls_back_to_the_default_cooldown():
    import argo.runner as runner_mod
    from datetime import datetime, timezone

    p = _Fake("codex", _raise_kind("unknown_retryable"))
    f = _Fake("headless", _return("CLAUDE-RESULT"))
    fr = FallbackRunner(PipelineConfig(), None, [p, f])
    assert fr.run(**_KW) == "CLAUDE-RESULT"

    now = datetime.now(timezone.utc)
    disabled_until = fr._disabled[0]
    assert now < disabled_until <= now + runner_mod._NO_HINT_RETRY_COOLDOWN


def test_moderation_flag_sleeps_before_retrying_the_same_backend_type(monkeypatch):
    """The core fix for the observed failure mode: a runner_fallbacks=["codex","codex"] chain
    previously fired the second attempt with zero delay, which flagged on every attempt even when
    a spaced-out one-off call with the identical prompt succeeded. Same-provider retries after a
    moderation flag must now wait."""
    import argo.runner as runner_mod

    slept = []
    monkeypatch.setattr(runner_mod.time, "sleep", lambda s: slept.append(s))

    p1 = _Fake("codex", _raise_kind("moderation_flagged"))
    p2 = _Fake("codex", _return("CODEX-RESULT-2"))
    fr = FallbackRunner(PipelineConfig(), None, [p1, p2])
    assert fr.run(**_KW) == "CODEX-RESULT-2"
    assert slept == [runner_mod._MODERATION_RETRY_DELAY.total_seconds()]


def test_moderation_flag_does_not_sleep_before_a_genuinely_different_backend(monkeypatch):
    """A different provider (codex -> headless) doesn't share whatever cooldown flagged the first
    one, so there is nothing to wait out -- the fallback should still fire immediately, same as any
    other retryable error."""
    import argo.runner as runner_mod

    slept = []
    monkeypatch.setattr(runner_mod.time, "sleep", lambda s: slept.append(s))

    p = _Fake("codex", _raise_kind("moderation_flagged"))
    f = _Fake("headless", _return("CLAUDE-RESULT"))
    fr = FallbackRunner(PipelineConfig(), None, [p, f])
    assert fr.run(**_KW) == "CLAUDE-RESULT"
    assert slept == []


def test_no_output_codex_failure_now_genuinely_falls_back_end_to_end(tmp_path, monkeypatch):
    """End-to-end regression test for the real bug: before this fix, CodexRunner._invoke's "no
    output at all" path (the exact shape a moderation flag or credits exhaustion takes when it
    fires immediately) was NOT retryable, so a configured fallback backend was never attempted at
    all -- the whole run died on the first hit. Drives the REAL CodexRunner (not the duck-typed
    _Fake) through FallbackRunner to prove the fix holds at the level a real pipeline run sees, not
    just at the unit level tested in test_codex.py."""
    import argo.runner as runner_mod
    from argo.ledger import Ledger

    class _FakeProc:
        def __init__(self, stdout="", stderr="", returncode=0):
            self.stdout, self.stderr, self.returncode = stdout, stderr, returncode

    ledger = Ledger(tmp_path / "l.sqlite")
    codex = runner_mod.CodexRunner(PipelineConfig(runner="codex"), ledger)
    codex._resolved_bin = "codex"  # avoid a PATH dependency
    stderr = "ERROR: This content was flagged for possible cybersecurity risk."
    monkeypatch.setattr(codex, "_exec", lambda *a, **k: _FakeProc("", stderr, 1))
    monkeypatch.setattr(runner_mod.time, "sleep", lambda s: None)  # don't actually wait in tests

    claude = _Fake("headless", _return("CLAUDE-RESULT"))
    fr = FallbackRunner(PipelineConfig(), ledger, [codex, claude])
    result = fr.run(prompt="p", run_dir=tmp_path, work_dir=tmp_path / "work",
                    model="m", stage="audit", run_id="R")
    assert result == "CLAUDE-RESULT"           # fell all the way through to the real fallback
    assert claude.calls == 1
    ledger.close()


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


def test_build_runner_multi_account_gemini_chain(tmp_path):
    """Unlike Claude/Codex's directory-based accounts, gemini_accounts holds raw GEMINI_API_KEY
    VALUES (a deliberate deviation -- see PipelineConfig's docstring) -- assert the chain expands
    one GeminiRunner per key, each with that key installed on its own config."""
    from argo.ledger import Ledger
    from argo.runner import GeminiRunner
    ledger = Ledger(tmp_path / "l.sqlite")
    try:
        cfg = PipelineConfig(runner="gemini", gemini_accounts=["key-a", "key-b"])
        r = build_runner(cfg, ledger)
        assert isinstance(r, FallbackRunner) and len(r._runners) == 2
        assert all(isinstance(x, GeminiRunner) for x in r._runners)
        assert [x.config.gemini_api_key for x in r._runners] == ["key-a", "key-b"]
    finally:
        ledger.close()


def test_pipeline_config_to_dict_redacts_gemini_secrets():
    """gemini_api_key/gemini_accounts carry REAL secret material (the credential lives in the
    field value itself, unlike claude_config_dir/codex_home which are just directory paths) --
    every PipelineConfig field is serialized verbatim into runs/<id>/config.json, so a live key
    must never round-trip into that file in the clear."""
    from argo.config import pipeline_config_to_dict
    cfg = PipelineConfig(runner="gemini", gemini_api_key="sk-live-secret-value",
                         gemini_accounts=["sk-a", "sk-b"])
    d = pipeline_config_to_dict(cfg)
    blob = str(d)
    assert "sk-live-secret-value" not in blob
    assert "sk-a" not in blob and "sk-b" not in blob
    assert d["gemini_api_key"] == "<redacted>"
    assert d["gemini_accounts"] == ["<redacted>", "<redacted>"]
    # a config with no key set stays falsy, not spuriously "<redacted>"
    empty = pipeline_config_to_dict(PipelineConfig(runner="gemini"))
    assert empty["gemini_api_key"] is None and empty["gemini_accounts"] == []


def test_build_runner_multi_account_claude_api_key_chain(tmp_path):
    """claude_api_keys is a SEPARATE, key-based chaining mechanism from claude_accounts (directory
    logins) -- mirrors gemini_accounts' shape exactly."""
    from argo.ledger import Ledger
    from argo.runner import HeadlessClaudeRunner
    ledger = Ledger(tmp_path / "l.sqlite")
    try:
        cfg = PipelineConfig(runner="headless", claude_api_keys=["sk-ant-a", "sk-ant-b"])
        r = build_runner(cfg, ledger)
        assert isinstance(r, FallbackRunner) and len(r._runners) == 2
        assert all(isinstance(x, HeadlessClaudeRunner) for x in r._runners)
        assert [x.config.claude_api_key for x in r._runners] == ["sk-ant-a", "sk-ant-b"]
        assert all(x.config.claude_config_dir is None for x in r._runners)
    finally:
        ledger.close()


def test_build_runner_multi_account_codex_api_key_chain(tmp_path):
    """codex_api_keys mirrors codex_accounts' shape but chains by key, not directory -- each
    resulting CodexRunner's codex_home stays unset (the real CODEX_HOME resolution happens lazily
    at _invoke time via the bootstrap helper, not here)."""
    from argo.ledger import Ledger
    from argo.runner import CodexRunner
    ledger = Ledger(tmp_path / "l.sqlite")
    try:
        cfg = PipelineConfig(runner="codex", codex_api_keys=["sk-oai-a", "sk-oai-b"])
        r = build_runner(cfg, ledger)
        assert isinstance(r, FallbackRunner) and len(r._runners) == 2
        assert all(isinstance(x, CodexRunner) for x in r._runners)
        assert [x.config.codex_api_key for x in r._runners] == ["sk-oai-a", "sk-oai-b"]
        assert all(x.config.codex_home is None for x in r._runners)
    finally:
        ledger.close()


def test_expand_backend_claude_accounts_win_over_claude_api_keys(tmp_path):
    """Directory-based claude_accounts wins over key-based claude_api_keys when both are set --
    avoids a Cartesian-product chain-expansion nobody asked for."""
    from argo.ledger import Ledger
    from argo.runner import HeadlessClaudeRunner
    ledger = Ledger(tmp_path / "l.sqlite")
    try:
        cfg = PipelineConfig(runner="headless", claude_accounts=["/acct/a", "/acct/b"],
                             claude_api_keys=["sk-ant-a", "sk-ant-b"])
        r = build_runner(cfg, ledger)
        assert isinstance(r, FallbackRunner) and len(r._runners) == 2
        assert [x.config.claude_config_dir for x in r._runners] == ["/acct/a", "/acct/b"]
        assert all(x.config.claude_api_key is None for x in r._runners)
    finally:
        ledger.close()


def test_expand_backend_codex_accounts_win_over_codex_api_keys(tmp_path):
    from argo.ledger import Ledger
    from argo.runner import CodexRunner
    ledger = Ledger(tmp_path / "l.sqlite")
    try:
        cfg = PipelineConfig(runner="codex", codex_accounts=["/cdx/a", "/cdx/b"],
                             codex_api_keys=["sk-oai-a", "sk-oai-b"])
        r = build_runner(cfg, ledger)
        assert isinstance(r, FallbackRunner) and len(r._runners) == 2
        assert [x.config.codex_home for x in r._runners] == ["/cdx/a", "/cdx/b"]
        assert all(x.config.codex_api_key is None for x in r._runners)
    finally:
        ledger.close()


def test_expand_backend_scalar_codex_home_wins_without_repeating_key_chain(tmp_path):
    from argo.ledger import Ledger
    from argo.runner import CodexRunner
    ledger = Ledger(tmp_path / "l.sqlite")
    try:
        cfg = PipelineConfig(runner="codex", codex_home="/cdx/explicit",
                             codex_api_keys=["sk-oai-a", "sk-oai-b"])
        r = build_runner(cfg, ledger)
        assert isinstance(r, CodexRunner)
        assert r.config.codex_home == "/cdx/explicit"
        assert r.config.codex_api_key is None and r.config.codex_api_keys == []
    finally:
        ledger.close()


def test_expand_backend_claude_accounts_clear_all_key_credentials(tmp_path):
    from argo.ledger import Ledger
    ledger = Ledger(tmp_path / "l.sqlite")
    try:
        cfg = PipelineConfig(runner="headless", claude_accounts=["/acct/a", "/acct/b"],
                             claude_api_key="sk-ant-scalar",
                             claude_api_keys=["sk-ant-a", "sk-ant-b"])
        r = build_runner(cfg, ledger)
        assert isinstance(r, FallbackRunner)
        assert all(x.config.claude_api_key is None for x in r._runners)
        assert all(x.config.claude_api_keys == [] for x in r._runners)
    finally:
        ledger.close()


def test_pipeline_config_to_dict_redacts_claude_and_codex_api_keys():
    from argo.config import pipeline_config_to_dict
    cfg = PipelineConfig(runner="headless", claude_api_key="sk-ant-live",
                         claude_api_keys=["sk-ant-a", "sk-ant-b"],
                         codex_api_key="sk-oai-live", codex_api_keys=["sk-oai-a", "sk-oai-b"])
    d = pipeline_config_to_dict(cfg)
    blob = str(d)
    for secret in ("sk-ant-live", "sk-ant-a", "sk-ant-b", "sk-oai-live", "sk-oai-a", "sk-oai-b"):
        assert secret not in blob
    assert d["claude_api_key"] == "<redacted>"
    assert d["claude_api_keys"] == ["<redacted>", "<redacted>"]
    assert d["codex_api_key"] == "<redacted>"
    assert d["codex_api_keys"] == ["<redacted>", "<redacted>"]


def test_pipeline_config_from_dict_never_resurrects_a_redacted_secret():
    """Regression test for a real bug found during this session's design pass:
    pipeline_config_from_dict previously did no _SECRET_FIELDS handling at all, so loading a
    written config.json back would set e.g. cfg.gemini_api_key = "<redacted>" (a truthy string)
    instead of None -- GeminiRunner._invoke would then inject GEMINI_API_KEY=<redacted> into the
    subprocess, silently clobbering any real ambient key. Round-trips all 6 secret fields
    (scalar + list) through write -> load and asserts every one comes back unset, never the
    literal sentinel string."""
    from argo.config import pipeline_config_from_dict, pipeline_config_to_dict
    cfg = PipelineConfig(runner="gemini", gemini_api_key="sk-g", gemini_accounts=["sk-g1", "sk-g2"],
                         claude_api_key="sk-c", claude_api_keys=["sk-c1", "sk-c2"],
                         codex_api_key="sk-x", codex_api_keys=["sk-x1", "sk-x2"])
    written = pipeline_config_to_dict(cfg)
    loaded = pipeline_config_from_dict(written)
    assert loaded.gemini_api_key is None and loaded.gemini_accounts == []
    assert loaded.claude_api_key is None and loaded.claude_api_keys == []
    assert loaded.codex_api_key is None and loaded.codex_api_keys == []
    # never the literal sentinel, for good measure
    for value in (loaded.gemini_api_key, loaded.claude_api_key, loaded.codex_api_key,
                 *loaded.gemini_accounts, *loaded.claude_api_keys, *loaded.codex_api_keys):
        assert value != "<redacted>"
    # a config with real values unset stays unset through the same round trip (no false positive)
    empty_loaded = pipeline_config_from_dict(pipeline_config_to_dict(PipelineConfig(runner="mock")))
    assert empty_loaded.gemini_api_key is None and empty_loaded.claude_api_key is None
    assert empty_loaded.codex_api_key is None


def test_runtime_credentials_are_redacted_and_not_resurrected():
    from argo.config import pipeline_config_from_dict, pipeline_config_to_dict
    written = pipeline_config_to_dict(PipelineConfig(
        runtime_credentials={"username": "alice", "password": "correct-horse"}))
    assert written["runtime_credentials"] == {
        "username": "<redacted>", "password": "<redacted>"}
    assert "correct-horse" not in str(written)
    assert pipeline_config_from_dict(written).runtime_credentials == {}
