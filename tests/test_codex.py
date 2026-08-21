"""Codex backend: command-construction guardrails (the safety re-validation) + parsing/cost.

The Codex backend enforces "no network except research, repo never writable" via the OS **sandbox**
(`-s workspace-write` + an opt-in network config) rather than a tool allowlist. These tests are the
equivalent of the Claude `--disallowedTools` sandbox test.
"""

import subprocess
import threading
import time
from pathlib import Path

import pytest

import argo.runner as runner_mod
from argo.config import PipelineConfig, estimate_cost_usd
from argo.guardrails import session_policy
from argo.ledger import Ledger
from argo.runner import (CodexRunner, RunnerError, _CODEX_NETWORK_CFG, _scan_codex_tokens,
                         _codex_home_for_api_key, _ensure_codex_api_key_home, build_runner)


def _runner(tmp_path, **cfg):
    r = CodexRunner(PipelineConfig(runner="codex", **cfg), Ledger(tmp_path / "l.sqlite"))
    r._resolved_bin = "codex"   # avoid a PATH dependency in CI
    return r


def test_build_cmd_is_sandboxed_and_offline_for_audit(tmp_path):
    r = _runner(tmp_path)
    cmd = r._build_codex_cmd(model="m", policy=session_policy("audit"),
                             last_msg_file=tmp_path / "msg")
    # sandboxed, non-interactive (exec never prompts), reads prompt from stdin
    assert cmd[cmd.index("-s") + 1] == "workspace-write"
    assert "-a" not in cmd                          # `exec` rejects the interactive approval flag
    assert cmd[-1] == "-" and "--skip-git-repo-check" in cmd and "--ephemeral" in cmd
    # NEVER a sandbox-escape
    assert "danger-full-access" not in cmd
    assert not any("dangerously" in t for t in cmd)
    # an audit stage gets NO network
    assert _CODEX_NETWORK_CFG not in cmd
    r.ledger.close()


def test_only_research_gets_network(tmp_path):
    r = _runner(tmp_path)
    research = r._build_codex_cmd(model="m", policy=session_policy("research"),
                                  last_msg_file=tmp_path / "m")
    assert _CODEX_NETWORK_CFG in research          # research re-enables egress…
    for stage in ("ingest", "recon", "audit", "validate", "report", "remediate"):
        cmd = r._build_codex_cmd(model="m", policy=session_policy(stage), last_msg_file=tmp_path / "m")
        assert _CODEX_NETWORK_CFG not in cmd        # …every other stage stays offline
        assert "danger-full-access" not in cmd
    r.ledger.close()


def test_oss_and_model_flags(tmp_path):
    r = _runner(tmp_path, codex_oss=True, codex_local_provider="ollama", codex_model="qwen2.5-coder")
    cmd = r._build_codex_cmd(model="m", policy=session_policy("audit"), last_msg_file=tmp_path / "m")
    assert "--oss" in cmd and cmd[cmd.index("--local-provider") + 1] == "ollama"
    assert cmd[cmd.index("-m") + 1] == "qwen2.5-coder"
    # default config omits --oss and -m (Codex uses its own configured model)
    plain = _runner(tmp_path)._build_codex_cmd(model="m", policy=session_policy("audit"),
                                               last_msg_file=tmp_path / "m")
    assert "--oss" not in plain and "-m" not in plain
    r.ledger.close()


def test_parse_envelope_tokens_cost_and_error(tmp_path):
    r = _runner(tmp_path)
    raw = {"returncode": 0, "text": "done",
           "stdout": '{"usage": {"input_tokens": 1000, "output_tokens": 500}}\nnot-json\n'}
    res = r.parse_envelope(raw, model="gpt-5-codex", prompt_sha256="h", work_dir=tmp_path)
    assert res.text == "done" and res.input_tokens == 1000 and res.output_tokens == 500
    assert res.cost_usd > 0 and res.is_error is False
    # non-zero exit -> recoverable error flag
    assert r.parse_envelope({"returncode": 1, "text": "", "stdout": ""},
                            model="m", prompt_sha256="h", work_dir=tmp_path).is_error is True
    r.ledger.close()


def test_scan_tokens_and_cost_estimate():
    assert _scan_codex_tokens('{"input_tokens": 10, "output_tokens": 7}') == (10, 7)
    assert _scan_codex_tokens("garbage\n{not json}") == (0, 0)
    assert estimate_cost_usd("gpt-5-codex", 1_000_000, 0) == 1.25       # known model
    assert estimate_cost_usd("qwen2.5-coder", 1_000_000, 1_000_000) == 0.0  # OSS/local -> $0
    assert estimate_cost_usd(None, 100, 100) == 0.0


def test_build_runner_dispatches_codex(tmp_path):
    r = build_runner(PipelineConfig(runner="codex"), Ledger(tmp_path / "l.sqlite"))
    assert isinstance(r, CodexRunner)
    r.ledger.close()


def test_model_for_codex(monkeypatch):
    import argo.config as cfgmod
    # explicit model wins
    assert PipelineConfig(runner="codex", codex_model="o3").model_for("audit") == "o3"
    # else the Codex CLI's configured default is detected and used (logged/costed as the real model)
    monkeypatch.setattr(cfgmod, "_codex_default_model", lambda: "gpt-5.5")
    assert PipelineConfig(runner="codex").model_for("audit") == "gpt-5.5"
    # else the "codex-default" label
    monkeypatch.setattr(cfgmod, "_codex_default_model", lambda: None)
    assert PipelineConfig(runner="codex").model_for("audit") == "codex-default"


def test_calibrated_actually_sets_codex_model():
    """calibrated() used to call with_stage_model("audit", OPUS), a no-op for runner=="codex"
    (model_for() ignores stage_models for codex) -- so calibration silently did nothing on Codex.
    Fixed to set codex_model=CODEX_TOP directly."""
    from argo.config import CODEX_TOP
    cfg = PipelineConfig(runner="codex").calibrated()
    assert cfg.codex_model == CODEX_TOP
    assert cfg.model_for("audit") == CODEX_TOP


# --------------------------------------------------------------- failure classification (_invoke)
class _FakeProc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


def _invoke(r, tmp_path, **overrides):
    kw = dict(prompt="p", work_dir=tmp_path, model="m", repo_dir=None,
              allowed=["Read"], disallowed=[], policy=None, stage="audit",
              run_id="R", label="x", timeout_s=5)
    kw.update(overrides)
    return r._invoke(**kw)


def test_invoke_timeout_is_now_retryable(tmp_path, monkeypatch):
    """A genuine hang-then-kill is not a deterministic failure -- the same call could well succeed
    on a retry. Before this fix it was NOT marked retryable, so a single timeout killed the whole
    run with no fallback attempt, even when one was configured."""
    r = _runner(tmp_path)

    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd=["codex"], timeout=5)

    monkeypatch.setattr(r, "_exec", _boom)
    with pytest.raises(RunnerError) as exc_info:
        _invoke(r, tmp_path)
    assert exc_info.value.retryable is True
    assert exc_info.value.failure_kind == "timeout"
    r.ledger.close()


def test_invoke_no_output_moderation_flag_is_classified_and_retryable(tmp_path, monkeypatch):
    """The real observed shape (codex-moderation-cybersecurity-flag campaign notes): the
    classifier firing before any tool call ran produces no last-message file and no stdout --
    structurally identical to credits exhaustion, distinguishable only by the stderr text. Before
    this fix, ANY "no output at all" failure was NOT retryable, so a configured fallback backend
    was never even attempted on exactly the failure shape fallback exists for."""
    r = _runner(tmp_path)
    stderr = ("ERROR: This content was flagged for possible cybersecurity risk. If this seems "
              "wrong, try rephrasing your request. To get authorized for security work, join the "
              "Trusted Access for Cyber program: https://chatgpt.com/cyber")
    monkeypatch.setattr(r, "_exec", lambda *a, **k: _FakeProc("", stderr, 1))
    with pytest.raises(RunnerError) as exc_info:
        _invoke(r, tmp_path)
    assert exc_info.value.retryable is True
    assert exc_info.value.failure_kind == "moderation_flagged"
    r.ledger.close()


def test_invoke_no_output_credits_exhausted_is_classified_and_retryable(tmp_path, monkeypatch):
    r = _runner(tmp_path)
    stderr = "ERROR: Your workspace is out of credits. Please contact your administrator."
    monkeypatch.setattr(r, "_exec", lambda *a, **k: _FakeProc("", stderr, 1))
    with pytest.raises(RunnerError) as exc_info:
        _invoke(r, tmp_path)
    assert exc_info.value.retryable is True
    assert exc_info.value.failure_kind == "credits_exhausted"
    r.ledger.close()


def test_invoke_no_output_unrecognized_text_is_still_retryable_with_unknown_kind(tmp_path, monkeypatch):
    """An unrecognized "no output" failure still defaults to retryable -- matching the existing,
    already-established philosophy for hint-less Codex failures (see _NO_HINT_RETRY_COOLDOWN's own
    reasoning): empirically more often a transient flake than something permanent, and a wasted
    retry costs ~0 tokens either way."""
    r = _runner(tmp_path)
    monkeypatch.setattr(r, "_exec", lambda *a, **k: _FakeProc("", "some unrelated startup error", 1))
    with pytest.raises(RunnerError) as exc_info:
        _invoke(r, tmp_path)
    assert exc_info.value.retryable is True
    assert exc_info.value.failure_kind == "unknown_retryable"
    r.ledger.close()


def test_api_and_cli_codex_config_passthrough(tmp_path):
    # API: RunConfig -> PipelineConfig mapping
    from server.jobs import JobManager
    from server.schemas import RunConfig, RunRequest
    jm = JobManager(PipelineConfig(runs_dir=tmp_path / "runs", ledger_path=tmp_path / "l.sqlite"))
    cfg = jm._config_for(RunRequest(brief="b", repo="r", config=RunConfig(
        runner="codex", codex_model="o3", codex_oss=True, codex_local_provider="ollama",
        codex_api_key="sk-oai-api-test")))
    assert cfg.runner == "codex" and cfg.codex_model == "o3"
    assert cfg.codex_oss is True and cfg.codex_local_provider == "ollama"
    assert cfg.codex_api_key == "sk-oai-api-test"
    # CLI: _build_config passthrough (single value + comma-split multi-account list)
    from argo.cli import _build_config
    c2 = _build_config("codex", None, False, None, 3, tmp_path / "runs", "happy",
                       codex_model="gpt-5-codex", codex_oss=True, codex_local_provider="lmstudio",
                       codex_api_key="sk-oai-cli-test", codex_api_keys="sk-a,sk-b")
    assert c2.runner == "codex" and c2.codex_model == "gpt-5-codex" and c2.codex_local_provider == "lmstudio"
    assert c2.codex_api_key == "sk-oai-cli-test"
    assert c2.codex_api_keys == ["sk-a", "sk-b"]


# --------------------------------------------------------------- API-key bootstrap (Codex only --
# unlike Claude/Gemini, a bare ambient OPENAI_API_KEY does NOT authenticate `codex exec`; a real,
# stateful `codex login --with-api-key` bootstrap into a dedicated CODEX_HOME is required)

def test_codex_home_for_api_key_hash_never_contains_literal_key(tmp_path):
    home = _codex_home_for_api_key("sk-super-secret-value", cache_root=tmp_path)
    assert "sk-super-secret-value" not in str(home)
    # same key -> same dir (caching/reuse depends on this)
    assert _codex_home_for_api_key("sk-super-secret-value", cache_root=tmp_path) == home
    # different key -> different dir
    assert _codex_home_for_api_key("sk-a-totally-different-key", cache_root=tmp_path) != home


def test_ensure_codex_api_key_home_pipes_key_via_stdin_not_argv(tmp_path, monkeypatch):
    calls = []
    def fake_run(args, *, codex_home, input_text=None, timeout=30):
        calls.append((list(args), input_text))
        if args[1:] == ["login", "status"]:
            return subprocess.CompletedProcess(args, 1, stdout="Not logged in", stderr="")
        return subprocess.CompletedProcess(args, 0, stdout="Logged in", stderr="")
    monkeypatch.setattr(runner_mod, "_run_codex_cli", fake_run)
    _ensure_codex_api_key_home("sk-secret-argv-test", codex_bin="codex", cache_root=tmp_path)
    login_calls = [c for c in calls if c[0][1:] == ["login", "--with-api-key"]]
    assert len(login_calls) == 1
    args, input_text = login_calls[0]
    assert "sk-secret-argv-test" not in args           # never in argv
    assert input_text == "sk-secret-argv-test"          # only ever via stdin


def test_ensure_codex_api_key_home_bootstraps_once_then_reuses(tmp_path, monkeypatch):
    status_calls = {"n": 0}
    login_calls = {"n": 0}
    def fake_run(args, *, codex_home, input_text=None, timeout=30):
        if args[1:] == ["login", "status"]:
            status_calls["n"] += 1
            already = status_calls["n"] > 1   # not logged in on the first check, logged in after
            return subprocess.CompletedProcess(args, 0 if already else 1,
                                               stdout="Logged in" if already else "Not logged in")
        login_calls["n"] += 1
        return subprocess.CompletedProcess(args, 0, stdout="ok")
    monkeypatch.setattr(runner_mod, "_run_codex_cli", fake_run)
    home1 = _ensure_codex_api_key_home("sk-reuse-test", cache_root=tmp_path)
    home2 = _ensure_codex_api_key_home("sk-reuse-test", cache_root=tmp_path)
    assert home1 == home2
    assert login_calls["n"] == 1   # bootstrapped once, reused on the second call


def test_ensure_codex_api_key_home_raises_on_login_failure_without_leaking_key(tmp_path, monkeypatch):
    def fake_run(args, *, codex_home, input_text=None, timeout=30):
        if args[1:] == ["login", "status"]:
            return subprocess.CompletedProcess(args, 1, stdout="Not logged in")
        return subprocess.CompletedProcess(
            args, 1, stdout="", stderr="invalid sk-should-never-leak quota 429 rejected")
    monkeypatch.setattr(runner_mod, "_run_codex_cli", fake_run)
    with pytest.raises(RunnerError) as exc_info:
        _ensure_codex_api_key_home("sk-should-never-leak", cache_root=tmp_path)
    assert "sk-should-never-leak" not in str(exc_info.value)
    assert "<redacted>" in str(exc_info.value)
    assert exc_info.value.failure_kind == "credential_bootstrap"
    assert not exc_info.value.retryable


def test_ensure_codex_api_key_home_rejects_non_directory_cache_leaf(tmp_path):
    key = "sk-unsafe-cache-test"
    home = _codex_home_for_api_key(key, cache_root=tmp_path)
    home.write_text("not a directory", encoding="utf-8")
    with pytest.raises(RunnerError) as exc_info:
        _ensure_codex_api_key_home(key, cache_root=tmp_path)
    assert exc_info.value.failure_kind == "credential_bootstrap"


def test_codex_cli_key_options_offer_non_argv_environment_ingress():
    from argo.cli import CodexApiKeyOpt, CodexApiKeysOpt
    assert CodexApiKeyOpt.envvar == "ARGO_CODEX_API_KEY"
    assert CodexApiKeysOpt.envvar == "ARGO_CODEX_API_KEYS"


def test_ensure_codex_api_key_home_serializes_concurrent_bootstraps_for_the_same_key(tmp_path, monkeypatch):
    login_calls = {"n": 0}
    logged_in = {"ok": False}
    lock = threading.Lock()
    def fake_run(args, *, codex_home, input_text=None, timeout=30):
        if args[1:] == ["login", "status"]:
            return subprocess.CompletedProcess(
                args, 0 if logged_in["ok"] else 1,
                stdout="Logged in" if logged_in["ok"] else "Not logged in")
        with lock:
            login_calls["n"] += 1
        time.sleep(0.05)   # widen the race window so a real bug would actually be caught
        logged_in["ok"] = True
        return subprocess.CompletedProcess(args, 0, stdout="ok")
    monkeypatch.setattr(runner_mod, "_run_codex_cli", fake_run)
    threads = [threading.Thread(target=_ensure_codex_api_key_home,
                                kwargs={"key": "sk-concurrent-test", "cache_root": tmp_path})
              for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert login_calls["n"] == 1   # exactly one real login attempt despite 5 concurrent callers


def test_codex_runner_uses_bootstrapped_home_for_api_key(tmp_path, monkeypatch):
    r = _runner(tmp_path, codex_api_key="sk-runner-test")
    fake_home = tmp_path / "fake_codex_home"
    monkeypatch.setattr(runner_mod, "_ensure_codex_api_key_home",
                        lambda key, **kw: fake_home)
    captured = {}
    def fake_exec(cmd, prompt, cwd, timeout, env=None):
        captured["env"] = env
        return _FakeProc("", "boom", 1)
    monkeypatch.setattr(r, "_exec", fake_exec)
    with pytest.raises(RunnerError):
        _invoke(r, tmp_path)
    assert captured["env"]["CODEX_HOME"] == str(fake_home)
    r.ledger.close()


def test_codex_runner_explicit_codex_home_wins_over_api_key(tmp_path, monkeypatch):
    r = _runner(tmp_path, codex_home="/explicit/home", codex_api_key="sk-should-be-ignored")
    def fail_if_called(key, **kw):
        raise AssertionError("bootstrap should not be attempted when codex_home is explicit")
    monkeypatch.setattr(runner_mod, "_ensure_codex_api_key_home", fail_if_called)
    captured = {}
    def fake_exec(cmd, prompt, cwd, timeout, env=None):
        captured["env"] = env
        return _FakeProc("", "boom", 1)
    monkeypatch.setattr(r, "_exec", fake_exec)
    with pytest.raises(RunnerError):
        _invoke(r, tmp_path)
    import os as _os
    expected = _os.path.abspath(_os.path.expanduser("/explicit/home"))
    assert captured["env"]["CODEX_HOME"] == expected
    r.ledger.close()


def test_codex_runner_memoizes_bootstrap_across_invokes(tmp_path, monkeypatch):
    r = _runner(tmp_path, codex_api_key="sk-memoize-test")
    calls = {"n": 0}
    def fake_ensure(key, **kw):
        calls["n"] += 1
        return tmp_path / "home"
    monkeypatch.setattr(runner_mod, "_ensure_codex_api_key_home", fake_ensure)
    monkeypatch.setattr(r, "_exec", lambda *a, **k: _FakeProc("", "boom", 1))
    with pytest.raises(RunnerError):
        _invoke(r, tmp_path)
    with pytest.raises(RunnerError):
        _invoke(r, tmp_path)
    assert calls["n"] == 1   # bootstrapped once, memoized on the instance across both _invoke calls
    r.ledger.close()
