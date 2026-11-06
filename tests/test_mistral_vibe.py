"""runner=mistral-vibe: headless Vibe CLI under an isolated, Argo-written config
(argo/mistral_vibe.py). Config envelope, command/env, output+export parsing, exit-code mapping,
auth, OSINT refusal and key hygiene. The CLI is faked; the real envelope was captured from
mistral-vibe 3.1.0 on 2026-11-06."""

import json
import tomllib

import pytest

from argo.config import MISTRAL_VIBE_DEFAULT, PipelineConfig, pipeline_config_to_dict
from argo.guardrails import session_policy
from argo.ledger import Ledger
from argo.mistral_vibe import MistralVibeRunner, _final_text, vibe_config_toml
from argo.runner import RunnerError, build_runner

KEY = "mstrl_VIBE_SENTINEL_KEY_987654321"
FINAL = [{"type": "message", "role": "user", "content": [{"type": "text", "text": "prompt"}]},
         {"type": "reasoning", "text": "thinking"},
         {"type": "effect", "title": "file_system.read_file", "detail": {}},
         {"type": "message", "role": "assistant",
          "content": [{"type": "text", "text": "Done. Generated files: out.md"}]}]


class _P:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


@pytest.fixture(autouse=True)
def _no_ambient(monkeypatch):
    for v in ("ARGO_MISTRAL_VIBE_API_KEY", "ARGO_MISTRAL_API_KEY", "MISTRAL_API_KEY"):
        monkeypatch.delenv(v, raising=False)


def _runner(tmp_path, **cfg):
    cfg.setdefault("mistral_vibe_api_key", KEY)
    r = MistralVibeRunner(PipelineConfig(runner="mistral-vibe", **cfg), Ledger(tmp_path / "l.sqlite"))
    r._resolved_bin = "vibe"
    return r


def _fake(r, monkeypatch, *, rc=0, stdout=None, stderr="", export=None):
    seen = {}

    def fake_exec(cmd, prompt, cwd, timeout, env=None, **_kw):
        seen.update(cmd=cmd, env=env, prompt=prompt, cwd=cwd)
        exp = cmd[cmd.index("--output-dir") + 1]
        if export is not None:
            from pathlib import Path
            Path(exp).mkdir(parents=True, exist_ok=True)
            Path(exp, "export.json").write_text(json.dumps(export), encoding="utf-8")
        return _P(json.dumps(FINAL) if stdout is None else stdout, stderr, rc)
    monkeypatch.setattr(r, "_exec", fake_exec)
    return seen


def _invoke(r, tmp_path, stage="audit", allowed=("Read", "Grep", "Glob", "Write"), repo=True):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir(exist_ok=True)
    work = tmp_path / "work" / stage
    return r._invoke(prompt="audit", work_dir=work, model=MISTRAL_VIBE_DEFAULT,
                     repo_dir=repo_dir if repo else None, allowed=list(allowed), disallowed=[],
                     policy=session_policy(stage), stage=stage, run_id="R", label="x", timeout_s=300)


EXPORT_OK = {"outcome": "finished", "stop_reason": None, "error": None,
             "usage": {"input_tokens": 21147, "output_tokens": 438}, "cost_usd": 0.0082, "steps": 4,
             "exit_code": 0, "vibe_version": "3.1.0",
             "config": {"active_model": "", "models": {"mistral-medium-3.5":
                                                         {"name": "mistral-vibe-cli-latest"}}}}


# ---------------------------------------------------------------------------- config envelope
def test_config_grants_repo_read_only_and_denies_outside_writes(tmp_path):
    cfg = tomllib.loads(vibe_config_toml(tmp_path / "repo", allow_write=True))
    assert cfg["outside_workdir"] == "deny"
    assert cfg["enabled_tools"] == ["read_file", "write_file"]
    for off in ("bash", "powershell", "git_bash", "web_fetch", "web_search", "task", "edit"):
        assert off in cfg["disabled_tools"]
    for shell in ("bash", "powershell", "git_bash"):
        assert cfg["tools"][shell]["permission"] == "never"
    grant = cfg["tools"]["read_file"]["allowlist"]
    assert len(grant) == 1 and grant[0].startswith("vibe-path:directory_recursive:")
    assert "allowlist" not in cfg["tools"]["write_file"]              # repo never writable
    assert cfg["tools"]["write_file"]["outside_workdir"] == "deny"
    for flag in ("enable_mcp", "enable_subagents", "enable_connectors", "include_project_context",
                 "enable_background_processes", "enable_telemetry", "bypass_tool_permissions"):
        assert cfg[flag] is False


def test_config_without_write_permission(tmp_path):
    cfg = tomllib.loads(vibe_config_toml(tmp_path / "repo", allow_write=False))
    assert cfg["enabled_tools"] == ["read_file"]
    assert "write_file" in cfg["disabled_tools"]
    assert cfg["tools"]["write_file"]["permission"] == "never"


def test_windows_path_survives_toml_literally():
    raw = vibe_config_toml(None, True)
    assert "allowlist" not in raw.split("[tools.write_file]")[0].split("[tools.read_file]")[1]
    import argo.mistral_vibe as mv
    with pytest.raises(RunnerError):
        mv._toml_literal("C:\\it's\\bad")


# ---------------------------------------------------------------------------- routing / config
def test_build_runner_and_model_default(tmp_path):
    led = Ledger(tmp_path / "l.sqlite")
    assert isinstance(build_runner(PipelineConfig(runner="mistral-vibe"), led), MistralVibeRunner)
    led.close()
    cfg = PipelineConfig(runner="mistral-vibe")
    assert cfg.model_for("audit") == MISTRAL_VIBE_DEFAULT
    assert cfg.with_stage_model("audit", "devstral").model_for("audit") == "devstral"


def test_vibe_key_redacted_in_config():
    d = pipeline_config_to_dict(PipelineConfig(runner="mistral-vibe", mistral_vibe_api_key=KEY))
    assert KEY not in json.dumps(d)


def test_key_precedence(tmp_path, monkeypatch):
    r = _runner(tmp_path, mistral_vibe_api_key=None)
    monkeypatch.setenv("MISTRAL_API_KEY", "ambient")
    assert r._api_key() == "ambient"
    monkeypatch.setenv("ARGO_MISTRAL_API_KEY", "api")
    assert r._api_key() == "api"
    monkeypatch.setenv("ARGO_MISTRAL_VIBE_API_KEY", "vibe")
    assert r._api_key() == "vibe"
    r.ledger.close()


# ---------------------------------------------------------------------------- invocation
def test_command_env_and_isolated_home(tmp_path, monkeypatch):
    r = _runner(tmp_path, session_max_turns=40)
    seen = _fake(r, monkeypatch, export=EXPORT_OK)
    raw = _invoke(r, tmp_path)
    cmd = seen["cmd"]
    assert cmd[:4] == ["vibe", "-p", "--output", "json"]
    assert "--add-dir" not in cmd and "--auto-approve" not in cmd and "--trust" not in cmd
    assert cmd[cmd.index("--workdir") + 1] == str(tmp_path / "work" / "audit")
    assert [cmd[i + 1] for i, c in enumerate(cmd) if c == "--enabled-tools"] == ["read_file",
                                                                                 "write_file"]
    assert cmd[cmd.index("--max-turns") + 1] == "40"
    assert cmd[cmd.index("--model") + 1] == MISTRAL_VIBE_DEFAULT
    assert KEY not in " ".join(cmd) and seen["prompt"] == "audit"
    assert seen["env"]["MISTRAL_API_KEY"] == KEY
    home = seen["env"]["VIBE_HOME"]
    assert ".argo_sessions" in home and not home.startswith(str(tmp_path / "work" / "audit"))
    toml = (tmp_path / "work" / ".argo_sessions" / "audit.vibe.x" / "home" / "config.toml").read_text()
    assert KEY not in toml
    assert raw["text"] == "Done. Generated files: out.md"
    r.ledger.close()


def test_parse_envelope_usage_cost_and_served_alias(tmp_path, monkeypatch):
    r = _runner(tmp_path)
    _fake(r, monkeypatch, export=EXPORT_OK)
    raw = _invoke(r, tmp_path)
    res = r.parse_envelope(raw, model=MISTRAL_VIBE_DEFAULT, prompt_sha256="h",
                           work_dir=tmp_path / "work")
    assert (res.input_tokens, res.output_tokens, res.num_turns) == (21147, 438, 4)
    assert res.cost_usd == pytest.approx(0.0082) and res.cost_source == "provider_estimated"
    assert res.served_model is None and res.served_models == ("mistral-vibe-cli-latest",)
    assert res.is_error is False and res.stop_reason == "finished"
    r.ledger.close()


def test_limit_exit_is_recoverable_error(tmp_path, monkeypatch):
    r = _runner(tmp_path)
    _fake(r, monkeypatch, rc=3, export={**EXPORT_OK, "outcome": "turn_limit", "exit_code": 3})
    raw = _invoke(r, tmp_path)
    res = r.parse_envelope(raw, model="m", prompt_sha256="h", work_dir=tmp_path)
    assert res.is_error is True and res.stop_reason == "turn_limit"
    r.ledger.close()


def test_config_error_exit_is_not_retryable(tmp_path, monkeypatch):
    r = _runner(tmp_path)
    _fake(r, monkeypatch, rc=1, stdout="", stderr="Error: unknown model alias 'nope'")
    with pytest.raises(RunnerError) as ei:
        _invoke(r, tmp_path)
    assert ei.value.failure_kind == "invalid_request" and ei.value.retryable is False
    r.ledger.close()


def test_auth_failure_fails_fast_and_scrubs_key(tmp_path, monkeypatch):
    r = _runner(tmp_path)
    _fake(r, monkeypatch, rc=2, stdout="", stderr=f"401 Unauthorized for key {KEY}",
          export={**EXPORT_OK, "outcome": "error", "error": {"message": "Invalid API Key"}})
    with pytest.raises(RunnerError) as ei:
        _invoke(r, tmp_path)
    assert ei.value.failure_kind == "auth_failed" and KEY not in str(ei.value)
    r.ledger.close()


def test_stderr_is_scrubbed(tmp_path, monkeypatch):
    r = _runner(tmp_path)
    _fake(r, monkeypatch, stderr=f"debug {KEY}", export=EXPORT_OK)
    assert KEY not in _invoke(r, tmp_path)["stderr"]
    r.ledger.close()


def test_osint_stage_refused(tmp_path, monkeypatch):
    r = _runner(tmp_path)
    seen = _fake(r, monkeypatch, export=EXPORT_OK)
    with pytest.raises(RunnerError) as ei:
        _invoke(r, tmp_path, stage="corroborate")
    assert ei.value.failure_kind == "unsupported_stage_tool" and "cmd" not in seen
    r.ledger.close()


def test_missing_key_and_missing_binary(tmp_path, monkeypatch):
    r = _runner(tmp_path, mistral_vibe_api_key=None)
    _fake(r, monkeypatch, export=EXPORT_OK)
    with pytest.raises(RunnerError, match="needs a Mistral key"):
        _invoke(r, tmp_path)
    r.ledger.close()
    r2 = MistralVibeRunner(PipelineConfig(runner="mistral-vibe"), Ledger(tmp_path / "m.sqlite"),
                           vibe_bin="definitely-not-vibe-xyz")
    with pytest.raises(RunnerError, match="vibe CLI not found"):
        r2._bin()
    r2.ledger.close()


def test_final_text_variants():
    assert _final_text([]) == ""
    assert _final_text("garbage") == ""
    assert _final_text([{"type": "message", "role": "assistant", "content": "plain"}]) == "plain"


def test_provenance_records_vibe_version(monkeypatch):
    import subprocess
    from argo import provenance

    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 0, stdout=f"{cmd[0]} 9.9.9\n", stderr="")
    monkeypatch.setattr(provenance.subprocess, "run", fake_run)
    assert provenance.cli_versions()["vibe"] == "vibe 9.9.9"
