"""runner=mistral-vibe: headless Vibe CLI under an isolated, Argo-written config
(argo/mistral_vibe.py). Config envelope, command/env, output+export parsing, exit-code mapping,
auth, OSINT refusal and key hygiene. The CLI is faked; the real envelope was captured from
mistral-vibe 3.1.0 on 2026-11-06."""

import json
import os
import subprocess
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
    cfg = tomllib.loads(vibe_config_toml(tmp_path / "repo", allow_write=True,
                                         work_dir=tmp_path / "work"))
    assert cfg["outside_workdir"] == "deny"
    assert cfg["enabled_tools"] == ["read_file", "argo_write_file"]
    assert "write_file" in cfg["disabled_tools"]
    assert cfg["enable_mcp"] is True
    assert cfg["mcp_servers"][0]["name"] == "argo"
    assert cfg["mcp_servers"][0]["transport"] == "stdio"
    assert cfg["mcp_servers"][0]["args"][-2:] == ["--work-dir", str((tmp_path / "work").resolve())]
    for off in ("bash", "powershell", "git_bash", "web_fetch", "web_search", "task", "edit"):
        assert off in cfg["disabled_tools"]
    for shell in ("bash", "powershell", "git_bash"):
        assert cfg["tools"][shell]["permission"] == "never"
    grant = cfg["tools"]["read_file"]["allowlist"]
    assert len(grant) == 1 and grant[0].startswith("vibe-path:directory_recursive:")
    assert "allowlist" not in cfg["tools"]["argo_write_file"]         # writer gets scratch only
    for flag in ("enable_subagents", "enable_connectors", "include_project_context",
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
                                                                                 "argo_write_file"]
    assert cmd[cmd.index("--max-turns") + 1] == "40"
    assert cmd[cmd.index("--model") + 1] == MISTRAL_VIBE_DEFAULT
    assert KEY not in " ".join(cmd) and seen["prompt"] == "audit"
    assert seen["env"]["MISTRAL_API_KEY"] == KEY
    home = seen["env"]["VIBE_HOME"]
    assert ".argo_sessions" in home and not home.startswith(str(tmp_path / "work" / "audit"))
    from pathlib import Path
    toml = (Path(home) / "config.toml").read_text()
    assert KEY not in toml
    assert raw["text"] == "Done. Generated files: out.md"
    r.ledger.close()


def _mcp_write_from_vibe_config(tmp_path, work, name, content):
    work.mkdir(parents=True, exist_ok=True)
    cfg = tomllib.loads(vibe_config_toml(None, allow_write=True, work_dir=work))
    server = cfg["mcp_servers"][0]
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo":
                    {"name": "test-vibe", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "write_file", "arguments": {"path": name, "content": content}}},
    ]
    env = {**server["env"], "PATH": os.environ.get("PATH", ""),
           "USERPROFILE": str(tmp_path)}
    proc = subprocess.run([server["command"], *server["args"]], input="".join(
        json.dumps(request) + "\n" for request in requests), text=True, capture_output=True,
        cwd=server["cwd"], env=env, timeout=20, check=True)
    replies = [json.loads(line) for line in proc.stdout.splitlines()]
    assert [reply["id"] for reply in replies] == [1, 2, 3]
    assert replies[1]["result"]["tools"][0]["name"] == "write_file"
    return replies[2]["result"]


def test_vibe_mcp_writer_writes_valid_json_unchanged(tmp_path):
    work = tmp_path / "work"
    content = '{"brief": "line one\\nline two", "quote": "say \\"hi\\""}'
    result = _mcp_write_from_vibe_config(tmp_path, work, "scope.JSON", content)
    assert "isError" not in result
    assert (work / "scope.JSON").read_text(encoding="utf-8") == content
    assert not list(work.glob("*.argo-tmp"))


@pytest.mark.parametrize("name,content", [
    ("scope.json", '{"brief": "first line\nsecond line"}'),
    ("scope.JSON", '{"brief": "say "hi""}'),
])
def test_vibe_mcp_writer_rejects_bad_json_before_write_and_keeps_previous_file(
        tmp_path, name, content):
    work = tmp_path / "work"
    work.mkdir()
    target = work / name
    target.write_text('{"previous": true}', encoding="utf-8")

    result = _mcp_write_from_vibe_config(tmp_path, work, name, content)
    message = result["content"][0]["text"]
    assert result["isError"] is True
    assert "not written" in message and "invalid JSON" in message
    assert "line 1, column" in message and "Escape inner double quotes" in message
    assert "\\n" in message
    assert len(message) < 400
    assert target.read_text(encoding="utf-8") == '{"previous": true}'
    assert not list(work.glob("*.argo-tmp"))


def test_vibe_mcp_json_error_excerpt_is_sanitized(tmp_path):
    work = tmp_path / "work"
    secret = "PRIVATE_BRIEF_SENTINEL_23984"
    result = _mcp_write_from_vibe_config(
        tmp_path, work, "scope.json", '{"brief": "' + secret + '\ncontinued"}')
    message = result["content"][0]["text"]
    assert result["isError"] is True
    assert "Invalid control character" in message
    assert secret not in message
    assert "*" in message
    assert len(message) < 400
    assert not (work / "scope.json").exists()


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
    monkeypatch.setattr(provenance.shutil, "which", lambda name: None)
    assert provenance.cli_versions()["vibe"] == "vibe 9.9.9"


def test_stored_auth_bypasses_key_resolution_and_sanitizes_child(tmp_path, monkeypatch):
    r = _runner(tmp_path, mistral_vibe_api_key=None, mistral_api_key="other-backend-key")
    object.__setattr__(r.config, "mistral_vibe_auth", "stored")
    for name in ("MISTRAL_API_KEY", "ARGO_MISTRAL_API_KEY", "ARGO_MISTRAL_VIBE_API_KEY"):
        monkeypatch.setenv(name, "must-not-reach-vibe")
    for name in ("VIBE_ENABLED_TOOLS", "VIBE_CONFIG_FILE", "VIBE_AGENT", "VIBE_ADMIN_CONFIG"):
        monkeypatch.setenv(name, "hostile-policy")
    monkeypatch.setenv("SSL_CERT_FILE", "approved-cert")
    monkeypatch.setattr(r, "_api_key", lambda: pytest.fail("stored must not resolve keys"))
    seen = _fake(r, monkeypatch, export=EXPORT_OK)
    _invoke(r, tmp_path)
    assert not {"MISTRAL_API_KEY", "ARGO_MISTRAL_API_KEY", "ARGO_MISTRAL_VIBE_API_KEY"} & seen["env"].keys()
    assert {k for k in seen["env"] if k.startswith("VIBE_")} == {"VIBE_HOME"}
    assert seen["env"]["SSL_CERT_FILE"] == "approved-cert"
    r.ledger.close()


@pytest.mark.parametrize("source", range(5))
def test_complete_legacy_key_precedence(tmp_path, monkeypatch, source):
    values = ["config-vibe", "env-vibe", "config-api", "env-api", "env-mistral"]
    r = _runner(tmp_path, mistral_vibe_api_key=values[0] if source == 0 else None,
                mistral_api_key=values[2] if source <= 2 else None)
    for index, name in ((1, "ARGO_MISTRAL_VIBE_API_KEY"), (3, "ARGO_MISTRAL_API_KEY"),
                        (4, "MISTRAL_API_KEY")):
        if source <= index:
            monkeypatch.setenv(name, values[index])
    assert r._api_key() == values[source]
    r.ledger.close()


def test_oidc_override_is_rejected_before_launch(tmp_path, monkeypatch):
    r = _runner(tmp_path)
    monkeypatch.setenv("VIBE_CLI_OIDC_ENABLED", "true")
    seen = _fake(r, monkeypatch, export=EXPORT_OK)
    with pytest.raises(RunnerError) as exc:
        _invoke(r, tmp_path)
    assert exc.value.failure_kind == "credential_bootstrap"
    assert "cmd" not in seen
    r.ledger.close()


def test_stale_home_dotenv_and_agents_are_not_imported(tmp_path, monkeypatch):
    r = _runner(tmp_path)
    home = tmp_path / "work" / ".argo_sessions" / "audit.vibe.x" / "home"
    home.mkdir(parents=True)
    (home / ".env").write_text("MISTRAL_API_KEY=stale-key")
    (home / "agents").mkdir()
    (home / "agents" / "default.toml").write_text('enabled_tools = ["bash"]')
    seen = _fake(r, monkeypatch, export=EXPORT_OK)
    _invoke(r, tmp_path)
    from pathlib import Path
    fresh_home = Path(seen["env"]["VIBE_HOME"])
    assert fresh_home != home
    assert not (fresh_home / ".env").exists()
    assert not (fresh_home / "agents").exists()
    r.ledger.close()


def _run(r, tmp_path):
    return r.run(prompt="audit", run_dir=tmp_path / "run", work_dir=tmp_path / "work" / "audit",
                 model=MISTRAL_VIBE_DEFAULT, stage="audit", run_id="R", label="x")


@pytest.mark.parametrize("diagnostic,kind,retryable", [
    ("429 Too many requests", "rate_limited", True),
    ("429 monthly Vibe allowance exhausted", "credits_exhausted", True),
    ("402 API budget exhausted", "credits_exhausted", True),
    ("403 Forbidden by organization policy", "invalid_request", False),
    ("403 Forbidden", "unknown_retryable", True),
    ("model_not_found: model unavailable", "model_unavailable", True),
])
@pytest.mark.parametrize("channel", ["stderr", "export"])
def test_run_classifies_vendor_diagnostics_without_exposing_them(
        tmp_path, monkeypatch, diagnostic, kind, retryable, channel):
    unknown_secret = "opaque-unknown-vendor-secret-782"
    r = _runner(tmp_path, mistral_vibe_api_key=None)
    object.__setattr__(r.config, "mistral_vibe_auth", "stored")
    message = diagnostic + " " + unknown_secret
    export = {**EXPORT_OK, "outcome": "error", "exit_code": 2,
              "error": {"message": message} if channel == "export" else None}
    _fake(r, monkeypatch, rc=2, stderr=message if channel == "stderr" else "", export=export)
    with pytest.raises(RunnerError) as exc:
        _run(r, tmp_path)
    assert exc.value.failure_kind == kind
    assert exc.value.retryable is retryable
    assert unknown_secret not in str(exc.value)
    row = json.loads((tmp_path / "run" / "llm_log.jsonl").read_text())
    assert row["failure_kind"] == kind
    assert row["mistral_vibe_auth"] == "stored"
    assert row["auth_source"] == "unknown"
    assert unknown_secret not in json.dumps(row)
    assert r.ledger._conn.execute("SELECT failure_kind FROM llm_calls").fetchone()[0] == kind
    r.ledger.close()


@pytest.mark.parametrize("change", [None, [], {"usage": []}, {"usage": {"input_tokens": "12", "output_tokens": 1}},
    {"usage": {"input_tokens": True, "output_tokens": 1}},
    {"usage": {"input_tokens": -1, "output_tokens": 1}}, {"steps": "4"},
    {"cost_usd": float("nan")}, {"cost_usd": float("inf")}, {"cost_usd": -0.1},
    {"outcome": "error"}, {"error": {"message": "vendor-secret"}}, {"config": []},
    {"config": {"models": []}}, {"exit_code": 2},
])
def test_exit_zero_rejects_malformed_export(tmp_path, monkeypatch, change):
    r = _runner(tmp_path)
    export = {**EXPORT_OK, **change} if isinstance(change, dict) else change
    _fake(r, monkeypatch, export=export)
    with pytest.raises(RunnerError) as exc:
        _invoke(r, tmp_path)
    assert exc.value.failure_kind == "invalid_request"
    assert "vendor-secret" not in str(exc.value)
    r.ledger.close()


@pytest.mark.parametrize("stdout", ["not json", "{}", '"text"', '[{"type":"message","role":"assistant","content":[{"type":"text","text":1}]}]'])
def test_exit_zero_rejects_malformed_stdout(tmp_path, monkeypatch, stdout):
    r = _runner(tmp_path)
    _fake(r, monkeypatch, export=EXPORT_OK, stdout=stdout)
    with pytest.raises(RunnerError) as exc:
        _invoke(r, tmp_path)
    assert exc.value.failure_kind == "invalid_request"
    r.ledger.close()


@pytest.mark.parametrize("rc", [2, 3])
def test_partial_failure_keeps_scratch_and_tolerates_missing_envelope(tmp_path, monkeypatch, rc):
    r = _runner(tmp_path)
    _fake(r, monkeypatch, rc=rc, stdout="broken", export=[])
    scratch = tmp_path / "work" / "audit"
    scratch.mkdir(parents=True)
    (scratch / "partial.json").write_text('{"findings": []}')
    with pytest.raises(RunnerError) as exc:
        _run(r, tmp_path)
    assert exc.value.retryable
    assert (scratch / "partial.json").exists()
    assert r.ledger.run_call_count("R") == 1
    r.ledger.close()


def test_malformed_failure_metadata_never_crashes_or_echoes_vendor_values(tmp_path, monkeypatch):
    r = _runner(tmp_path, mistral_vibe_api_key=None, mistral_vibe_auth="stored")
    _fake(r, monkeypatch, rc=2, stdout="UNKNOWN_SENTINEL", stderr="UNKNOWN_SENTINEL",
          export={"outcome": [], "config": {"models": [], "active_model": []},
                  "vibe_version": "UNKNOWN_SENTINEL", "usage": [], "cost_usd": "bad"})
    with pytest.raises(RunnerError) as exc:
        _run(r, tmp_path)
    assert "UNKNOWN_SENTINEL" not in str(exc.value)
    assert exc.value.retryable
    assert "UNKNOWN_SENTINEL" not in (tmp_path / "run" / "llm_log.jsonl").read_text()
    r.ledger.close()


def test_missing_stored_credentials_are_terminal_and_do_not_expose_diagnostics(tmp_path, monkeypatch):
    r = _runner(tmp_path, mistral_vibe_api_key=None, mistral_vibe_auth="stored")
    _fake(r, monkeypatch, rc=1, stdout="", stderr="Missing API key UNKNOWN_SENTINEL",
          export={"error": {"message": "Missing API key UNKNOWN_SENTINEL"}})
    with pytest.raises(RunnerError) as exc:
        _run(r, tmp_path)
    assert exc.value.failure_kind == "credential_bootstrap"
    assert not exc.value.retryable
    assert "vibe --setup" in str(exc.value) and "UNKNOWN_SENTINEL" not in str(exc.value)
    from argo.runner import _is_retryable
    assert not _is_retryable(exc.value)
    row = json.loads((tmp_path / "run" / "llm_log.jsonl").read_text())
    assert row["mistral_vibe_auth"] == "stored"
    assert row["failure_kind"] == "credential_bootstrap"
    assert row["cost_source"] == "unknown"
    assert "UNKNOWN_SENTINEL" not in json.dumps(row)
    r.ledger.close()


@pytest.mark.parametrize("diagnostic,kind", [
    ("429 monthly Vibe allowance exhausted", "credits_exhausted"),
    ("402 API budget exhausted", "credits_exhausted"),
    ("model_not_found: model unavailable", "model_unavailable"),
])
@pytest.mark.parametrize("channel", ["stderr", "export"])
def test_run_routes_terminal_backend_failure_to_explicit_fallback(
        tmp_path, monkeypatch, diagnostic, kind, channel):
    from datetime import datetime, timezone
    from unittest.mock import Mock
    from argo.runner import FallbackRunner, TERMINAL_FAILURE_KINDS, _COOLDOWN_BY_FAILURE_KIND

    cfg = PipelineConfig(runner="mistral-vibe", mistral_vibe_api_key=KEY,
                         runner_fallbacks=["mock"])
    ledger = Ledger(tmp_path / "l.sqlite")
    try:
        chain = build_runner(cfg, ledger)
        assert isinstance(chain, FallbackRunner)
        vibe, fallback = chain._runners
        assert isinstance(vibe, MistralVibeRunner)
        vibe._resolved_bin = "vibe"
        _fake(vibe, monkeypatch, rc=2,
              stderr=diagnostic if channel == "stderr" else "",
              export={**EXPORT_OK, "outcome": "error", "exit_code": 2,
                      "error": {"message": diagnostic} if channel == "export" else None})
        execute = Mock(wraps=vibe._exec)
        monkeypatch.setattr(vibe, "_exec", execute)
        next_run = Mock(return_value="FALLBACK-RESULT")
        monkeypatch.setattr(fallback, "run", next_run)

        before = datetime.now(timezone.utc)
        assert _run(chain, tmp_path) == "FALLBACK-RESULT"
        after = datetime.now(timezone.utc)
        assert kind in TERMINAL_FAILURE_KINDS  # still terminal for same-backend stage retries
        cooldown = _COOLDOWN_BY_FAILURE_KIND[kind]
        disabled_until = chain._disabled[0]
        assert disabled_until is not None
        assert before + cooldown <= disabled_until <= after + cooldown
        assert _run(chain, tmp_path) == "FALLBACK-RESULT"
        assert execute.call_count == 1  # subsequent calls skip the cooled-down Vibe backend
        assert next_run.call_count == 2
        assert next_run.call_args.kwargs["model"] == fallback.config.model_for("audit")
        assert ledger._conn.execute("SELECT failure_kind FROM llm_calls").fetchone()[0] == kind
    finally:
        ledger.close()


@pytest.mark.parametrize("diagnostic,kind", [
    ("Missing API key", "credential_bootstrap"),
    ("401 Unauthorized", "auth_failed"),
    ("403 Forbidden by organization policy", "invalid_request"),
])
def test_run_does_not_fallback_on_credentials_or_invalid_request(
        tmp_path, monkeypatch, diagnostic, kind):
    from unittest.mock import Mock
    from argo.runner import FallbackRunner

    r = _runner(tmp_path)
    _fake(r, monkeypatch, rc=2, stderr=diagnostic,
          export={**EXPORT_OK, "outcome": "error", "exit_code": 2})
    fallback = build_runner(PipelineConfig(runner="mock"), r.ledger)
    next_run = Mock(return_value="UNEXPECTED-FALLBACK")
    monkeypatch.setattr(fallback, "run", next_run)
    chain = FallbackRunner(r.config, r.ledger, [r, fallback])
    try:
        with pytest.raises(RunnerError) as exc:
            _run(chain, tmp_path)
        assert exc.value.failure_kind == kind
        assert exc.value.retryable is False
        next_run.assert_not_called()
        assert not chain._disabled
    finally:
        r.ledger.close()


@pytest.mark.parametrize("diagnostic,kind", [
    ("402 API budget exhausted", "credits_exhausted"),
    ("model_not_found: model unavailable", "model_unavailable"),
])
def test_recon_does_not_retry_vibe_terminal_backend_failure(
        tmp_path, monkeypatch, env, diagnostic, kind):
    from unittest.mock import Mock
    from argo.orchestrator import do_ingest
    from argo.runner import TERMINAL_FAILURE_KINDS
    from argo.stages import recon
    from conftest import BRIEF, REPO

    ctx = env()
    do_ingest(ctx, BRIEF, str(REPO))  # fixture-only setup, no real CLI
    r = _runner(tmp_path)
    _fake(r, monkeypatch, rc=2, stderr=diagnostic,
          export={**EXPORT_OK, "outcome": "error", "exit_code": 2})
    execute = Mock(wraps=r._exec)
    monkeypatch.setattr(r, "_exec", execute)
    ctx.runner = r
    try:
        with pytest.raises(RunnerError) as exc:
            recon.run(ctx)
        assert exc.value.failure_kind == kind
        assert exc.value.retryable is True  # eligible for an explicit cross-backend fallback
        assert kind in TERMINAL_FAILURE_KINDS
        assert execute.call_count == 1  # recon's same-backend retry must nevertheless stop
    finally:
        r.ledger.close()


def test_repeated_invocations_use_fresh_homes_without_deleting_readonly_logs(tmp_path, monkeypatch):
    import argo.mistral_vibe as mv
    from pathlib import Path
    r = _runner(tmp_path)
    seen = _fake(r, monkeypatch, export=EXPORT_OK)
    _invoke(r, tmp_path)
    first_home = Path(seen['env']['VIBE_HOME'])
    readonly_log = first_home / 'logs' / 'plugin-blob'
    readonly_log.parent.mkdir()
    readonly_log.write_text('immutable native Vibe cache')
    original = mv.shutil.rmtree
    def refuse_native_home_deletion(path, *args, **kwargs):
        if Path(path) == first_home:
            raise PermissionError('simulated Windows read-only plugin blob')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(mv.shutil, 'rmtree', refuse_native_home_deletion)
    _invoke(r, tmp_path)
    assert Path(seen['env']['VIBE_HOME']) != first_home
    assert readonly_log.exists()
    r.ledger.close()


@pytest.mark.parametrize("outcome,rc", [("deadline", 3), ("terminated", 3), ("length", 3),
    ("refusal", 3), ("infrastructure_failure", 2), ("aborted", 4)])
def test_native_vibe_stop_outcomes_are_preserved(tmp_path, monkeypatch, outcome, rc):
    r = _runner(tmp_path)
    _fake(r, monkeypatch, rc=rc, export={**EXPORT_OK, "outcome": outcome, "exit_code": rc})
    raw = _invoke(r, tmp_path)
    result = r.parse_envelope(raw, model="m", prompt_sha256="h", work_dir=tmp_path)
    assert result.is_error and result.stop_reason == outcome
    r.ledger.close()
