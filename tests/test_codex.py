"""Codex backend: command-construction guardrails (the safety re-validation) + parsing/cost.

The Codex backend enforces "no network except research, repo never writable" via the OS **sandbox**
(`-s workspace-write` + an opt-in network config) rather than a tool allowlist. These tests are the
equivalent of the Claude `--disallowedTools` sandbox test.
"""

from pathlib import Path

from argo.config import PipelineConfig, estimate_cost_usd
from argo.guardrails import session_policy
from argo.ledger import Ledger
from argo.runner import CodexRunner, _CODEX_NETWORK_CFG, _scan_codex_tokens, build_runner


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


def test_api_and_cli_codex_config_passthrough(tmp_path):
    # API: RunConfig -> PipelineConfig mapping
    from server.jobs import JobManager
    from server.schemas import RunConfig, RunRequest
    jm = JobManager(PipelineConfig(runs_dir=tmp_path / "runs", ledger_path=tmp_path / "l.sqlite"))
    cfg = jm._config_for(RunRequest(brief="b", repo="r", config=RunConfig(
        runner="codex", codex_model="o3", codex_oss=True, codex_local_provider="ollama")))
    assert cfg.runner == "codex" and cfg.codex_model == "o3"
    assert cfg.codex_oss is True and cfg.codex_local_provider == "ollama"
    # CLI: _build_config passthrough
    from argo.cli import _build_config
    c2 = _build_config("codex", None, False, None, 3, tmp_path / "runs", "happy",
                       codex_model="gpt-5-codex", codex_oss=True, codex_local_provider="lmstudio")
    assert c2.runner == "codex" and c2.codex_model == "gpt-5-codex" and c2.codex_local_provider == "lmstudio"
