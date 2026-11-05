"""Codex local-model hardening: live turn cap, tool-loop tripwire, event capture, disabled
sub-agents, declared context window, and the recon JSON syntax-repair session.

Regression source: Qwen3-Coder-Next 80B via Ollama on UCloud (2026-11-04/05) -- num_turns was
hard-coded 0 so --max-turns never applied to Codex, a sandbox-broken session looped >1000 requests
into an Ollama context shift, a recon sub-agent (multi_agent) wrote off-template prompts, and one
malformed character in repo_profile.json discarded a complete recon."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from argo.config import PipelineConfig, pipeline_config_from_dict, pipeline_config_to_dict
from argo.guardrails import session_policy
from argo.ledger import Ledger
from argo.runner import (CodexRunner, RunnerError, SessionGuardTripped, _CODEX_FAIL_STREAK,
                         _CODEX_LOOP_REPEAT, _CodexSessionGuard, _count_codex_turns)
from argo.stages import recon


def _runner(tmp_path, **cfg):
    r = CodexRunner(PipelineConfig(runner="codex", **cfg), Ledger(tmp_path / "l.sqlite"))
    r._resolved_bin = "codex"
    return r


def _cmd_event(command, exit_code=0, output="", n=0):
    return json.dumps({"type": "item.completed", "item": {
        "id": f"item_{n}", "type": "command_execution", "command": command,
        "aggregated_output": output, "exit_code": exit_code, "status": "completed"}})


def test_turns_count_tool_items_only():
    lines = [json.dumps({"type": "thread.started"}),
             json.dumps({"type": "item.completed", "item": {"type": "error", "message": "x"}}),
             _cmd_event("ls", n=1),
             json.dumps({"type": "item.completed", "item": {"type": "file_change"}}),
             json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": "ok"}}),
             "not json"]
    assert _count_codex_turns("\n".join(lines)) == 2


def test_guard_enforces_turn_cap_live(tmp_path):
    g = _CodexSessionGuard(max_turns=3, events_path=tmp_path / "ev" / "s.jsonl")
    reasons = [g(_cmd_event(f"cat f{i}", n=i)) for i in range(4)]
    g.close()
    assert reasons[:3] == [None, None, None]
    assert "max_turns cap 3" in reasons[3] and g.kind == "turn_cap"
    assert len((tmp_path / "ev" / "s.jsonl").read_text().splitlines()) == 4   # every line teed


def test_guard_detects_identical_repeats_but_not_progress():
    g = _CodexSessionGuard(max_turns=None)
    assert all(g(_cmd_event(f"cat file{i}", n=i)) is None for i in range(50))  # distinct = fine
    reasons = [g(_cmd_event("cat same", output="same")) for _ in range(_CODEX_LOOP_REPEAT)]
    assert reasons[-1] and "repeated the same tool call" in reasons[-1] and g.kind == "tool_loop"


def test_guard_detects_failure_streak():
    g = _CodexSessionGuard(max_turns=None)
    reasons = [g(_cmd_event(f"cmd {i}", exit_code=1, output=f"bwrap: denied {i}"))
               for i in range(_CODEX_FAIL_STREAK)]
    assert reasons[-1] and "consecutive failed tool calls" in reasons[-1]


def test_guard_failure_streak_resets_on_success():
    g = _CodexSessionGuard(max_turns=None)
    for i in range(_CODEX_FAIL_STREAK * 3):
        ok = i % (_CODEX_FAIL_STREAK - 1) == 0
        assert g(_cmd_event(f"cmd {i}", exit_code=0 if ok else 1)) is None


def test_exec_streaming_aborts_mid_session(tmp_path):
    r = _runner(tmp_path)
    script = ("import sys,time\n"
              "for i in range(1000):\n"
              "    print('line', i, flush=True); time.sleep(0.01)\n")
    seen = []

    def cb(line):
        seen.append(line)
        return "stop now" if len(seen) == 5 else None
    with pytest.raises(SessionGuardTripped) as ei:
        r._exec([sys.executable, "-c", script], prompt="", cwd=tmp_path, timeout=30,
                on_stdout_line=cb)
    assert ei.value.reason == "stop now"
    assert len(seen) < 100                       # killed long before the child would finish


def test_exec_streaming_returns_full_stdout_and_reads_stdin(tmp_path):
    r = _runner(tmp_path)
    script = "import sys\ndata=sys.stdin.read()\nprint('got', len(data))\nprint('bye')\n"
    proc = r._exec([sys.executable, "-c", script], prompt="x" * 200_000, cwd=tmp_path,
                   timeout=30, on_stdout_line=lambda line: None)
    assert proc.returncode == 0 and proc.stdout.splitlines() == ["got 200000", "bye"]


def test_invoke_maps_guard_trip_to_runner_error(tmp_path, monkeypatch):
    r = _runner(tmp_path, session_max_turns=1)

    def fake_exec(cmd, prompt, cwd, timeout, env=None, on_stdout_line=None):
        for i in range(3):
            reason = on_stdout_line(_cmd_event(f"c{i}", n=i))
            if reason:
                raise SessionGuardTripped(reason)
        raise AssertionError("guard should have tripped")
    monkeypatch.setattr(r, "_exec", fake_exec)
    with pytest.raises(RunnerError) as ei:
        r._invoke(prompt="p", work_dir=tmp_path, model="m", repo_dir=None, allowed=(),
                  disallowed=(), stage="recon", run_id="r", label="recon-synthesis")
    assert ei.value.failure_kind == "turn_cap" and ei.value.retryable is False
    # outside the model's cwd (it would otherwise read its own transcript back)
    work = tmp_path
    assert (work.parent / ".argo_sessions" / f"{work.name}.codex.recon-synthesis.jsonl").exists()
    assert not (work / ".argo_sessions").exists()


def test_parse_envelope_reports_real_turns(tmp_path):
    r = _runner(tmp_path)
    stdout = "\n".join(_cmd_event(f"c{i}", n=i) for i in range(7))
    res = r.parse_envelope({"returncode": 0, "text": "t", "stdout": stdout}, model="m",
                           prompt_sha256="x", work_dir=tmp_path)
    assert res.num_turns == 7


def test_multi_agent_disabled_by_default_and_configurable(tmp_path):
    cmd = _runner(tmp_path)._build_codex_cmd(model="m", policy=session_policy("recon"),
                                             last_msg_file=tmp_path / "m")
    assert cmd[cmd.index("--disable") + 1] == "multi_agent"
    assert cmd[-1] == "-"
    none = _runner(tmp_path, codex_disable_features=())._build_codex_cmd(
        model="m", policy=session_policy("recon"), last_msg_file=tmp_path / "m")
    assert "--disable" not in none


def test_context_window_sets_compaction(tmp_path):
    cmd = _runner(tmp_path, codex_oss=True, codex_local_provider="ollama",
                  codex_context_window=131072)._build_codex_cmd(
        model="m", policy=session_policy("recon"), last_msg_file=tmp_path / "m")
    assert "model_context_window=131072" in cmd
    assert "model_auto_compact_token_limit=104857" in cmd
    plain = _runner(tmp_path)._build_codex_cmd(model="m", policy=session_policy("recon"),
                                               last_msg_file=tmp_path / "m")
    assert not any("model_context_window" in t for t in plain)


def test_new_fields_roundtrip_and_old_configs_get_defaults():
    cfg = PipelineConfig(runner="codex", codex_context_window=65536)
    back = pipeline_config_from_dict(json.loads(json.dumps(pipeline_config_to_dict(cfg))))
    assert back.codex_context_window == 65536 and list(back.codex_disable_features) == ["multi_agent"]
    raw = pipeline_config_to_dict(PipelineConfig(runner="codex"))
    raw.pop("codex_disable_features"); raw.pop("codex_context_window")
    old = pipeline_config_from_dict(raw)                       # a pre-existing run's config.json
    assert tuple(old.codex_disable_features) == ("multi_agent",) and old.codex_context_window is None


def _repair_ctx(tmp_path, writer):
    calls = []

    class FakeRunner:
        def run(self, **kw):
            calls.append(kw)
            writer(kw["work_dir"])
    ctx = SimpleNamespace(runner_for=lambda stage: FakeRunner(), run_dir=tmp_path,
                          config=SimpleNamespace(model_for=lambda stage: "m"), run_id="r")
    return ctx, calls


def test_recon_json_repair_runs_once_and_keeps_original(tmp_path):
    bad = '{"packages": ["left-pad": "1.0.0"]}'
    p = tmp_path / "repo_profile.json"
    p.write_text(bad, encoding="utf-8")
    ctx, calls = _repair_ctx(tmp_path, lambda wd: (Path(wd) / "repo_profile.json").write_text(
        '{"packages": {"left-pad": "1.0.0"}}', encoding="utf-8"))
    recon._repair_json_artifact(ctx, tmp_path, p)
    assert len(calls) == 1 and calls[0]["repo_dir"] is None
    assert "Parser error" in calls[0]["prompt"] and calls[0]["label"] == "recon-json-repair-repo_profile"
    assert json.loads(p.read_text()) == {"packages": {"left-pad": "1.0.0"}}
    assert (tmp_path / "repo_profile.json.malformed").read_text() == bad


def test_recon_json_repair_skips_valid_files(tmp_path):
    p = tmp_path / "repo_profile.json"
    p.write_text('{"ok": true}', encoding="utf-8")
    ctx, calls = _repair_ctx(tmp_path, lambda wd: None)
    recon._repair_json_artifact(ctx, tmp_path, p)
    assert calls == [] and not (tmp_path / "repo_profile.json.malformed").exists()


def test_recon_json_repair_failure_is_not_fatal_by_itself(tmp_path):
    p = tmp_path / "repo_profile.json"
    p.write_text("{broken", encoding="utf-8")

    def boom(wd):
        raise RunnerError("model died")
    ctx, _ = _repair_ctx(tmp_path, boom)
    recon._repair_json_artifact(ctx, tmp_path, p)     # caller's json.loads gate still decides
    assert p.read_text() == "{broken"


def test_web_search_disabled_on_offline_stages_only(tmp_path):
    from argo.runner import _CODEX_NETWORK_CFG, _CODEX_WEB_SEARCH_OFF
    r = _runner(tmp_path)
    for stage in ("ingest", "recon", "audit", "validate", "report"):
        cmd = r._build_codex_cmd(model="m", policy=session_policy(stage), last_msg_file=tmp_path / "m")
        assert _CODEX_WEB_SEARCH_OFF in cmd and _CODEX_NETWORK_CFG not in cmd, stage
    research = r._build_codex_cmd(model="m", policy=session_policy("research"),
                                  last_msg_file=tmp_path / "m")
    assert _CODEX_NETWORK_CFG in research and _CODEX_WEB_SEARCH_OFF not in research
