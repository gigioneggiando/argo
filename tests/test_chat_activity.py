"""B2: live chat activity. Runners report one-line progress (tool calls, interim messages) through
an optional sink while a session runs; POST /runs/{id}/chat/stream relays it as NDJSON and ends with
the same payload as POST /runs/{id}/chat. The sink never changes results, ledger or guardrails."""

from __future__ import annotations

import json

from argo.runner import FallbackRunner, _codex_activity

from test_api import _client, _start, _wait


def _ev(kind, **item):
    return json.dumps({"type": kind, "item": item})


def test_codex_activity_lines():
    assert _codex_activity(_ev("item.started", type="command_execution",
                               command="bash -lc 'rg -n get_order src'")) == "$ bash -lc 'rg -n get_order src'"
    assert _codex_activity(_ev("item.started", type="file_change",
                               changes=[{"path": "generated/test_x.py"}])) == "edit generated/test_x.py"
    assert _codex_activity(_ev("item.completed", type="agent_message", text="Checking the ORM")) \
        == "Checking the ORM"
    # Completed commands, reasoning, token counts and garbage are not activity.
    assert _codex_activity(_ev("item.completed", type="command_execution", command="ls")) is None
    assert _codex_activity(_ev("item.completed", type="reasoning", text="hmm")) is None
    assert _codex_activity(json.dumps({"type": "turn.completed", "usage": {}})) is None
    assert _codex_activity("not json") is None and _codex_activity("") is None


def test_with_activity_tees_lines_and_keeps_the_guard(tmp_path):
    from argo.config import PipelineConfig
    from argo.ledger import Ledger
    from argo.runner import MockClaudeRunner
    r = MockClaudeRunner(PipelineConfig(runner="mock"), Ledger(tmp_path / "l.sqlite"))
    try:
        assert r._with_activity(None, _codex_activity) is None        # no sink: untouched
        seen, guard_lines = [], []
        r.on_activity = seen.append
        tee = r._with_activity(lambda line: guard_lines.append(line) or "stop", _codex_activity)
        line = _ev("item.started", type="command_execution", command="ls")
        assert tee(line) == "stop"                                     # guard verdict preserved
        assert guard_lines == [line] and seen == ["$ ls"]
        r.on_activity = lambda t: 1 / 0                                # a broken sink is ignored
        assert tee(line) == "stop"
        r._activity("x" * 1000)                                        # and so is its error here
    finally:
        r.ledger.close()


def test_fallback_runner_propagates_the_sink(tmp_path):
    from argo.config import PipelineConfig
    from argo.ledger import Ledger
    from argo.runner import MockClaudeRunner
    led = Ledger(tmp_path / "l.sqlite")
    try:
        cfg = PipelineConfig(runner="mock")
        a, b = MockClaudeRunner(cfg, led), MockClaudeRunner(cfg, led)
        fb = FallbackRunner(cfg, led, [a, b])
        sink = print
        fb.on_activity = sink
        assert a.on_activity is sink and b.on_activity is sink and fb.on_activity is sink
    finally:
        led.close()


def test_chat_stream_relays_activity_then_the_reply(tmp_path):
    _app, client = _client(tmp_path)
    run_id = _start(client)
    assert _wait(client, run_id)["state"] == "completed"
    with client.stream("POST", f"/runs/{run_id}/chat/stream",
                       json={"message": "Explain finding SQLI-001"}) as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/x-ndjson")
        events = [json.loads(line) for line in r.iter_lines() if line.strip()]
    kinds = [e["type"] for e in events]
    assert kinds[-1] == "done" and kinds.count("done") == 1 and "error" not in kinds
    assert kinds.index("activity") < kinds.index("done")
    assert any("rg -n" in e["text"] for e in events if e["type"] == "activity")
    done = events[-1]
    assert done["reply"] and "cost_usd" in done and "generated" in done
    # The streamed turn is persisted exactly like the plain one, and the sink is detached after.
    history = client.get(f"/runs/{run_id}/chat").json()
    assert [m["role"] for m in history][-2:] == ["user", "assistant"]
    plain = client.post(f"/runs/{run_id}/chat", json={"message": "Explain finding SQLI-001"}).json()
    assert set(plain) == set(done) - {"type"}


def test_chat_stream_requires_scope(tmp_path):
    _app, client = _client(tmp_path)
    (tmp_path / "runs" / "no-scope").mkdir(parents=True)
    r = client.post("/runs/no-scope/chat/stream", json={"message": "hi"})
    assert r.status_code == 409
    assert client.post("/runs/missing/chat/stream", json={"message": "hi"}).status_code == 404


# ---------------------------------------------------------------- Claude stream-json (B2)
# Event shapes as emitted by claude 2.1.319 `-p --output-format stream-json --verbose` (captured
# 2026-11-06); ids/paths replaced with synthetic values. The final "result" event carries the same
# fields as the `--output-format json` envelope.
_CLAUDE_STREAM = [
    {"type": "system", "subtype": "init", "session_id": "s-1", "model": "claude-haiku-5-5"},
    {"type": "system", "subtype": "thinking_tokens", "estimated_tokens": 50, "session_id": "s-1"},
    {"type": "assistant", "message": {"role": "assistant", "content": [
        {"type": "thinking", "thinking": "", "signature": "x"}]}, "session_id": "s-1"},
    {"type": "assistant", "message": {"role": "assistant", "content": [
        {"type": "text", "text": "Checking the order lookup"},
        {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "src/api/orders.py"}}]},
     "session_id": "s-1"},
    {"type": "user", "message": {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t1", "content": "def get_order(..."}]}},
    {"type": "rate_limit_event", "rate_limit_info": {"status": "allowed"}},
    {"type": "result", "subtype": "success", "is_error": False, "num_turns": 2, "result": "It is SQLi.",
     "session_id": "s-1", "total_cost_usd": 0.0047, "stop_reason": "end_turn",
     "terminal_reason": "completed", "api_error_status": None,
     "usage": {"input_tokens": 2, "output_tokens": 76}},
]


def test_claude_activity_and_stream_result():
    from argo.runner import _claude_activity, _claude_stream_result
    lines = [json.dumps(e) for e in _CLAUDE_STREAM]
    seen = [a for a in map(_claude_activity, lines) if a]
    assert seen == ["Checking the order lookup · Read src/api/orders.py"]
    env = _claude_stream_result("\n".join(lines) + "\n")
    assert env["type"] == "result" and env["result"] == "It is SQLi." and env["num_turns"] == 2
    assert _claude_stream_result("\n".join(lines[:-1])) is None          # stream never finished


class _Proc:
    def __init__(self, out, rc=0):
        self.stdout, self.stderr, self.returncode = out, "", rc


def test_headless_streams_only_with_a_viewer_and_parses_the_same_envelope(tmp_path, monkeypatch):
    from argo.config import PipelineConfig
    from argo.ledger import Ledger
    from argo.runner import HeadlessClaudeRunner, parse_result_envelope
    runner = HeadlessClaudeRunner(PipelineConfig(), Ledger(tmp_path / "l.sqlite"))
    runner._resolved_bin = "claude"                                       # no PATH lookup in CI
    stream = "\n".join(json.dumps(e) for e in _CLAUDE_STREAM) + "\n"
    calls = []

    def fake_exec(cmd, prompt, cwd, timeout, env=None, on_stdout_line=None):
        calls.append((cmd, on_stdout_line))
        if "stream-json" in cmd:
            for line in stream.splitlines(keepends=True):
                if on_stdout_line:
                    on_stdout_line(line)
            return _Proc(stream)
        return _Proc(json.dumps(_CLAUDE_STREAM[-1]))

    monkeypatch.setattr(runner, "_exec", fake_exec)
    kw = dict(prompt="p", work_dir=tmp_path, model="m", repo_dir=None, allowed=[], disallowed=[],
              stage="chat", run_id="R", label="chat")
    try:
        plain = runner._invoke(**kw)                                      # no viewer: json, as before
        assert "json" in calls[0][0] and "stream-json" not in calls[0][0] and calls[0][1] is None
        seen = []
        runner.on_activity = seen.append
        streamed = runner._invoke(**kw)
        cmd = calls[1][0]
        assert cmd[cmd.index("--output-format") + 1] == "stream-json" and "--verbose" in cmd
        assert seen == ["Checking the order lookup · Read src/api/orders.py"]
        parsed = [parse_result_envelope(e, model="m", prompt_sha256="h", work_dir=tmp_path)
                  for e in (plain, streamed)]
        assert (parsed[0].text, parsed[0].cost_usd, parsed[0].num_turns) == \
               (parsed[1].text, parsed[1].cost_usd, parsed[1].num_turns) == ("It is SQLi.", 0.0047, 2)
    finally:
        runner.ledger.close()


# ---------------------------------------------------------------- Gemini stream-json (B2)
# Event shapes as emitted by gemini CLI 0.66 `--output-format stream-json` (captured 2026-11-06,
# synthetic ids). Unlike Claude, the final "result" event has no response text: the answer is the
# assistant deltas after the last tool result, and stats.models uses flat input/output tokens.
_GEMINI_STREAM = [
    {"type": "init", "session_id": "g-1", "model": "gemini-2.5-flash"},
    {"type": "message", "role": "user", "content": "Read probe.txt"},
    {"type": "message", "role": "assistant", "content": "Let me read it.", "delta": True},
    {"type": "tool_use", "tool_name": "read_file", "tool_id": "t1", "parameters": {"file_path": "probe.txt"}},
    {"type": "tool_result", "tool_id": "t1", "status": "success", "output": ""},
    {"type": "message", "role": "assistant", "content": "PROBE-4", "delta": True},
    {"type": "message", "role": "assistant", "content": "2\n", "delta": True},
    {"type": "result", "status": "success", "stats": {
        "total_tokens": 13965, "input_tokens": 13907, "output_tokens": 23, "cached": 6739,
        "input": 7168, "tool_calls": 1, "models": {"gemini-2.5-flash": {
            "total_tokens": 13965, "input_tokens": 13907, "output_tokens": 23,
            "cached": 6739, "input": 7168}}}},
]


def test_gemini_stream_rebuilds_the_json_envelope(tmp_path):
    from argo.config import PipelineConfig
    from argo.ledger import Ledger
    from argo.runner import GeminiRunner, _gemini_activity, _gemini_stream_envelope
    lines = [json.dumps(e) for e in _GEMINI_STREAM]
    assert [a for a in map(_gemini_activity, lines) if a] == ["read_file probe.txt"]
    env = _gemini_stream_envelope("\n".join(lines))
    assert env == {"session_id": "g-1", "response": "PROBE-42\n", "stats": {"models": {
        "gemini-2.5-flash": {"tokens": {"prompt": 13907, "candidates": 23}}}}}
    assert _gemini_stream_envelope("\n".join(lines[:-1])) is None       # never finished
    failed = dict(_GEMINI_STREAM[-1], status="error", error={"message": "quota exceeded"})
    assert _gemini_stream_envelope(json.dumps(failed))["error"] == {"message": "quota exceeded"}

    # The rebuilt envelope parses exactly like the json-mode one with the same numbers.
    r = GeminiRunner(PipelineConfig(runner="gemini"), Ledger(tmp_path / "l.sqlite"))
    try:
        json_env = {"session_id": "g-1", "response": "PROBE-42\n", "stats": {"models": {
            "gemini-2.5-flash": {"tokens": {"prompt": 13907, "candidates": 23, "cached": 6739}}}}}
        a, b = (r.parse_envelope({**e, "_exit_code": 0}, model="gemini-2.5-flash",
                                 prompt_sha256="h", work_dir=tmp_path) for e in (env, json_env))
        assert (a.text, a.input_tokens, a.output_tokens, a.cost_usd, a.served_model, a.is_error) == \
               (b.text, b.input_tokens, b.output_tokens, b.cost_usd, b.served_model, b.is_error)
    finally:
        r.ledger.close()


def test_gemini_uses_stream_json_only_with_a_viewer(tmp_path, monkeypatch):
    from argo.config import PipelineConfig
    from argo.ledger import Ledger
    from argo.runner import GeminiRunner
    r = GeminiRunner(PipelineConfig(runner="gemini"), Ledger(tmp_path / "l.sqlite"))
    r._resolved_bin = "gemini"
    stream = "\n".join(json.dumps(e) for e in _GEMINI_STREAM) + "\n"
    cmds = []

    def fake_exec(cmd, prompt, cwd, timeout, env=None, on_stdout_line=None):
        cmds.append(cmd)
        if "stream-json" in cmd:
            for line in stream.splitlines(keepends=True):
                if on_stdout_line:
                    on_stdout_line(line)
            return _Proc(stream)
        return _Proc(json.dumps({"session_id": "g-1", "response": "PROBE-42\n", "stats": {}}))

    monkeypatch.setattr(r, "_exec", fake_exec)
    kw = dict(prompt="p", work_dir=tmp_path, model="gemini-2.5-flash", repo_dir=None, allowed=[],
              disallowed=[], stage="chat", run_id="R", label="chat")
    try:
        assert r._invoke(**kw)["response"] == "PROBE-42\n"
        assert cmds[0][cmds[0].index("--output-format") + 1] == "json"
        seen = []
        r.on_activity = seen.append
        assert r._invoke(**kw)["response"] == "PROBE-42\n"
        assert cmds[1][cmds[1].index("--output-format") + 1] == "stream-json"
        assert seen == ["read_file probe.txt"]
    finally:
        r.ledger.close()
