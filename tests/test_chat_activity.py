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
