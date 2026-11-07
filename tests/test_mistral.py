"""runner=mistral-api: Mistral Chat Completions + Argo-owned tool loop (argo/mistral_api.py).

Routing/config, the tool dispatcher's path policy (the security boundary of this backend), the
loop (tool calls, tokens, served model), HTTP error mapping/retries, OSINT-stage refusal, secret
hygiene and context elision. The API is simulated with httpx.MockTransport -- no network."""

import json
import os

import httpx
import pytest

from argo.cli import _apply_stage_assignments
from argo.config import (MISTRAL_API_BALANCED, MISTRAL_API_TOP, PipelineConfig,
                         pipeline_config_to_dict)
from argo.guardrails import session_policy
from argo.ledger import Ledger
from argo.mistral_api import _ELIDED, MistralApiRunner, Toolbox, ToolError
from argo.model_catalog import validate_selection
from argo.runner import RunnerError, build_runner

KEY = "mstrl_TEST_SENTINEL_KEY_0123456789"


@pytest.fixture(autouse=True)
def _no_ambient_keys(monkeypatch):
    monkeypatch.delenv("ARGO_MISTRAL_API_KEY", raising=False)
    monkeypatch.delenv("MISTRAL_API_KEY", raising=False)


@pytest.fixture
def dirs(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("import os\nSECRET = os.environ['X']\nprint(1)\n",
                                         encoding="utf-8")
    (repo / "README.md").write_text("hello\n", encoding="utf-8")
    work = tmp_path / "work" / "audit"
    work.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("do not read", encoding="utf-8")
    return repo, work, outside


# ------------------------------------------------------------------------------ helpers
def _reply(content="", calls=None, model="mistral-medium-latest", pt=100, ct=10, finish=None):
    msg = {"role": "assistant", "content": content}
    if calls:
        msg["tool_calls"] = [{"id": f"c{i}", "type": "function",
                              "function": {"name": n, "arguments": json.dumps(a)}}
                             for i, (n, a) in enumerate(calls)]
    return {"model": model, "usage": {"prompt_tokens": pt, "completion_tokens": ct},
            "choices": [{"index": 0, "message": msg,
                         "finish_reason": finish or ("tool_calls" if calls else "stop")}]}


def _runner(tmp_path, responses, **cfg):
    """responses: list of dict (200 JSON) or (status, body, headers) tuples, served in order."""
    seen = []
    queue = list(responses)

    def handler(request):
        seen.append({"headers": dict(request.headers), "body": json.loads(request.content)})
        item = queue.pop(0)
        if isinstance(item, tuple):
            status, body, headers = item
            return httpx.Response(status, text=body if isinstance(body, str) else json.dumps(body),
                                  headers=headers or {})
        return httpx.Response(200, json=item)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    sleeps = []
    cfg.setdefault("mistral_api_key", KEY)
    r = MistralApiRunner(PipelineConfig(runner="mistral-api", **cfg),
                         Ledger(tmp_path / "l.sqlite"), client=client, sleep=sleeps.append)
    return r, seen, sleeps


def _invoke(r, repo, work, stage="audit", allowed=("Read", "Grep", "Glob", "Write"), **kw):
    return r._invoke(prompt="audit this", work_dir=work, model=kw.pop("model", "mistral-medium-latest"),
                     repo_dir=repo, allowed=list(allowed), disallowed=[],
                     policy=session_policy(stage), stage=stage, run_id="R", label="x",
                     timeout_s=kw.pop("timeout_s", 60))


# ------------------------------------------------------------------------------ routing/config
def test_build_runner_dispatches_native_mistral(tmp_path):
    led = Ledger(tmp_path / "l.sqlite")
    assert isinstance(build_runner(PipelineConfig(runner="mistral-api"), led), MistralApiRunner)
    led.close()


def test_model_precedence_stage_over_flat_over_default():
    cfg = PipelineConfig(runner="mistral-api")
    assert cfg.model_for("audit") == MISTRAL_API_BALANCED
    cfg = cfg.with_overrides(mistral_api_model="mistral-small-latest")
    assert cfg.model_for("recon") == "mistral-small-latest"
    cfg = cfg.with_stage_model("audit", "mistral-large-latest")
    assert (cfg.model_for("audit"), cfg.model_for("recon")) == ("mistral-large-latest",
                                                                 "mistral-small-latest")


def test_calibrated_uses_top_model_for_audit():
    assert PipelineConfig(runner="mistral-api").calibrated().model_for("audit") == MISTRAL_API_TOP


def test_stage_runner_and_stage_model_route_to_mistral_map():
    cfg = _apply_stage_assignments(PipelineConfig(runner="headless"),
                                   ["audit=mistral-large-latest"], ["audit=mistral-api"])
    assert cfg.stage_runners["audit"] == "mistral-api"
    assert cfg.model_for("audit") == "mistral-large-latest"
    assert cfg.model_for("recon") == cfg.stage_models["recon"]


def test_other_provider_model_rejected_on_mistral_api():
    assert validate_selection("gpt-6-astra", "mistral-api")["selectable"] is False


def test_key_is_redacted_in_serialized_config():
    d = pipeline_config_to_dict(PipelineConfig(runner="mistral-api", mistral_api_key=KEY))
    assert KEY not in json.dumps(d)


def test_key_precedence_config_then_argo_env_then_ambient(tmp_path, monkeypatch):
    r, _, _ = _runner(tmp_path, [], mistral_api_key=None)
    monkeypatch.setenv("MISTRAL_API_KEY", "ambient")
    assert r._api_key() == "ambient"
    monkeypatch.setenv("ARGO_MISTRAL_API_KEY", "argo-env")
    assert r._api_key() == "argo-env"
    r2, _, _ = _runner(tmp_path, [], mistral_api_key="explicit")
    assert r2._api_key() == "explicit"
    r.ledger.close(); r2.ledger.close()


# ------------------------------------------------------------------------------ dispatcher policy
def test_reads_repo_and_scratch_by_relative_and_absolute_path(dirs):
    repo, work, _ = dirs
    tb = Toolbox(repo, work, allow_write=True)
    assert "SECRET" in tb.read_file("src/app.py")
    assert "SECRET" in tb.read_file(str(repo / "src" / "app.py"))
    tb.write_file("notes.md", "x")
    assert "x" in tb.read_file("notes.md")              # relative prefers the scratch dir


@pytest.mark.parametrize("bad", ["../outside.txt", "../../outside.txt", "src/../../outside.txt"])
def test_traversal_outside_roots_is_denied(dirs, bad):
    repo, work, outside = dirs
    tb = Toolbox(repo, work, allow_write=True)
    with pytest.raises(ToolError, match="denied|not found"):
        tb.read_file(bad)
    with pytest.raises(ToolError, match="denied"):
        tb.read_file(str(outside))


def test_symlink_escape_is_denied(dirs):
    repo, work, outside = dirs
    link = repo / "evil"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this platform/user")
    tb = Toolbox(repo, work, allow_write=True)
    with pytest.raises(ToolError, match="denied"):
        tb.read_file("evil")


def test_grep_and_glob_skip_symlinked_files(dirs):
    repo, work, outside = dirs
    try:
        os.symlink(outside, repo / "evil.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this platform/user")
    tb = Toolbox(repo, work, allow_write=False)
    assert "do not read" not in tb.grep("do not read")
    assert "evil.txt" not in tb.glob("*.txt")


def test_writes_only_inside_scratch(dirs):
    repo, work, outside = dirs
    tb = Toolbox(repo, work, allow_write=True)
    assert "wrote" in tb.write_file("sub/dir/out.json", "{}")
    assert (work / "sub" / "dir" / "out.json").read_text() == "{}"
    for bad in [str(repo / "src" / "app.py"), "../../repo/README.md", str(outside), "../x.txt"]:
        with pytest.raises(ToolError, match="denied"):
            tb.write_file(bad, "pwned")
    assert (repo / "README.md").read_text() == "hello\n"
    assert outside.read_text() == "do not read"


def test_write_tool_absent_without_write_permission(dirs):
    repo, work, _ = dirs
    tb = Toolbox(repo, work, allow_write=False)
    assert "write_file" not in [t["function"]["name"] for t in tb.schemas()]
    with pytest.raises(ToolError):
        tb.dispatch("write_file", {"path": "a", "content": "b"})


def test_no_shell_or_unknown_tool(dirs):
    repo, work, _ = dirs
    tb = Toolbox(repo, work, allow_write=True)
    names = {t["function"]["name"] for t in tb.schemas()}
    assert names == {"read_file", "list_dir", "glob", "grep", "write_file"}
    with pytest.raises(ToolError, match="unknown tool"):
        tb.dispatch("bash", {"command": "id"})


def test_grep_glob_list(dirs):
    repo, work, _ = dirs
    tb = Toolbox(repo, work, allow_write=True)
    assert "app.py:2:" in tb.grep("SECRET")
    assert "app.py" in tb.glob("**/*.py")
    assert "src/" in tb.list_dir(str(repo))
    assert tb.grep("nomatchzzz") == "(no matches)"
    with pytest.raises(ToolError, match="invalid regex"):
        tb.grep("(")


# ------------------------------------------------------------------------------ the loop
def test_loop_executes_tools_writes_artifact_and_counts_tokens(tmp_path, dirs):
    repo, work, _ = dirs
    r, seen, _ = _runner(tmp_path, [
        _reply(calls=[("grep", {"pattern": "SECRET"})], pt=100, ct=5),
        _reply(calls=[("write_file", {"path": "findings.json", "content": "[]"})], pt=200, ct=7),
        _reply(content="Done. Generated files: findings.json", pt=300, ct=9),
    ])
    raw = _invoke(r, repo, work)
    assert (work / "findings.json").read_text() == "[]"
    assert raw["text"].startswith("Done.")
    assert (raw["input_tokens"], raw["output_tokens"], raw["tool_calls"]) == (600, 21, 2)
    # tool result fed back with the call id; Authorization header carries the key
    second = seen[1]["body"]["messages"]
    assert second[-1]["role"] == "tool" and second[-1]["tool_call_id"] == "c0"
    assert "app.py:2:" in second[-1]["content"]
    assert seen[0]["headers"]["authorization"] == f"Bearer {KEY}"
    res = r.parse_envelope(raw, model="mistral-medium-latest", prompt_sha256="h", work_dir=work)
    assert res.input_tokens == 600 and res.served_model == "mistral-medium-latest"
    r.ledger.close()


def test_alias_resolving_to_dated_model_is_not_a_substitution(tmp_path, dirs):
    repo, work, _ = dirs
    r, _, _ = _runner(tmp_path, [_reply(content="ok", model="mistral-medium-2604")])
    raw = _invoke(r, repo, work)
    res = r.parse_envelope(raw, model="mistral-medium-latest", prompt_sha256="h", work_dir=work)
    assert res.served_model is None and res.served_models == ("mistral-medium-2604",)
    r.ledger.close()


def test_tool_errors_go_back_to_the_model_not_fatal(tmp_path, dirs):
    repo, work, _ = dirs
    r, seen, _ = _runner(tmp_path, [
        _reply(calls=[("read_file", {"path": "../../outside.txt"})]),
        _reply(content="fine"),
    ])
    raw = _invoke(r, repo, work)
    assert raw["text"] == "fine"
    assert seen[1]["body"]["messages"][-1]["content"].startswith("ERROR: access denied")
    r.ledger.close()


def test_research_stage_is_refused_up_front(tmp_path, dirs):
    repo, work, _ = dirs
    r, seen, _ = _runner(tmp_path, [])
    with pytest.raises(RunnerError) as ei:
        _invoke(r, None, work, stage="research")
    assert ei.value.failure_kind == "unsupported_stage_tool" and not ei.value.retryable
    assert seen == []
    r.ledger.close()


def test_missing_key_fails_before_any_request(tmp_path, dirs):
    repo, work, _ = dirs
    r, seen, _ = _runner(tmp_path, [], mistral_api_key=None)
    with pytest.raises(RunnerError) as ei:
        _invoke(r, repo, work)
    assert ei.value.failure_kind == "credential_bootstrap" and seen == []
    r.ledger.close()


def test_401_is_auth_failed_not_retried(tmp_path, dirs):
    repo, work, _ = dirs
    r, seen, _ = _runner(tmp_path, [(401, {"detail": "Invalid API Key"}, None)])
    with pytest.raises(RunnerError) as ei:
        _invoke(r, repo, work)
    assert ei.value.failure_kind == "auth_failed" and ei.value.retryable is False
    assert len(seen) == 1
    r.ledger.close()


def test_429_waits_retry_after_then_succeeds(tmp_path, dirs):
    repo, work, _ = dirs
    r, seen, sleeps = _runner(tmp_path, [(429, "slow down", {"retry-after": "3"}),
                                         _reply(content="ok")])
    assert _invoke(r, repo, work)["text"] == "ok"
    assert len(seen) == 2 and sum(sleeps) >= 2.9
    r.ledger.close()


def test_5xx_retried_then_gives_up_retryable(tmp_path, dirs):
    repo, work, _ = dirs
    r, seen, _ = _runner(tmp_path, [(503, "busy", None)] * 5)
    with pytest.raises(RunnerError) as ei:
        _invoke(r, repo, work)
    assert ei.value.retryable is True and len(seen) == 5
    r.ledger.close()


def test_400_is_invalid_request_and_key_scrubbed(tmp_path, dirs):
    repo, work, _ = dirs
    r, _, _ = _runner(tmp_path, [(400, f"bad model; key={KEY}", None)])
    with pytest.raises(RunnerError) as ei:
        _invoke(r, repo, work)
    assert ei.value.failure_kind == "invalid_request" and KEY not in str(ei.value)
    r.ledger.close()


def test_identical_tool_call_loop_is_stopped(tmp_path, dirs):
    repo, work, _ = dirs
    loop = _reply(calls=[("list_dir", {"path": "."})])
    r, _, _ = _runner(tmp_path, [loop] * 5)
    with pytest.raises(RunnerError) as ei:
        _invoke(r, repo, work)
    assert ei.value.failure_kind == "tool_loop"
    r.ledger.close()


def test_tool_call_cap(tmp_path, dirs):
    repo, work, _ = dirs
    replies = [_reply(calls=[("grep", {"pattern": f"p{i}"})]) for i in range(5)]
    r, _, _ = _runner(tmp_path, replies, session_max_turns=3)
    with pytest.raises(RunnerError) as ei:
        _invoke(r, repo, work)
    assert ei.value.failure_kind == "turn_limit_exceeded"
    r.ledger.close()


def test_events_log_outside_scratch_and_key_free(tmp_path, dirs):
    repo, work, _ = dirs
    r, _, _ = _runner(tmp_path, [_reply(calls=[("grep", {"pattern": KEY})]), _reply(content="ok")])
    raw = _invoke(r, repo, work)
    ev = raw["events"]
    assert not ev.startswith(str(work)) and os.path.exists(ev)
    assert KEY not in open(ev, encoding="utf-8").read()
    r.ledger.close()


def test_old_tool_outputs_are_elided_near_the_window(tmp_path):
    r, _, _ = _runner(tmp_path, [], mistral_api_context_window=2000)
    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    for i in range(20):
        msgs.append({"role": "tool", "tool_call_id": str(i), "name": "read_file",
                     "content": "x" * 1000})
    n = r._fit_context(msgs)
    assert n > 0
    tools = [m for m in msgs if m["role"] == "tool"]
    assert all(m["content"] != _ELIDED for m in tools[-8:])      # recent results kept
    assert tools[0]["content"] == _ELIDED
    r.ledger.close()


def test_full_session_through_agentrunner_run_logs_and_checks_repo(tmp_path, dirs):
    """End to end through AgentRunner.run: ledger row, llm_log.jsonl, repo-integrity check."""
    repo, work, _ = dirs
    r, _, _ = _runner(tmp_path, [
        _reply(calls=[("write_file", {"path": "out.md", "content": "# ok"})]),
        _reply(content="Generated files: out.md"),
    ])
    res = r.run(prompt="p", run_dir=tmp_path, work_dir=work, model="mistral-medium-latest",
                stage="audit", run_id="R", repo_dir=repo, label="x")
    assert res.text == "Generated files: out.md" and (work / "out.md").exists()
    rows = [json.loads(l) for l in (tmp_path / "llm_log.jsonl").read_text().splitlines()]
    assert rows[-1]["backend"] == "mistral-api" and rows[-1]["input_tokens"] == 200
    r.ledger.close()


def test_cli_preflight_refuses_osint_stages_on_mistral():
    import typer
    from argo.cli import _preflight_networked_stages
    cfg = PipelineConfig(runner="mistral-api", research_enabled=True, corroborate_enabled=False)
    with pytest.raises(typer.BadParameter, match="--no-research"):
        _preflight_networked_stages(cfg)
    _preflight_networked_stages(cfg.with_overrides(research_enabled=False))
    _preflight_networked_stages(cfg.with_overrides(stage_runners={"research": "headless"}))


def test_invalid_json_is_rejected_with_location_and_not_written(dirs):
    repo, work, _ = dirs
    tb = Toolbox(repo, work, allow_write=True)
    with pytest.raises(ToolError, match=r"invalid JSON .*line 1, column"):
        tb.write_file("SECURITY_FINDINGS__x.json", '{"a": "say "hi""}')
    assert not (work / "SECURITY_FINDINGS__x.json").exists()
    assert "wrote" in tb.write_file("ok.json", '{"a": "say \\"hi\\""}')
    assert "wrote" in tb.write_file("notes.md", 'not "json" at all')


def test_catalog_prices_and_alias_resolution():
    from argo.config import MISTRAL_API_CHEAP, estimate_cost_usd, model_cost_source
    from argo.model_catalog import catalog_integrity, get_model_spec
    assert catalog_integrity()["valid"]
    assert MISTRAL_API_BALANCED == "mistral-large-4"
    assert model_cost_source("mistral-large-4") == "estimated_known_price"
    assert estimate_cost_usd("mistral-large-4", 1_000_000, 1_000_000) == pytest.approx(2.8)
    assert get_model_spec(MISTRAL_API_CHEAP).pricing_known
    # -latest aliases that point at deprecated, unpriced models stay honest: cost unknown, not $0
    assert get_model_spec("mistral-large-latest").model_id == "mistral-large-2512"
    assert model_cost_source("mistral-large-latest") == "unknown"
    assert model_cost_source("mistral-medium-latest") == "unknown"
    assert get_model_spec("mistral-medium-latest").lifecycle == "deprecated"


def test_benchmark_cheap_tier_and_adaptive_strong_model():
    from argo.adaptive import _set_stage_model, _strong_model
    from argo.benchmark import _cheap_tier
    from argo.config import MISTRAL_API_CHEAP
    cfg = PipelineConfig(runner="mistral-api")
    assert _cheap_tier(cfg).model_for("audit") == MISTRAL_API_CHEAP
    assert _strong_model("mistral-api", cfg, "validate") == MISTRAL_API_TOP
    assert _strong_model("mistral-vibe", cfg, "validate") is None
    assert _set_stage_model(cfg, "mistral-api", "validate", "x").model_for("validate") == "x"


def test_session_budget_stops_the_tool_loop(tmp_path, dirs):
    repo, work, _ = dirs
    # each turn: 1M prompt tokens; the cap is hit after the first turn
    replies = [_reply(calls=[("grep", {"pattern": f"p{i}"})], pt=1_000_000,
                      model="mistral-small-2603") for i in range(5)]
    r, seen, _ = _runner(tmp_path, replies)
    raw = r._invoke(prompt="audit this", work_dir=work, model="mistral-small-2603",
                    repo_dir=repo, allowed=["Read", "Grep", "Glob", "Write"], disallowed=[],
                    policy=session_policy("audit"), stage="audit", run_id="R", label="x",
                    timeout_s=60, session_budget_usd=0.01)
    assert raw["stop_reason"] == "budget_exceeded"
    assert len(seen) == 1


def test_live_activity_reports_tool_calls_and_interim_text(tmp_path, dirs):
    repo, work, _ = dirs
    r, _seen, _ = _runner(tmp_path, [
        _reply(content="Looking for secrets first", calls=[("grep", {"pattern": "SECRET"})]),
        _reply(content="Done."),
    ])
    activity = []
    r.on_activity = activity.append
    raw = _invoke(r, repo, work)
    assert raw["text"] == "Done."
    assert activity == ["Looking for secrets first", 'grep {"pattern": "SECRET"}']
    r.ledger.close()
