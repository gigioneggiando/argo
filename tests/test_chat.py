"""B1 — chat re-validates a user-proposed candidate finding ("why didn't you find X?").

The hard part (validating a single ad-hoc finding) reuses the pipeline's `_validate_one`; these
tests cover the chat plumbing deterministically (the adversarial validator is monkeypatched, and a
stub runner stands in for the model writing CANDIDATE_FINDING.json)."""

import json
from pathlib import Path
from types import SimpleNamespace

import argo.chat as chat
from argo.models import Validation
from argo.orchestrator import run_pipeline

from conftest import BRIEF, REPO


class _StubRunner:
    """Stands in for the chat model: optionally writes a CANDIDATE_FINDING.json into the work dir."""
    def __init__(self, write_candidate: bool = True):
        self.write_candidate = write_candidate

    def run(self, *, work_dir, **kw):
        if self.write_candidate:
            (Path(work_dir) / "CANDIDATE_FINDING.json").write_text(json.dumps({
                "id": "CAND-1", "title": "SQLi in search", "cwe": "CWE-89",
                "severity": "High", "confidence": "Medium",
                "affected": ["src/api/search.py:42"], "vulnerable_flow": "input -> query",
                "why_vulnerable": "string concat", "exploit_scenario": "' OR 1=1",
                "impact": "db read", "recommended_fix": "parameterize"}), encoding="utf-8")
        return SimpleNamespace(text="Here is my analysis.", cost_usd=0.0, is_error=False)


def test_coerce_candidate_backfills():
    d = chat._coerce_candidate({"affected": "x.py:1"})
    for k in ("id", "title", "severity", "confidence", "cwe", "vulnerable_flow",
              "why_vulnerable", "exploit_scenario", "impact", "recommended_fix"):
        assert k in d
    assert d["affected"] == ["x.py:1"]          # a bare string is wrapped into a list


def test_validate_candidate_runs_the_validator(env, monkeypatch):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO))
    monkeypatch.setattr(chat, "_validate_one",
                        lambda c, s, t, f: Validation(verdict="refuted", rationale="sanitized"))
    out = chat._validate_candidate(ctx, ctx.load_scope(), {"affected": "x.py:1", "cwe": "CWE-79"})
    assert out["verdict"] == "refuted" and out["cwe"] == "CWE-79"
    assert out["finding_id"] == "CHAT-CANDIDATE"      # backfilled


def test_ask_revalidates_candidate(env, monkeypatch):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO))
    ctx.runner = _StubRunner(write_candidate=True)
    monkeypatch.setattr(chat, "_validate_one", lambda c, s, t, f: Validation(
        verdict="confirmed", rationale="traced source->sink", validated_severity="High"))
    res = chat.ask(ctx, "why didn't you find the SQLi at search.py:42?")
    assert res["validated_candidate"]["verdict"] == "confirmed"
    assert res["validated_candidate"]["finding_id"] == "CAND-1"
    assert "CONFIRMED" in res["reply"]
    # the raw hypothesis file is not surfaced as a generated artifact; the verdict file is written
    assert "CANDIDATE_FINDING.json" not in res["generated"]
    assert (ctx.run_dir / "generated" / "candidate_CAND-1.json").exists()


def test_ask_without_candidate_is_none(env):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO))
    ctx.runner = _StubRunner(write_candidate=False)
    res = chat.ask(ctx, "explain the top finding")
    assert res["validated_candidate"] is None and res["generated"] == []


# ------------------------------------------------------------------------------ HTTP chat config
def _chat_app(tmp_path):
    from fastapi.testclient import TestClient
    from argo.config import PipelineConfig
    from server.app import create_app
    root = tmp_path / "chat-runs"
    root.mkdir()
    app = create_app(PipelineConfig(runner="mock", runs_dir=root, ledger_path=tmp_path / "c.sqlite"),
                     token="synthetic-token")
    client = TestClient(app, base_url="http://127.0.0.1:8000",
                        headers={"X-Argo-Token": "synthetic-token"})
    return app, client, root


def _saved_run(root, run_id, cfg, meta):
    from argo.config import write_pipeline_config
    rd = root / run_id
    rd.mkdir(parents=True)
    (rd / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    (rd / "scope.json").write_text("{}", encoding="utf-8")
    if cfg is not None:
        write_pipeline_config(rd / "config.json", cfg)
    return rd


def test_http_chat_uses_the_saved_run_config(tmp_path, monkeypatch):
    """Chat must run with the configuration the run was executed with (auth mode, caps, budget),
    not a reconstruction from meta.json plus server defaults."""
    import server.app as server_app
    from argo.config import PipelineConfig
    app, client, root = _chat_app(tmp_path)
    _saved_run(root, "stored-run",
               PipelineConfig(runner="mistral-vibe", mistral_vibe_auth="stored", budget_usd=1.5,
                              session_max_turns=12, session_timeout_s=240),
               {"runner": "mistral-vibe", "stage_models": {}})
    seen = {}

    def fake_ask(ctx, message, **kw):
        c = ctx.config
        seen.update(auth=c.mistral_vibe_auth, runner=c.runner, budget=c.budget_usd,
                    turns=c.session_max_turns, timeout=c.session_timeout_s, runs_dir=c.runs_dir)
        return {"reply": "synthetic", "generated": [], "cost_usd": 0, "validated_candidate": None}

    monkeypatch.setattr(server_app.chat_engine, "ask", fake_ask)
    with client:
        assert client.post("/runs/stored-run/chat", json={"message": "hi"}).status_code == 200
    app.state.ledger.close()
    assert seen["auth"] == "stored" and seen["runner"] == "mistral-vibe"
    assert (seen["budget"], seen["turns"], seen["timeout"]) == (1.5, 12, 240)
    assert seen["runs_dir"] == root                    # runs dir of THIS server, not the saved one


def test_http_chat_never_resurrects_a_redacted_key(tmp_path, monkeypatch):
    import server.app as server_app
    from argo.config import PipelineConfig
    app, client, root = _chat_app(tmp_path)
    rd = _saved_run(root, "keyed-run",
                    PipelineConfig(runner="mistral-api", mistral_api_key="mstrl_SECRET_CANARY_1"),
                    {"runner": "mistral-api", "stage_models": {}})
    assert "mstrl_SECRET_CANARY_1" not in (rd / "config.json").read_text(encoding="utf-8")
    seen = {}

    def fake_ask(ctx, message, **kw):
        seen["key"] = ctx.config.mistral_api_key
        return {"reply": "synthetic", "generated": [], "cost_usd": 0, "validated_candidate": None}

    monkeypatch.setattr(server_app.chat_engine, "ask", fake_ask)
    with client:
        assert client.post("/runs/keyed-run/chat", json={"message": "hi"}).status_code == 200
    app.state.ledger.close()
    assert seen["key"] is None                          # never the "<redacted>" marker


def test_http_chat_keeps_the_legacy_meta_fallback(tmp_path, monkeypatch):
    import server.app as server_app
    app, client, root = _chat_app(tmp_path)
    _saved_run(root, "legacy-run", None, {"runner": "mock", "stage_models": {"chat": "m-legacy"}})
    seen = {}

    def fake_ask(ctx, message, **kw):
        seen["runner"], seen["model"] = ctx.config.runner, ctx.config.model_for("chat")
        return {"reply": "synthetic", "generated": [], "cost_usd": 0, "validated_candidate": None}

    monkeypatch.setattr(server_app.chat_engine, "ask", fake_ask)
    with client:
        assert client.post("/runs/legacy-run/chat", json={"message": "hi"}).status_code == 200
    app.state.ledger.close()
    assert seen == {"runner": "mock", "model": "m-legacy"}
