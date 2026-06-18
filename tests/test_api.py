"""HTTP API tests (Phase 0) — driven entirely on the mock runner, zero tokens.

Exercises the full run lifecycle through the API: start → live status/SSE → artifacts, plus
dry-run, the artifact whitelist, and 404s.
"""

import json
import time

import pytest
from fastapi.testclient import TestClient

from argo.config import PipelineConfig
from server.app import create_app

from conftest import FIXTURES, BRIEF, REPO, _force_rmtree

TERMINAL = {"completed", "failed", "cancelled"}


def _client(tmp_path):
    cfg = PipelineConfig(
        runner="mock",
        runs_dir=tmp_path / "runs",
        ledger_path=tmp_path / "ledger.sqlite",
        fixtures_dir=FIXTURES,
        fixtures_scenario="happy",
    )
    app = create_app(cfg)
    return app, TestClient(app)


def _start(client, **over):
    body = {"brief": BRIEF.read_text(encoding="utf-8"), "repo": str(REPO),
            "config": {"runner": "mock"}}
    body.update(over)
    r = client.post("/runs", json=body)
    assert r.status_code == 202, r.text
    return r.json()["run_id"]


def _wait(client, run_id, timeout=15.0):
    deadline = time.time() + timeout
    st = {}
    while time.time() < deadline:
        st = client.get(f"/runs/{run_id}").json()
        if st["state"] in TERMINAL:
            return st
        time.sleep(0.05)
    raise AssertionError(f"run {run_id} did not finish; last={st}")


def test_upload_zip_then_run(tmp_path):
    import io, zipfile
    app, client = _client(tmp_path)
    try:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("proj/app.py", "x = 1\n")
            zf.writestr("proj/readme.md", "# proj\n")
        buf.seek(0)
        r = client.post("/uploads", files={"file": ("proj.zip", buf, "application/zip")})
        assert r.status_code == 200, r.text
        up = r.json()
        assert up["files"] == 2 and up["name"] == "proj" and up["repo"].endswith("proj")
        # the returned path drives a normal local-review run (no brief)
        run_id = _start(client, brief="", repo=up["repo"])
        assert _wait(client, run_id)["state"] == "completed"
        # a non-zip upload is rejected
        bad = client.post("/uploads", files={"file": ("x.txt", io.BytesIO(b"nope"), "text/plain")})
        assert bad.status_code == 400
    finally:
        app.state.ledger.close()


def test_full_pipeline_via_api(tmp_path):
    app, client = _client(tmp_path)
    try:
        run_id = _start(client)
        st = _wait(client, run_id)
        assert st["state"] == "completed"
        # research (default on) + ingest + recon + audit + validate + report = 6 stages
        assert [s["state"] for s in st["stages"]] == ["done"] * 6
        assert "research" in [s["name"] for s in st["stages"]]
        assert st["artifacts"]["report"] is True
        assert st["artifacts"]["validated_findings"] is True

        assert "Security Audit Report" in client.get(f"/runs/{run_id}/report").text
        vf = client.get(f"/runs/{run_id}/artifacts/validated_findings").json()
        assert {f["id"] for f in vf["findings"]} == {"FULL-001", "AUTHZ-002", "FULL-003"}
        assert len(client.get(f"/runs/{run_id}/findings").json()) == 2          # 2 focuses
        assert {d["name"] for d in client.get(f"/runs/{run_id}/drafts").json()} == \
            {"FULL-001.md", "AUTHZ-002.md"}
        assert any(r["run_id"] == run_id and r["state"] == "completed"
                   for r in client.get("/runs").json())
        assert client.get(f"/runs/{run_id}/artifacts/nope").status_code == 404  # whitelist
    finally:
        app.state.ledger.close()
        _force_rmtree(tmp_path / "runs")


def test_dry_run_via_api(tmp_path):
    app, client = _client(tmp_path)
    try:
        run_id = _start(client, dry_run=True)
        st = _wait(client, run_id)
        assert st["state"] == "completed"
        assert st["artifacts"]["report"] is False
        assert st["artifacts"]["prompts"] == 2
        assert client.get(f"/runs/{run_id}/report").status_code == 404  # report not produced
    finally:
        app.state.ledger.close()
        _force_rmtree(tmp_path / "runs")


def test_events_stream_reaches_terminal(tmp_path):
    app, client = _client(tmp_path)
    try:
        run_id = _start(client)
        states = []
        with client.stream("GET", f"/runs/{run_id}/events") as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/event-stream")
            for line in resp.iter_lines():
                if line.startswith("data: "):
                    st = json.loads(line[6:])
                    states.append(st["state"])
                    if st["state"] in TERMINAL:
                        break
        assert states[-1] == "completed"
    finally:
        app.state.ledger.close()
        _force_rmtree(tmp_path / "runs")


def test_spa_assets_served(tmp_path):
    app, client = _client(tmp_path)
    try:
        # "/" redirects into the SPA and serves index.html
        idx = client.get("/")
        assert idx.status_code == 200
        assert "Argo" in idx.text and "js/app.js" in idx.text
        # static JS module is served
        js = client.get("/app/js/app.js")
        assert js.status_code == 200 and "router" in js.text.lower()
        assert client.get("/app/styles.css").status_code == 200
    finally:
        app.state.ledger.close()


def test_settings_roundtrip(tmp_path):
    app, client = _client(tmp_path)
    try:
        # defaults
        s = client.get("/settings").json()
        assert s["runner"] == "mock" and s["parallel"] == 3
        # save + read back
        saved = client.put("/settings", json={"runner": "headless", "budget_usd": 25,
                                              "parallel": 5, "calibration": True,
                                              "models": {"audit": "claude-opus-4-8"}}).json()
        assert saved["runner"] == "headless" and saved["models"]["audit"] == "claude-opus-4-8"
        assert client.get("/settings").json()["budget_usd"] == 25
    finally:
        app.state.ledger.close()


def test_recommend_tiers(tmp_path):
    app, client = _client(tmp_path)
    try:
        quick = client.post("/recommend", json={"target": "quick"}).json()
        thorough = client.post("/recommend", json={"target": "thorough", "repo": str(REPO)}).json()
        assert quick["config"]["runner"] == "mock"                 # never auto-enables spend
        assert quick["config"]["budget_usd"] < thorough["config"]["budget_usd"]
        assert thorough["config"]["calibration"] is True
        assert thorough["config"]["models"]["audit"] == "claude-opus-4-8"
        assert "rationale" in thorough and thorough["rationale"]
    finally:
        app.state.ledger.close()


def test_per_stage_models_applied(tmp_path):
    # a run with per-stage model overrides goes through (mock ignores the model, but config maps)
    app, client = _client(tmp_path)
    try:
        run_id = _start(client, config={"runner": "mock", "models": {"recon": "claude-opus-4-8"}})
        st = _wait(client, run_id)
        assert st["state"] == "completed"
    finally:
        app.state.ledger.close()
        _force_rmtree(tmp_path / "runs")


def test_chat_roundtrip_and_test_generation(tmp_path):
    app, client = _client(tmp_path)
    try:
        run_id = _start(client)
        _wait(client, run_id)                                  # need a completed run (scope etc.)
        assert client.get(f"/runs/{run_id}/chat").json() == []  # empty history
        # a normal question
        r = client.post(f"/runs/{run_id}/chat", json={"message": "Why didn't you find a CSRF bug?"}).json()
        assert r["reply"] and "CSRF" in r["reply"] and r["generated"] == []
        # history now has the user + assistant turn
        hist = client.get(f"/runs/{run_id}/chat").json()
        assert [m["role"] for m in hist] == ["user", "assistant"]
        # a test-generation request writes a file into generated/ (never the repo)
        r2 = client.post(f"/runs/{run_id}/chat",
                         json={"message": "Generate a test suite that would catch CWE-89"}).json()
        assert "test_generated_sample.py" in r2["generated"]
        gen = client.get(f"/runs/{run_id}/generated").json()
        assert any(f["name"] == "test_generated_sample.py" for f in gen)
        # chat on an unknown run is a 404
        assert client.post("/runs/NOPE/chat", json={"message": "hi"}).status_code == 404
    finally:
        app.state.ledger.close()
        _force_rmtree(tmp_path / "runs")


def test_quality_endpoint(tmp_path):
    app, client = _client(tmp_path)
    try:
        # empty ledger / no feedback -> judged 0, accept_rate null, no crash
        q0 = client.get("/quality").json()
        assert q0["accept_rate"]["judged"] == 0 and q0["headline"]["real_world_accept_rate"] is None
        # seed a finding + record triager feedback on the app's ledger
        app.state.ledger.record_finding(program_name="acme", run_id="R", dedup_key="k",
                                        title="t", verdict="confirmed", validated_severity="High")
        app.state.ledger.record_triager_feedback(program_name="acme", dedup_key="k", accepted=True)
        q1 = client.get("/quality").json()
        assert q1["accept_rate"]["accepted"] == 1 and q1["headline"]["real_world_accept_rate"] == 1.0
    finally:
        app.state.ledger.close()


def test_costs_endpoint(tmp_path):
    app, client = _client(tmp_path)
    try:
        # empty ledger -> zeros, no crash
        c0 = client.get("/costs").json()
        assert c0["totals"]["runs"] == 0 and c0["by_model"] == []
        # seed the app's ledger and re-query
        app.state.ledger.log_call(run_id="R", stage="audit", model="sonnet",
                                  prompt_sha256="h", output_tokens=1000, cost_usd=0.30)
        c1 = client.get("/costs").json()
        assert c1["totals"]["cost_usd"] == 0.3 and c1["totals"]["runs"] == 1
        assert c1["by_model"][0]["model"] == "sonnet"
        # recommend now appends the observed average to its rationale
        rec = client.post("/recommend", json={"target": "standard"}).json()
        assert "average $0.30" in rec["rationale"]
        # by_archetype: groups per-run cost by the archetype recorded in meta.json
        rd = tmp_path / "runs" / "R"
        rd.mkdir(parents=True, exist_ok=True)
        (rd / "meta.json").write_text(json.dumps({"archetype": "plugin_extension"}))
        c2 = client.get("/costs").json()
        arch = {a["archetype"]: a for a in c2["by_archetype"]}
        assert arch["plugin_extension"]["cost_usd"] == 0.3
        assert arch["plugin_extension"]["label"] == "Plugin / Extension / Mod"
    finally:
        app.state.ledger.close()


def test_fixes_endpoint(tmp_path):
    app, client = _client(tmp_path)
    try:
        run_id = _start(client)
        _wait(client, run_id)
        # before generating: no report, empty patches
        assert client.get(f"/runs/{run_id}/fixes").json() is None
        assert client.get(f"/runs/{run_id}/patches").json() == []
        # generate + verify on the mock runner (free)
        r = client.post(f"/runs/{run_id}/fixes", json={"verify": True})
        report = r.json()
        assert report["patched"] == 3 and report["verified"] == 3
        # now readable, with patch diffs listed
        assert client.get(f"/runs/{run_id}/fixes").json()["count"] == 3
        patches = client.get(f"/runs/{run_id}/patches").json()
        assert {p["name"] for p in patches} == {"FULL-001.diff", "AUTHZ-002.diff", "FULL-003.diff"}
        assert all(p["content"].startswith(("---", "diff")) for p in patches)
        # the fixes_report artifact is whitelisted
        assert client.get(f"/runs/{run_id}/artifacts/fixes_report").json()["run_id"] == run_id
    finally:
        app.state.ledger.close()


def test_fixes_requires_validated_findings(tmp_path):
    app, client = _client(tmp_path)
    try:
        run_id = _start(client, dry_run=True)   # stops after recon, no validated findings
        _wait(client, run_id)
        assert client.post(f"/runs/{run_id}/fixes", json={}).status_code == 409
    finally:
        app.state.ledger.close()


def test_research_toggle_off(tmp_path):
    app, client = _client(tmp_path)
    try:
        run_id = _start(client, research=False)
        st = _wait(client, run_id)
        names = [s["name"] for s in st["stages"]]
        assert "research" not in names and names[:2] == ["ingest", "recon"]
    finally:
        app.state.ledger.close()


def test_models_endpoint(tmp_path):
    app, client = _client(tmp_path)
    try:
        m = client.get("/models").json()
        ids = {b["id"] for b in m["backends"]}
        assert {"mock", "headless", "codex"} <= ids
        claude = next(b for b in m["backends"] if b["id"] == "headless")
        assert any("opus" in x["id"] for x in claude["models"])
        codex = next(b for b in m["backends"] if b["id"] == "codex")
        assert "ollama" in codex["oss_providers"]
        assert any(p["model"] == "gpt-5.5" for p in m["pricing"])   # price table exposed
    finally:
        app.state.ledger.close()


def test_benchmark_endpoint(tmp_path):
    app, client = _client(tmp_path)
    try:
        assert client.get("/benchmark").json() is None        # none yet
        (tmp_path / "runs").mkdir(exist_ok=True)
        (tmp_path / "runs" / "benchmark_report.json").write_text(
            json.dumps({"suite": "s", "totals": {"precision": 1.0, "recall": 1.0, "f1": 1.0,
                                                 "tp": 3, "fp": 0, "fn": 0, "cases": 1}}))
        rep = client.get("/benchmark").json()
        assert rep["totals"]["f1"] == 1.0 and rep["suite"] == "s"
    finally:
        app.state.ledger.close()


def test_knowledge_endpoint(tmp_path):
    app, client = _client(tmp_path)
    try:
        idx = client.get("/knowledge").json()
        assert "plugin_extension" in idx and isinstance(idx["plugin_extension"], list)
        assert idx["plugin_extension"][0]["cwe"].startswith("CWE-")
    finally:
        app.state.ledger.close()


def test_health_and_404s(tmp_path):
    app, client = _client(tmp_path)
    try:
        assert client.get("/health").json()["ok"] is True
        assert client.get("/runs/NOPE").status_code == 404
        assert client.post("/runs/NOPE/cancel").status_code == 404
        assert client.get("/runs/NOPE/report").status_code == 404
    finally:
        app.state.ledger.close()
