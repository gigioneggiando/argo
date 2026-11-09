"""HTTP API surface for the Mistral backends: /models advertises both, RunConfig maps onto
PipelineConfig, keys are never echoed, and the OSINT-stage preflight answers 400 (no model call)."""

import json

import pytest

from fastapi.testclient import TestClient

from argo.config import MISTRAL_API_BALANCED, PipelineConfig
from server.app import create_app
from server.jobs import JobManager
from server.schemas import RunConfig, RunRequest

from conftest import BRIEF, FIXTURES, REPO

KEY = "mstrl_SERVER_SENTINEL_42"


def _client(tmp_path):
    cfg = PipelineConfig(runner="mock", runs_dir=tmp_path / "runs",
                         ledger_path=tmp_path / "ledger.sqlite", fixtures_dir=FIXTURES)
    return TestClient(create_app(cfg, token="t"), base_url="http://127.0.0.1:8000",
                      headers={"X-Argo-Token": "t"})


def _req(**config):
    return RunRequest(brief=BRIEF.read_text(encoding="utf-8"), repo=str(REPO),
                      config=RunConfig(**config))


def test_models_lists_both_mistral_backends(tmp_path):
    body = _client(tmp_path).get("/models").json()
    by_id = {b["id"]: b for b in body["backends"]}
    api, vibe = by_id["mistral-api"], by_id["mistral-vibe"]
    assert api["default_model"] == MISTRAL_API_BALANCED and api["offline_only"] is True
    assert any(m["id"] == "mistral-large-4" and m["input_per_million"] == 0.7 for m in api["models"])
    assert isinstance(vibe["installed"], bool)
    assert all(m["cli_available"] for m in vibe["models"])


def test_run_config_maps_mistral_fields_and_redacts_key(tmp_path):
    jm = JobManager(PipelineConfig(runner="mock", runs_dir=tmp_path))
    cfg = jm._config_for(_req(runner="mistral-api", mistral_api_model="mistral-small-2603",
                              mistral_api_key=KEY, research_enabled=False,
                              corroborate_enabled=False))
    assert cfg.runner == "mistral-api" and cfg.model_for("audit") == "mistral-small-2603"
    assert cfg.mistral_api_key == KEY and not cfg.research_enabled
    from argo.config import pipeline_config_to_dict
    assert KEY not in json.dumps(pipeline_config_to_dict(cfg))


def test_osint_stage_on_mistral_is_400_before_any_call(tmp_path):
    client = _client(tmp_path)
    r = client.post("/runs", json={"brief": BRIEF.read_text(encoding="utf-8"), "repo": str(REPO),
                                   "config": {"runner": "mistral-api", "mistral_api_key": KEY}})
    assert r.status_code == 400 and "web tools" in r.json()["detail"]
    assert KEY not in r.text


def test_stage_runner_reroutes_research_off_mistral(tmp_path):
    jm = JobManager(PipelineConfig(runner="mock", runs_dir=tmp_path))
    cfg = jm._config_for(_req(runner="mistral-vibe",
                              stage_runners={"research": "headless", "corroborate": "headless"}))
    assert cfg.runner == "mistral-vibe" and cfg.stage_runners["research"] == "headless"


def test_settings_cannot_persist_a_key(tmp_path):
    client = _client(tmp_path)
    client.put("/settings", json={"runner": "mistral-api", "mistral_api_key": KEY})
    assert KEY not in json.dumps(client.get("/settings").json())


@pytest.mark.parametrize("runner,stage_runners", [
    ("mistral-vibe", {}), ("mock", {"audit": "mistral-vibe"}),
])
def test_stored_auth_reaches_job_config(tmp_path, runner, stage_runners):
    jm = JobManager(PipelineConfig(runner="mock", runs_dir=tmp_path))
    cfg = jm._config_for(_req(runner=runner, stage_runners=stage_runners,
                              mistral_vibe_auth="stored", research_enabled=False,
                              corroborate_enabled=False))
    assert cfg.mistral_vibe_auth == "stored"
    assert cfg.stage_runners.get("audit", cfg.runner) == "mistral-vibe"


def test_run_config_defaults_to_key():
    assert RunConfig().mistral_vibe_auth == "key"


@pytest.mark.parametrize("backend", ["mistral-api", "mistral-vibe"])
def test_job_preflight_uses_the_ui_research_switch(tmp_path, backend):
    req = RunRequest(brief=BRIEF.read_text(encoding="utf-8"), repo=str(REPO), research=False,
                     config=RunConfig(runner=backend, corroborate_enabled=False))
    cfg = JobManager(PipelineConfig(runs_dir=tmp_path))._config_for(req)
    assert cfg.research_enabled is False


def test_local_vibe_job_disables_both_networked_stages_before_preflight(tmp_path):
    req = RunRequest(repo=str(REPO), config=RunConfig(runner="mistral-vibe",
                                                    mistral_vibe_auth="stored"))
    cfg = JobManager(PipelineConfig(runs_dir=tmp_path))._config_for(req)
    assert not cfg.research_enabled and not cfg.corroborate_enabled


def test_stored_plus_key_http_error_does_not_echo_the_key(tmp_path):
    client = _client(tmp_path)
    r = client.post("/runs", json={"repo": str(REPO), "research": False,
        "config": {"runner": "mistral-vibe", "mistral_vibe_auth": "stored",
                   "mistral_vibe_api_key": KEY, "corroborate_enabled": False}})
    assert r.status_code == 400
    assert KEY not in r.text


def test_invalid_auth_http_enum_is_a_schema_error(tmp_path):
    r = _client(tmp_path).post("/runs", json={"repo": str(REPO),
        "config": {"runner": "mistral-vibe", "mistral_vibe_auth": "auto"}})
    assert r.status_code == 422
