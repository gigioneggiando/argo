"""Offline HTTP/CLI parity and secret handling for DeepSeek."""
import json

import pytest
from pydantic import ValidationError

from argo.config import PipelineConfig, pipeline_config_to_dict
from server.jobs import JobManager
from server.schemas import RunConfig, RunRequest
from test_mistral_server import _client

KEY = 'synthetic-http-deepseek-key'


def test_http_fields_caps_and_key_are_translated(tmp_path):
    req = RunRequest(repo='synthetic', research=False, config=RunConfig(
        runner='deepseek-api', deepseek_api_key=KEY, budget_usd=3,
        deepseek_api_model='deepseek-v4-pro', deepseek_thinking='disabled',
        deepseek_api_max_tokens=4096, deepseek_api_context_window=32768,
        deepseek_api_max_requests=12, session_timeout_s=45, session_max_turns=8,
        session_max_cost_usd=.5, max_focuses=1, models={'audit':'deepseek-flash'}))
    cfg = JobManager(PipelineConfig(runs_dir=tmp_path))._config_for(req)
    assert cfg.deepseek_api_key == KEY
    assert cfg.model_for('audit') == 'deepseek-flash'
    assert cfg.model_for('recon') == 'deepseek-v4-pro'
    assert cfg.deepseek_thinking == 'disabled'
    assert cfg.deepseek_api_max_tokens == 4096
    assert cfg.timeout_for('recon') <= 45
    assert cfg.session_max_turns == 8 and cfg.session_max_cost_usd == .5
    assert cfg.max_focuses == 1
    assert KEY not in json.dumps(pipeline_config_to_dict(cfg))
    assert KEY not in req.config.model_dump_json()


@pytest.mark.parametrize('field,value', [('deepseek_api_max_tokens', True),
    ('deepseek_api_max_requests',0), ('deepseek_thinking','auto'),
    ('deepseek_reasoning_effort','medium'), ('deepseek_api_context_window',1000001)])
def test_http_invalid_values_rejected(field, value):
    with pytest.raises(ValidationError):
        RunConfig(**{field:value})


def test_models_and_settings_have_no_key(tmp_path):
    client = _client(tmp_path)
    backends = {b['id']:b for b in client.get('/models').json()['backends']}
    assert backends['deepseek-api']['default_model'] == 'deepseek-flash'
    client.put('/settings', json={'runner':'deepseek-api', 'deepseek_thinking':'disabled',
                                  'deepseek_api_key':KEY})
    result = client.get('/settings')
    assert result.json()['deepseek_thinking'] == 'disabled' and KEY not in result.text


def test_validation_error_never_echoes_key(tmp_path, monkeypatch):
    monkeypatch.setattr(JobManager, 'start', lambda *a: pytest.fail('invalid input reached job launch'))
    result = _client(tmp_path).post('/runs', json={'repo':'synthetic', 'config':{
        'runner':'deepseek-api', 'deepseek_api_key':{'nested':KEY},
        'deepseek_api_max_tokens':KEY}})
    assert result.status_code == 422 and KEY not in result.text


def test_cli_config_accepts_deepseek_controls(tmp_path):
    from argo.cli import _build_config
    cfg = _build_config('deepseek-api', None, False, 3, 1, tmp_path, 'happy',
        deepseek_api_model='deepseek-v4-pro', deepseek_thinking='disabled',
        deepseek_max_tokens=4096, deepseek_context_window=32768, deepseek_max_requests=12,
        timeout=45, max_turns=8, session_budget=.5, max_focuses=1,
        stage_models=['audit=deepseek-flash'])
    assert cfg.model_for('audit') == 'deepseek-flash'
    assert cfg.model_for('recon') == 'deepseek-v4-pro'
    assert cfg.deepseek_api_max_tokens == 4096 and cfg.deepseek_api_max_requests == 12


def test_profiles_preserve_deepseek_stage_map_without_key(tmp_path):
    from argo.profiles import apply_profile, save_profile
    cfg = PipelineConfig(runner='deepseek-api', deepseek_api_key=KEY,
                         deepseek_api_stage_models={'audit':'deepseek-v4-pro'})
    path = tmp_path / 'routing.json'
    save_profile(path, cfg, 'custom')
    assert KEY not in path.read_text()
    out = apply_profile(PipelineConfig(), str(path))
    assert out.model_for('audit') == 'deepseek-v4-pro'


def test_costs_expose_unknown_reserves(tmp_path):
    from argo.costs import cost_report
    from argo.ledger import Ledger
    with Ledger(tmp_path/'ledger.sqlite') as ledger:
        ledger.log_call(run_id='r', stage='audit', model='deepseek-flash', prompt_sha256='p',
                        cost_usd=.01, unknown_reserved_usd=.05,
                        metadata={'usage_complete':False})
        totals = cost_report(ledger)['totals']
        assert totals['cost_usd'] == .01
        assert totals['unknown_reserved_usd'] == .05 and totals['incomplete_calls'] == 1


def test_deepseek_preflight_requires_budget_and_runtime_key(tmp_path, monkeypatch):
    monkeypatch.delenv('ARGO_DEEPSEEK_API_KEY', raising=False)
    monkeypatch.delenv('DEEPSEEK_API_KEY', raising=False)
    monkeypatch.setattr(JobManager, 'start', lambda *a: pytest.fail('preflight did not reject'))
    from argo.config import deepseek_run_conflicts
    assert deepseek_run_conflicts(PipelineConfig(runner='deepseek-api'))
    assert deepseek_run_conflicts(PipelineConfig(runner='deepseek-api', budget_usd=1))
    assert not deepseek_run_conflicts(PipelineConfig(runner='deepseek-api', budget_usd=1,
                                                     deepseek_api_key=KEY))


def test_profile_exports_flat_model_and_thinking(tmp_path):
    from argo.profiles import apply_profile, save_profile
    path = tmp_path/'flat.json'
    save_profile(path, PipelineConfig(runner='deepseek-api', deepseek_api_model='deepseek-v4-pro',
                                     deepseek_thinking='disabled'), 'custom')
    cfg = apply_profile(PipelineConfig(), str(path))
    assert cfg.model_for('audit') == 'deepseek-v4-pro' and cfg.deepseek_thinking == 'disabled'


def test_calibration_resolves_stage_backend_first(tmp_path):
    from argo.cli import _build_config
    cfg = _build_config('headless', None, True, 1, 1, tmp_path, 'happy',
                        stage_runners=['audit=deepseek-api'])
    assert cfg.model_for('audit') == 'deepseek-v4-pro'


def test_stream_missing_key_is_409_before_worker_start(tmp_path,monkeypatch):
    import server.app as appmod
    from conftest import FIXTURES
    monkeypatch.delenv('ARGO_DEEPSEEK_API_KEY',raising=False)
    monkeypatch.delenv('DEEPSEEK_API_KEY',raising=False)
    rd=tmp_path/'runs/ds-chat'
    rd.mkdir(parents=True)
    (rd/'scope.json').write_bytes((FIXTURES/'happy/ingest/scope.json').read_bytes())
    (rd/'config.json').write_bytes(json.dumps(pipeline_config_to_dict(PipelineConfig(
        runner='deepseek-api',budget_usd=1,runs_dir=tmp_path/'runs',
        ledger_path=tmp_path/'ledger.sqlite'))).encode())
    with _client(tmp_path) as client:
        client.get('/health')
        original=appmod.threading.Thread
        def guard(*args,**kw):
            if kw.get('name','').startswith('chat-'):
                raise RuntimeError('worker started without key')
            return original(*args,**kw)
        with monkeypatch.context() as patch:
            patch.setattr(appmod.threading,'Thread',guard)
            result=client.post('/runs/ds-chat/chat/stream',json={'message':'synthetic'})
            assert result.status_code==409


@pytest.mark.parametrize('suffix',['chat','chat/stream'])
def test_saved_deepseek_chat_uses_fake_provider_without_private_channel(tmp_path,monkeypatch,suffix):
    import httpx
    from argo.deepseek_api import DeepSeekApiRunner
    from conftest import FIXTURES
    from test_deepseek_protocol import response,REASON
    monkeypatch.setenv('ARGO_DEEPSEEK_API_KEY',KEY)
    rd=tmp_path/'runs/ds-chat'
    rd.mkdir(parents=True)
    (rd/'scope.json').write_bytes((FIXTURES/'happy/ingest/scope.json').read_bytes())
    cfg=PipelineConfig(runner='deepseek-api',budget_usd=1,runs_dir=tmp_path/'runs',
                       ledger_path=tmp_path/'ledger.sqlite',deepseek_thinking='disabled')
    (rd/'config.json').write_bytes(json.dumps(pipeline_config_to_dict(cfg)).encode())
    original=DeepSeekApiRunner.__init__
    def init(self,config,ledger,**kw):
        def handler(req):
            body=json.loads(req.content)
            assert body['thinking']=={'type':'disabled'}
            return httpx.Response(200,json=response(content='Synthetic chat answer'))
        original(self,config,ledger,transport=httpx.MockTransport(handler))
    monkeypatch.setattr(DeepSeekApiRunner,'__init__',init)
    result=_client(tmp_path).post('/runs/ds-chat/'+suffix,json={'message':'Explain synthetic fixture'})
    assert result.status_code==200
    assert 'Synthetic chat answer' in result.text and KEY not in result.text and REASON not in result.text
    if suffix.endswith('stream'):
        events=[json.loads(x) for x in result.text.splitlines() if x.strip()]
        assert [e['type'] for e in events].count('done')==1
        assert not any(e['type']=='error' for e in events)


def test_profile_output_cap_is_resolved_before_context_cross_validation(tmp_path):
    profile=tmp_path/'small-output.json'
    profile.write_bytes(json.dumps({'name':'small-output','flags':{'deepseek_api_max_tokens':4096}}).encode())
    req=RunRequest(repo='synthetic',config=RunConfig(runner='deepseek-api',budget_usd=1,
        deepseek_api_key=KEY,profile=str(profile),deepseek_api_context_window=32768))
    cfg=JobManager(PipelineConfig(runs_dir=tmp_path))._config_for(req)
    assert cfg.deepseek_api_max_tokens==4096 and cfg.deepseek_api_context_window==32768
