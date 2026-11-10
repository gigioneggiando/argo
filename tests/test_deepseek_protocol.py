"""Synthetic provider contracts; never connects to a real provider."""
import json
from pathlib import Path

import httpx
import pytest

from argo.config import PipelineConfig
from argo.ledger import Ledger
from argo.runner import RunnerError

KEY = 'synthetic-deepseek-key'
REASON = 'PRIVATE_REASONING_CANARY'


def response(content='done', calls=None, finish='stop', **extra):
    return dict(model='deepseek-flash', choices=[dict(index=0, finish_reason=finish,
                message=dict(role='assistant', content=content, reasoning_content=REASON,
                             **({'tool_calls': calls} if calls is not None else {})))],
                usage=dict(prompt_tokens=100, completion_tokens=20,
                           prompt_cache_hit_tokens=40, prompt_cache_miss_tokens=60), **extra)


def call(id='one', name='list_dir', args='{}'):
    return dict(id=id, type='function', function=dict(name=name, arguments=args))


def setup_runner(tmp_path, handler, **overrides):
    from argo.deepseek_api import DeepSeekApiRunner
    cfg = PipelineConfig(runner='deepseek-api', budget_usd=1,
                         deepseek_api_key=KEY, **overrides)
    ledger = Ledger(tmp_path / 'ledger.sqlite')
    return DeepSeekApiRunner(cfg, ledger, transport=httpx.MockTransport(handler)), ledger


def invoke(runner, tmp_path):
    return runner.run(prompt='Inspect synthetic repo', run_dir=tmp_path / 'run',
                      work_dir=tmp_path / 'run' / 'scratch', model='deepseek-flash',
                      stage='audit', run_id='synthetic')


@pytest.mark.parametrize('thinking', ['enabled', 'disabled'])
def test_wire_and_reasoning_never_persist(tmp_path, thinking):
    requests = []
    def handler(req):
        payload = json.loads(req.content)
        requests.append(payload)
        assert str(req.url) == 'https://api.deepseek.com/chat/completions'
        assert req.headers['Authorization'] == 'Bearer ' + KEY
        assert KEY not in req.content.decode()
        assert payload['thinking'] == {'type': thinking}
        assert ('reasoning_effort' in payload) == (thinking == 'enabled')
        assert payload['max_tokens'] == 32768 and payload['stream'] is False
        assert not {'temperature', 'parallel_tool_calls', 'response_format', 'extra_body'} & payload.keys()
        if len(requests) == 1:
            return httpx.Response(200, json=response(calls=[call()], finish='tool_calls'))
        assert payload['messages'][-2]['reasoning_content'] == REASON
        assert payload['messages'][-1]['tool_call_id'] == 'one'
        return httpx.Response(200, json=response())
    runner, ledger = setup_runner(tmp_path, handler, deepseek_thinking=thinking)
    result = invoke(runner, tmp_path)
    assert result.input_tokens == 200 and result.output_tokens == 40
    assert result.num_turns == 1 and result.metadata['request_count'] == 2
    assert result.cost_usd == pytest.approx(2 * (40*.006 + 60*.30 + 20*1.20)/1e6)
    assert REASON not in json.dumps(result.raw)
    for path in (tmp_path / 'run').rglob('*'):
        if path.is_file():
            assert REASON.encode() not in path.read_bytes()
            assert KEY.encode() not in path.read_bytes()
    ledger.close()


@pytest.mark.parametrize('finish', ['length', 'content_filter', 'aborted',
                                     'insufficient_system_resource', 'mystery'])
def test_non_final_reasons_fail_with_usage(tmp_path, finish):
    runner, ledger = setup_runner(tmp_path, lambda req: httpx.Response(200, json=response(finish=finish)))
    with pytest.raises(RunnerError):
        invoke(runner, tmp_path)
    assert ledger.run_cost('synthetic') > 0
    ledger.close()


@pytest.mark.parametrize('status,kind', [(400,'invalid_request'), (401,'auth_failed'),
                                      (402,'credits_exhausted'), (422,'invalid_request')])
def test_errors_are_sanitized_and_not_retried(tmp_path, status, kind):
    seen = []
    def handler(req):
        seen.append(req)
        return httpx.Response(status, text=KEY + REASON + ' quota 429')
    runner, ledger = setup_runner(tmp_path, handler)
    with pytest.raises(RunnerError) as exc:
        invoke(runner, tmp_path)
    assert exc.value.failure_kind == kind and len(seen) == 1
    assert KEY not in str(exc.value) and REASON not in str(exc.value)
    ledger.close()


@pytest.mark.parametrize('calls,cap', [([call('same'), call('same')], 5),
                                    ([call('a'), call('b')], 1)])
def test_batch_validation_before_effects(tmp_path, monkeypatch, calls, cap):
    from argo.api_tools import Toolbox
    effects = []
    monkeypatch.setattr(Toolbox, 'dispatch', lambda *args: effects.append(args) or 'ok')
    runner, ledger = setup_runner(tmp_path, lambda req: httpx.Response(
        200, json=response(calls=calls, finish='tool_calls')), session_max_turns=cap)
    with pytest.raises(RunnerError):
        invoke(runner, tmp_path)
    assert not effects and ledger.run_cost('synthetic') > 0
    ledger.close()


def test_official_alias_is_preserved_without_mismatch(tmp_path):
    def handler(req):
        data = response()
        data['model'] = 'deepseek-v4-flash'
        return httpx.Response(200, json=data)
    runner, ledger = setup_runner(tmp_path, handler)
    result = invoke(runner, tmp_path)
    assert result.served_model == 'deepseek-v4-flash'
    ledger.close()


def test_journal_has_no_final_content(tmp_path):
    runner, ledger = setup_runner(tmp_path, lambda req: httpx.Response(
        200, json=response(content='FINAL_CONTENT_CANARY')))
    invoke(runner, tmp_path)
    journals = list((tmp_path / 'run' / '.argo_sessions').glob('*.jsonl'))
    assert journals
    assert all('FINAL_CONTENT_CANARY' not in p.read_text() for p in journals)
    ledger.close()


def test_missing_usage_keeps_reserve(tmp_path):
    data = response()
    del data['usage']
    runner, ledger = setup_runner(tmp_path, lambda req: httpx.Response(200, json=data))
    result = invoke(runner, tmp_path)
    assert result.cost_source == 'unknown'
    assert result.metadata['unknown_reserved_usd'] > 0
    assert ledger.run_budget_spent('synthetic') > ledger.run_cost('synthetic')
    ledger.close()


def test_ambiguous_transport_keeps_reserve(tmp_path):
    def handler(req):
        raise httpx.ReadError(KEY + REASON)
    runner, ledger = setup_runner(tmp_path, handler)
    with pytest.raises(RunnerError) as exc:
        invoke(runner, tmp_path)
    assert KEY not in str(exc.value) and REASON not in str(exc.value)
    assert ledger.run_budget_spent('synthetic') > 0
    ledger.close()


def test_cancel_during_http_is_prompt_and_accounted(tmp_path):
    import asyncio
    import threading
    from argo.runner import RunnerCancelled
    async def handler(req):
        runner.cancel_event.set()
        await asyncio.sleep(10)
        return httpx.Response(200, json=response())
    runner, ledger = setup_runner(tmp_path, handler)
    runner.cancel_event = threading.Event()
    with pytest.raises(RunnerCancelled):
        invoke(runner, tmp_path)
    assert ledger.run_budget_spent('synthetic') > 0
    ledger.close()


def test_context_and_reservation_stop_before_http(tmp_path):
    calls = []
    runner, ledger = setup_runner(tmp_path, lambda req: calls.append(req),
                                  session_max_cost_usd=0.000001)
    with pytest.raises(RunnerError) as exc:
        invoke(runner, tmp_path)
    assert exc.value.failure_kind == 'budget_reached' and not calls
    ledger.close()
