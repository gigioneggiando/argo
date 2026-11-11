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
                                     'insufficient_system_resource', 'mystery', REASON, None, {}])
def test_non_final_reasons_fail_with_usage(tmp_path, finish):
    runner, ledger = setup_runner(tmp_path, lambda req: httpx.Response(200, json=response(finish=finish)))
    with pytest.raises(RunnerError):
        invoke(runner, tmp_path)
    assert ledger.run_cost('synthetic') > 0
    events = [json.loads(line) for path in (tmp_path / 'run' / '.argo_sessions').glob('*.jsonl')
              for line in path.read_text(encoding='utf-8').splitlines()]
    finishes = [event['finish_reason'] for event in events if event['event'] == 'response_finish']
    allowed = ('length', 'content_filter', 'aborted', 'insufficient_system_resource')
    assert finishes == [finish if isinstance(finish, str) and finish in allowed else 'unknown']
    assert REASON not in json.dumps(events) and KEY not in json.dumps(events)
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


def test_journal_reconciliation_is_idempotent(tmp_path):
    from argo.deepseek_api import reconcile_journals
    runner, ledger = setup_runner(tmp_path, lambda req: httpx.Response(200, json=response()))
    invoke(runner, tmp_path)
    other = Ledger(tmp_path / 'after-crash.sqlite')
    reconcile_journals(tmp_path / 'run', other, 'synthetic')
    assert other.run_cost('synthetic') == ledger.run_cost('synthetic')
    reconcile_journals(tmp_path / 'run', other, 'synthetic')
    assert len(other.run_calls('synthetic')) == 1
    other.close()
    ledger.close()


def test_orphan_intent_is_reserved(tmp_path):
    from argo.deepseek_api import reconcile_journals
    directory = tmp_path / '.argo_sessions'
    directory.mkdir()
    record = dict(event='intent', accounting_id='0123456789abcdef', run_id='synthetic',
                  stage='audit', model='deepseek-flash', request_index=1, reserve_usd=.05)
    (directory / 'deepseek-0123456789abcdef.jsonl').write_bytes((json.dumps(record)+'\n').encode())
    with Ledger(tmp_path / 'after-crash.sqlite') as ledger:
        reconcile_journals(tmp_path, ledger, 'synthetic')
        assert ledger.run_budget_spent('synthetic') == pytest.approx(.05)
        assert ledger.run_cost('synthetic') == 0


@pytest.mark.parametrize('status', [500, 503])
def test_ambiguous_server_retry_reserves_each_attempt_before_retry(tmp_path, status):
    requests = []
    def handler(req):
        requests.append(req)
        return httpx.Response(status, text='temporary server error')

    runner, ledger = setup_runner(tmp_path, handler, session_max_cost_usd=.05)
    with pytest.raises(RunnerError) as exc:
        invoke(runner, tmp_path)

    # The first ambiguous attempt consumes an operational reserve, so this cap
    # cannot also cover a second request. The provider must not be retried.
    assert exc.value.failure_kind == 'budget_reached'
    assert len(requests) == 1
    accounting = ledger.accounting_summary('synthetic')
    assert accounting['unknown_reserved_usd'] > 0
    assert accounting['incomplete_calls'] == 1
    events = [json.loads(line) for path in (tmp_path / 'run' / '.argo_sessions').glob('*.jsonl')
              for line in path.read_text(encoding='utf-8').splitlines()]
    ambiguous = [event for event in events if event['event'] == 'unknown']
    assert len(ambiguous) == 1
    assert ambiguous[0]['status'] == status
    assert ambiguous[0]['reserve_usd'] > 0
    assert 'body' not in ambiguous[0] and 'response' not in ambiguous[0]
    ledger.close()


def test_ambiguous_server_retry_keeps_reserve_after_later_success(tmp_path):
    statuses = []
    def handler(req):
        if len(statuses) < 2:
            status = (500, 503)[len(statuses)]
            statuses.append(status)
            return httpx.Response(status, text='temporary server error')
        return httpx.Response(200, json=response())

    runner, ledger = setup_runner(tmp_path, handler)
    result = invoke(runner, tmp_path)

    assert statuses == [500, 503]
    assert result.metadata['request_count'] == 3
    assert result.metadata['unknown_request_count'] == 2
    assert result.metadata['unknown_reserved_usd'] > 0
    assert result.metadata['usage_complete'] is False
    assert result.metadata['accounting_complete'] is False
    assert ledger.accounting_summary('synthetic')['unknown_reserved_usd'] == pytest.approx(
        result.metadata['unknown_reserved_usd'])
    events = [json.loads(line) for path in (tmp_path / 'run' / '.argo_sessions').glob('*.jsonl')
              for line in path.read_text(encoding='utf-8').splitlines()]
    ambiguous = [event for event in events if event['event'] == 'unknown']
    assert [event['status'] for event in ambiguous] == statuses
    assert sum(event['reserve_usd'] for event in ambiguous) == pytest.approx(
        result.metadata['unknown_reserved_usd'])
    ledger.close()


def test_orphan_server_error_journal_preserves_reserve_idempotently(tmp_path):
    from argo.deepseek_api import reconcile_journals

    directory = tmp_path / '.argo_sessions'
    directory.mkdir()
    aid = '0123456789abcdef'
    reserve = .05
    summary = {'cost_usd': 0., 'input_tokens': 0, 'output_tokens': 0,
               'tool_calls': 0, 'served_models': [], 'failure_kind': 'unknown_retryable',
               'metadata': {'accounting_version': 1, 'accounting_id': aid,
                   'request_count': 1, 'unknown_request_count': 1,
                   'unknown_reserved_usd': reserve, 'usage_complete': False,
                   'accounting_complete': False}}
    records = [
        {'event': 'intent', 'accounting_id': aid, 'run_id': 'synthetic',
         'stage': 'audit', 'model': 'deepseek-flash', 'request_index': 1,
         'reserve_usd': reserve, 'pid': -1},
        {'event': 'unknown', 'accounting_id': aid, 'run_id': 'synthetic',
         'stage': 'audit', 'model': 'deepseek-flash', 'request_index': 1,
         'reserve_usd': reserve, 'status': 503, 'summary': summary, 'pid': -1},
    ]
    path = directory / f'deepseek-{aid}.jsonl'
    path.write_text(''.join(json.dumps(row) + '\n' for row in records), encoding='utf-8')

    with Ledger(tmp_path / 'after-crash.sqlite') as ledger:
        reconcile_journals(tmp_path, ledger, 'synthetic')
        assert ledger.run_cost('synthetic') == 0
        assert ledger.run_budget_spent('synthetic') == pytest.approx(reserve)
        assert ledger.accounting_summary('synthetic')['unknown_reserved_usd'] == pytest.approx(reserve)
        reconcile_journals(tmp_path, ledger, 'synthetic')
        assert len(ledger.run_calls('synthetic')) == 1


def test_factory_run_reads_repo_and_writes_schema_valid_artifact(tmp_path):
    from argo.runner import build_runner
    from argo.schemas import validate_findings
    repo = tmp_path/'repo'
    repo.mkdir()
    source = repo/'main.py'
    source.write_bytes(b'print("synthetic fixture")\n')
    artifact = json.loads((Path(__file__).parent/'fixtures/happy/audit/audit_p1_full_scope.findings.json').read_text())
    requests = []
    def handler(req):
        payload = json.loads(req.content)
        requests.append(payload)
        if len(requests) == 1:
            return httpx.Response(200, json=response(calls=[call(name='read_file',
                args=json.dumps({'path':str(source)}))], finish='tool_calls'))
        if len(requests) == 2:
            assert 'synthetic fixture' in payload['messages'][-1]['content']
            return httpx.Response(200, json=response(calls=[call(id='write', name='write_file',
                args=json.dumps({'path':'findings.json','content':json.dumps(artifact)}))], finish='tool_calls'))
        return httpx.Response(200, json=response())
    with Ledger(tmp_path/'factory.sqlite') as ledger:
        runner = build_runner(PipelineConfig(runner='deepseek-api', budget_usd=1,
                                             deepseek_api_key=KEY),ledger)
        runner._transport = httpx.MockTransport(handler)
        result = runner.run(prompt='Synthetic fixture only', run_dir=tmp_path/'run',
            work_dir=tmp_path/'run/scratch', repo_dir=repo, model='deepseek-flash', stage='audit',
            run_id='fixture')
        validate_findings(json.loads((result.work_dir/'findings.json').read_text()))
        assert source.read_bytes() == b'print("synthetic fixture")\n'
        assert len(ledger.run_calls('fixture')) == 1


def test_socket_heartbeat_does_not_extend_total_deadline(tmp_path):
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            self.send_response(200)
            self.end_headers()
            try:
                for _ in range(50):
                    self.wfile.write(b' \n')
                    self.wfile.flush()
                    time.sleep(.02)
            except (BrokenPipeError, ConnectionResetError):
                pass
    server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    class Loopback(httpx.AsyncBaseTransport):
        def __init__(self):
            self.inner = httpx.AsyncHTTPTransport()
        async def handle_async_request(self, request):
            request.url = request.url.copy_with(scheme='http', host='127.0.0.1',port=server.server_port)
            return await self.inner.handle_async_request(request)
        async def aclose(self):
            await self.inner.aclose()
    runner, ledger = setup_runner(tmp_path, lambda req: None, stage_timeouts={'audit':.15})
    runner._transport = Loopback()
    try:
        start = time.monotonic()
        with pytest.raises(RunnerError) as exc:
            invoke(runner,tmp_path)
        assert exc.value.failure_kind == 'timeout'
        assert time.monotonic()-start < 1.5
        assert ledger.run_budget_spent('synthetic') > 0
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)
        ledger.close()


def test_body_cap_is_accounted_without_dispatch(tmp_path, monkeypatch):
    import argo.deepseek_api as ds
    monkeypatch.setattr(ds,'MAX_BODY_BYTES',16)
    runner, ledger = setup_runner(tmp_path, lambda req:httpx.Response(200,text='x'*17))
    with pytest.raises(RunnerError) as exc:
        invoke(runner,tmp_path)
    assert exc.value.failure_kind == 'response_limit'
    assert ledger.run_budget_spent('synthetic') > 0
    ledger.close()


@pytest.mark.parametrize('content', ['', '   ', None])
def test_empty_final_is_error(tmp_path,content):
    runner,ledger=setup_runner(tmp_path,lambda req:httpx.Response(200,json=response(content=content)))
    with pytest.raises(RunnerError) as exc:
        invoke(runner,tmp_path)
    assert exc.value.failure_kind=='invalid_response' and not exc.value.retryable
    ledger.close()


def test_partial_usage_survives_a_later_402(tmp_path):
    count=0
    def handler(req):
        nonlocal count
        count+=1
        return (httpx.Response(200,json=response(calls=[call()],finish='tool_calls'))
                if count==1 else httpx.Response(402,text=REASON))
    runner,ledger=setup_runner(tmp_path,handler)
    with pytest.raises(RunnerError) as exc:
        invoke(runner,tmp_path)
    assert exc.value.failure_kind=='credits_exhausted'
    row=json.loads((tmp_path/'run/llm_log.jsonl').read_text().splitlines()[0])
    assert row['input_tokens']==100 and row['output_tokens']==20 and row['cost_usd']>0
    assert ledger.run_cost('synthetic')==pytest.approx(row['cost_usd'])
    ledger.close()


def test_context_limit_preserves_history_and_stops_before_send(tmp_path):
    requests=[]
    runner,ledger=setup_runner(tmp_path,lambda req:requests.append(req),
                               deepseek_api_context_window=42000)
    with pytest.raises(RunnerError) as exc:
        runner.run(prompt='x'*5000,run_dir=tmp_path/'run',work_dir=tmp_path/'run/scratch',
                   model='deepseek-flash',stage='audit',run_id='synthetic')
    assert exc.value.failure_kind=='context_limit' and not requests
    ledger.close()


def test_context_limit_includes_received_tool_call_before_effect(tmp_path):
    # The assistant response is appended to the shared messages list before the
    # pre-tool size check; its arguments must count before dispatch can write.
    destination = tmp_path / 'run' / 'scratch' / 'oversized.txt'
    oversized = 'x' * 270_000
    data = response(calls=[call(name='write_file', args=json.dumps({
        'path': 'oversized.txt', 'content': oversized}))], finish='tool_calls')
    runner, ledger = setup_runner(tmp_path, lambda req: httpx.Response(200, json=data))

    with pytest.raises(RunnerError) as exc:
        invoke(runner, tmp_path)

    assert exc.value.failure_kind == 'context_limit'
    assert not destination.exists()
    assert ledger.run_cost('synthetic') > 0
    ledger.close()


def test_history_is_auto_compacted_instead_of_failing_at_context_limit(tmp_path):
    # A turn returns a large assistant content; the next top-of-loop estimate crosses
    # the 80% compaction threshold, so the adapter folds history (a tools-free summary
    # request) into [system, user(task + notes)] and continues to a final answer,
    # rather than raising context_limit the way an uncompacted session would.
    from argo.deepseek_api import COMPACT_INSTRUCTION
    seen = []
    def handler(req):
        payload = json.loads(req.content)
        seen.append(payload)
        has_tools = 'tools' in payload
        last = payload['messages'][-1]
        if has_tools and last['content'] == 'Inspect synthetic repo':
            # Round 1: big content forces the history over the threshold next iteration.
            return httpx.Response(200, json=response(
                content='A' * 95_000, calls=[call()], finish='tool_calls'))
        if not has_tools:
            # The compaction request: tools-free, asking for a progress summary.
            assert last['content'] == COMPACT_INSTRUCTION
            return httpx.Response(200, json=response(content='SUMMARY NOTES', finish='stop'))
        # Continuation after compaction: history folded to system + one user message.
        assert len(payload['messages']) == 2
        assert '[Auto-compacted progress notes]' in last['content']
        assert 'SUMMARY NOTES' in last['content'] and 'Inspect synthetic repo' in last['content']
        return httpx.Response(200, json=response(content='FINAL ANSWER', finish='stop'))

    runner, ledger = setup_runner(tmp_path, handler, deepseek_api_max_tokens=4000,
                                  deepseek_api_context_window=120_000)
    result = invoke(runner, tmp_path)
    assert result.text == 'FINAL ANSWER'
    assert not result.is_error and result.failure_kind is None
    # req1 (tools) + compaction (no tools) + continuation (tools) == 3 provider requests.
    assert len(seen) == 3
    assert sum('tools' not in p for p in seen) == 1
    events = [json.loads(line) for path in (tmp_path / 'run' / '.argo_sessions').glob('*.jsonl')
              for line in path.read_text(encoding='utf-8').splitlines()]
    assert any(event['event'] == 'compacted' for event in events)
    ledger.close()


def test_bad_tool_arguments_and_unknown_tool_get_ordered_denials(tmp_path):
    count=0
    def handler(req):
        nonlocal count
        count+=1
        if count==1:
            return httpx.Response(200,json=response(calls=[call('one','exec','{}'),
                call('two','write_file','{invalid')],finish='tool_calls'))
        payload=json.loads(req.content)
        assert [m['tool_call_id'] for m in payload['messages'][-2:]]==['one','two']
        assert all(m['content'].startswith('ERROR:') for m in payload['messages'][-2:])
        return httpx.Response(200,json=response())
    runner,ledger=setup_runner(tmp_path,handler)
    invoke(runner,tmp_path)
    assert not list((tmp_path/'run/scratch').iterdir())
    ledger.close()


def test_rate_retry_is_bounded_and_counts_http(tmp_path):
    count=0
    def handler(req):
        nonlocal count
        count+=1
        return httpx.Response(429,headers={'Retry-After':'0'},text=REASON)
    runner,ledger=setup_runner(tmp_path,handler)
    with pytest.raises(RunnerError) as exc:
        invoke(runner,tmp_path)
    assert count==4 and exc.value.failure_kind=='rate_limited'
    ledger.close()


def test_missing_key_never_constructs_http(tmp_path,monkeypatch):
    import argo.deepseek_api as ds
    monkeypatch.delenv('ARGO_DEEPSEEK_API_KEY',raising=False)
    monkeypatch.delenv('DEEPSEEK_API_KEY',raising=False)
    monkeypatch.setattr(ds.httpx,'AsyncClient',lambda **kw:pytest.fail('HTTP constructed'))
    with Ledger(tmp_path/'key.sqlite') as ledger:
        runner=ds.DeepSeekApiRunner(PipelineConfig(runner='deepseek-api',budget_usd=1),ledger)
        with pytest.raises(RunnerError) as exc:
            invoke(runner,tmp_path)
        assert exc.value.failure_kind=='credential_bootstrap'


def test_three_workers_expose_non_atomic_budget_overshoot(tmp_path):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    barrier=threading.Barrier(3)
    def handler(req):
        barrier.wait(timeout=5)
        data=response()
        data['usage']={'prompt_tokens':100000,'completion_tokens':20000}
        return httpx.Response(200,json=data)
    runner,ledger=setup_runner(tmp_path,handler)
    runner.config=runner.config.with_overrides(budget_usd=.05)
    def worker(index):
        return runner.run(prompt='synthetic concurrent fixture',run_dir=tmp_path/'run',
            work_dir=tmp_path/'run'/f'scratch-{index}',model='deepseek-flash',stage='audit',
            run_id='synthetic')
    with ThreadPoolExecutor(max_workers=3) as pool:
        results=list(pool.map(worker,range(3)))
    assert len(results)==3 and ledger.run_budget_spent('synthetic')>.05
    assert len(ledger.run_calls('synthetic'))==3
    ledger.close()


def test_inconsistent_cache_breakdown_is_conservative_and_incomplete(tmp_path):
    data=response()
    data['usage']['prompt_cache_hit_tokens']=1000
    runner,ledger=setup_runner(tmp_path,lambda req:httpx.Response(200,json=data))
    result=invoke(runner,tmp_path)
    assert result.cost_usd==pytest.approx((100*.30+20*1.20)/1e6)
    assert result.metadata['cache_breakdown_unavailable']
    assert result.metadata['accounting_complete'] is False
    assert result.cost_source=='estimated_partial'
    ledger.close()


def test_later_model_mismatch_stops_before_tools_and_is_recorded(tmp_path):
    count=0
    def handler(req):
        nonlocal count
        count+=1
        data=response(calls=[call(id=str(count))],finish='tool_calls')
        if count==2:
            data['model']='deepseek-v4-pro'
        return httpx.Response(200,json=data)
    runner,ledger=setup_runner(tmp_path,handler)
    with pytest.raises(RunnerError) as exc:
        invoke(runner,tmp_path)
    assert exc.value.failure_kind=='model_mismatch' and count==2
    assert ledger.run_cost('synthetic')>0
    assert ledger.run_model_mismatches('synthetic')
    ledger.close()


def test_production_chain_rejects_real_mock_before_any_provider(tmp_path,monkeypatch):
    from argo.runner import build_runner
    monkeypatch.delenv('ARGO_DEEPSEEK_API_KEY',raising=False)
    monkeypatch.delenv('DEEPSEEK_API_KEY',raising=False)
    with Ledger(tmp_path/'chain.sqlite') as ledger:
        runner=build_runner(PipelineConfig(runner='deepseek-api',runner_fallbacks=['mock'],
                                           budget_usd=1),ledger)
        with pytest.raises(RunnerError) as exc:
            invoke(runner,tmp_path)
        assert exc.value.failure_kind=='invalid_request'
        assert not ledger.run_calls('synthetic')


@pytest.mark.parametrize('limit',['context','budget'])
def test_response_resource_limit_stops_before_tool_effect(tmp_path,limit):
    data=response(calls=[call(name='write_file',args=json.dumps({
        'path':'must-not-exist.txt','content':'unexpected effect'}))],finish='tool_calls')
    if limit=='context':
        data['choices'][0]['message']['reasoning_content']='r'*270000
    else:
        data['usage']={'prompt_tokens':4000000,'completion_tokens':1}
    runner,ledger=setup_runner(tmp_path,lambda req:httpx.Response(200,json=data))
    with pytest.raises(RunnerError) as exc:
        invoke(runner,tmp_path)
    assert exc.value.failure_kind==('context_limit' if limit=='context' else 'budget_reached')
    assert not (tmp_path/'run/scratch/must-not-exist.txt').exists()
    assert ledger.run_cost('synthetic')>0
    ledger.close()
