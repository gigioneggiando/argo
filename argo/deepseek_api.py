"""DeepSeek cloud Chat Completions with a confined toolbox and volatile history.

The request journal contains accounting only. Provider bodies, private reasoning,
headers and tool arguments must never be persisted by this adapter.
"""
from __future__ import annotations

import asyncio
import json
import math
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

import httpx

from .api_tools import Toolbox, ToolError, bound_tool_result
from .config import DEEPSEEK_API_BASE_URL, DEEPSEEK_CONTEXT_MARGIN, PipelineConfig
from .ledger import Ledger
from .model_catalog import DEEPSEEK_PRICING_SNAPSHOT_ID, get_model_spec
from .runner import AgentRunner, LLMResult, RunnerCancelled, RunnerError, sanitize_metadata
from .rendering import sha256_text

MAX_BODY_BYTES = 16 * 1024 * 1024


class _Failure(Exception):
    def __init__(self, kind):
        self.kind = kind


def equivalent_model(requested: str, returned: str) -> bool:
    a, b = get_model_spec(requested), get_model_spec(returned)
    return requested == returned or bool(a and b and a.provider == b.provider == 'deepseek'
                                        and a.model_id == b.model_id)


def _integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _sync(coro):
    """Also usable by callers already on an event loop; no nested asyncio.run."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    values, errors = [], []
    def worker():
        try:
            values.append(asyncio.run(coro))
        except BaseException as exc:
            errors.append(exc)
    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()
    if errors:
        raise errors[0]
    return values[0]


class DeepSeekApiRunner(AgentRunner):
    def __init__(self, config: PipelineConfig, ledger: Ledger, *,
                 transport: httpx.AsyncBaseTransport | None = None):
        super().__init__(config, ledger)
        self._transport = transport

    def _api_key(self) -> str:
        key = (self.config.deepseek_api_key or os.environ.get('ARGO_DEEPSEEK_API_KEY')
               or os.environ.get('DEEPSEEK_API_KEY') or '').strip()
        if not key or key == '<redacted>':
            raise RunnerError('deepseek-api requires a runtime API key',
                              failure_kind='credential_bootstrap')
        return key

    def _invoke(self, *, prompt, work_dir, model, repo_dir, allowed, disallowed,
                policy=None, stage, run_id, label, session_budget_usd=None, timeout_s=None,
                run_dir=None):
        if policy is not None and policy.network:
            raise RunnerError('deepseek-api has no web tools', failure_kind='unsupported_stage_tool')
        key = self._api_key()
        if session_budget_usd is None or not math.isfinite(session_budget_usd):
            raise RunnerError('deepseek-api requires an explicit finite budget',
                              failure_kind='budget_reached')
        return _sync(self._session(prompt=prompt, work_dir=Path(work_dir), model=model,
                     repo_dir=Path(repo_dir) if repo_dir else None, allowed=allowed, key=key,
                     stage=stage, run_id=run_id, budget=session_budget_usd,
                     run_dir=Path(run_dir) if run_dir else Path(work_dir).parent,
                     timeout=timeout_s if timeout_s is not None else self.config.session_timeout_s))

    async def _session(self, *, prompt, work_dir, model, repo_dir, allowed, key,
                       stage, run_id, budget, timeout, run_dir):
        cfg = self.config
        deadline = time.monotonic() + max(0, timeout)
        tb = Toolbox(repo_dir=repo_dir, work_dir=work_dir, allow_write='Write' in allowed,
                     deadline=deadline, cancel_event=self.cancel_event)
        tools = tb.schemas()
        messages = [dict(role='system', content=(
            'Use only the supplied tools. No shell, execution or network is available. '
            f'Repository: {tb.repo_real} (read only). Write artifacts only in {tb.work_real}. '
            'Finish with a nonempty plain text answer.')),
            dict(role='user', content=prompt)]
        aid = uuid.uuid4().hex
        journal_dir = run_dir / '.argo_sessions'
        for root in (repo_dir, work_dir):
            if root and journal_dir.resolve().is_relative_to(root.resolve()):
                raise RunnerError('accounting journal must be outside tool roots',
                                  failure_kind='artifact_isolation_failed')
        journal_dir.mkdir(parents=True, exist_ok=True)
        journal = journal_dir / f'deepseek-{aid}.jsonl'
        spec = get_model_spec(model)
        raw = dict(text='', input_tokens=0, output_tokens=0, tool_calls=0, cost_usd=0.,
                   served_models=[], failure_kind=None, stop_reason='stop')
        md = dict(accounting_version=1, accounting_id=aid, request_count=0,
                  unknown_request_count=0, unknown_reserved_usd=0., usage_complete=True,
                  accounting_complete=True, input_cache_hit_tokens=0, input_cache_miss_tokens=0,
                  cache_breakdown_unavailable=False, deepseek_thinking=cfg.deepseek_thinking,
                  resolved_effort=cfg.deepseek_reasoning_effort if cfg.deepseek_thinking == 'enabled'
                  else 'provider_default', pricing_snapshot_id=DEEPSEEK_PRICING_SNAPSHOT_ID)
        if cfg.deepseek_thinking == 'enabled':
            md['deepseek_reasoning_effort'] = cfg.deepseek_reasoning_effort
        if spec:
            md.update(catalog_declared_version=spec.declared_version, catalog_as_of=spec.verified_at)
        raw['metadata'] = md

        def check():
            if self.cancel_event is not None and self.cancel_event.is_set():
                raise RunnerCancelled('DeepSeek session cancelled')
            if time.monotonic() >= deadline:
                raise _Failure('timeout')

        def log(event, **fields):
            if 'summary' in fields:
                fields['summary'] = {k: v for k, v in fields['summary'].items() if k != 'text'}
            # flush+fsync before sending: a crash leaves a reconcilable outstanding intent.
            with journal.open('ab') as fh:
                record = dict(event=event, run_id=run_id, stage=stage, model=model,
                              accounting_id=aid, request_index=md['request_count'],
                              pid=os.getpid(), prompt_sha256=sha256_text(prompt), **fields)
                fh.write((json.dumps(record, separators=(',', ':')) + '\n').encode())
                fh.flush()
                os.fsync(fh.fileno())

        async def interruptible(awaitable):
            task = asyncio.ensure_future(awaitable)
            try:
                while not task.done():
                    check()
                    await asyncio.wait({task}, timeout=min(.05, max(0., deadline-time.monotonic())))
                check()
                return task.result()
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        async def receive(client, payload):
            remaining = deadline - time.monotonic()
            async with client.stream('POST', DEEPSEEK_API_BASE_URL + '/chat/completions',
                    headers={'Authorization': 'Bearer ' + key}, json=payload,
                    timeout=httpx.Timeout(remaining)) as resp:
                body = bytearray()
                async for chunk in resp.aiter_bytes():
                    if len(body) + len(chunk) > MAX_BODY_BYTES:
                        raise _Failure('response_limit')
                    body.extend(chunk)
                return resp.status_code, resp.headers.get('retry-after'), bytes(body)

        def observe(data, reserve):
            usage = data.get('usage')
            usage = usage if isinstance(usage, dict) else {}
            complete = all(_integer(usage.get(k)) for k in ('prompt_tokens', 'completion_tokens'))
            if not complete:
                md['usage_complete'] = md['accounting_complete'] = False
                md['unknown_request_count'] += 1
                md['unknown_reserved_usd'] += reserve
            inp = usage['prompt_tokens'] if _integer(usage.get('prompt_tokens')) else 0
            out = usage['completion_tokens'] if _integer(usage.get('completion_tokens')) else 0
            hit, miss = usage.get('prompt_cache_hit_tokens'), usage.get('prompt_cache_miss_tokens')
            if not (_integer(hit) and _integer(miss) and hit + miss == inp):
                if 'prompt_cache_hit_tokens' in usage or 'prompt_cache_miss_tokens' in usage:
                    md['accounting_complete'] = False
                hit, miss = 0, inp
                md['cache_breakdown_unavailable'] = True
            raw['input_tokens'] += inp
            raw['output_tokens'] += out
            md['input_cache_hit_tokens'] += hit
            md['input_cache_miss_tokens'] += miss
            priced = get_model_spec(data.get('model')) if isinstance(data.get('model'), str) else None
            priced = priced if priced and priced.provider == 'deepseek' else spec
            raw['cost_usd'] += (hit*priced.input_cache_hit_per_million +
                               miss*priced.input_per_million + out*priced.output_per_million)/1e6

        last, repeats, ids = None, 0, set()
        try:
            if spec is None or spec.provider != 'deepseek' or not spec.pricing_known:
                raise _Failure('model_unavailable')
            async with httpx.AsyncClient(transport=self._transport, trust_env=False,
                                        follow_redirects=False, verify=True) as client:
                while True:
                    payload = dict(model=model, messages=messages, tools=tools, tool_choice='auto',
                                   max_tokens=cfg.deepseek_api_max_tokens, stream=False,
                                   thinking={'type': cfg.deepseek_thinking})
                    if cfg.deepseek_thinking == 'enabled':
                        payload['reasoning_effort'] = cfg.deepseek_reasoning_effort
                    # UTF-8 byte count deliberately overestimates tokens, including all history.
                    estimate = len(json.dumps(payload, ensure_ascii=False).encode('utf-8'))
                    if estimate + cfg.deepseek_api_max_tokens + DEEPSEEK_CONTEXT_MARGIN > cfg.deepseek_api_context_window:
                        raise _Failure('context_limit')
                    reserve = (estimate*spec.input_per_million +
                               cfg.deepseek_api_max_tokens*spec.output_per_million)/1e6
                    for retry in range(4):
                        check()
                        if md['request_count'] >= cfg.deepseek_api_max_requests:
                            raise _Failure('request_limit')
                        used = raw['cost_usd'] + md['unknown_reserved_usd']
                        run_remaining = (cfg.budget_usd-self.ledger.run_budget_spent(run_id)
                                         if cfg.budget_usd is not None else budget)
                        if used + reserve > min(budget, run_remaining):
                            raise _Failure('budget_reached')
                        md['request_count'] += 1
                        log('intent', reserve_usd=reserve, max_tokens=cfg.deepseek_api_max_tokens)
                        try:
                            status, retry_after, body = await interruptible(receive(client, payload))
                        except (httpx.HTTPError, _Failure, RunnerCancelled):
                            md['unknown_request_count'] += 1
                            md['unknown_reserved_usd'] += reserve
                            md['usage_complete'] = md['accounting_complete'] = False
                            log('unknown', summary=raw)
                            raise
                        if status == 200:
                            try:
                                data = json.loads(body)
                                if not isinstance(data, dict):
                                    raise ValueError()
                            except (ValueError, UnicodeError):
                                md['unknown_request_count'] += 1
                                md['unknown_reserved_usd'] += reserve
                                md['usage_complete'] = md['accounting_complete'] = False
                                raise _Failure('invalid_response') from None
                            observe(data, reserve)
                            log('observed', summary=raw)
                            break
                        kind = {400:'invalid_request', 401:'auth_failed', 403:'auth_failed',
                                402:'credits_exhausted', 422:'invalid_request',
                                429:'rate_limited', 500:'unknown_retryable',
                                503:'unknown_retryable'}.get(status, 'invalid_request')
                        log('rejected', status=status)
                        if status not in (429, 500, 503) or retry == 3:
                            raise _Failure(kind)
                        delay = 2. ** retry
                        if status == 429 and retry_after:
                            try:
                                delay = float(retry_after)
                            except ValueError:
                                try:
                                    delay = (parsedate_to_datetime(retry_after) - datetime.now(timezone.utc)).total_seconds()
                                except (ValueError, TypeError, OverflowError):
                                    delay = 2. ** retry
                            if not math.isfinite(delay) or delay < 0:
                                delay = 2. ** retry
                        if delay >= deadline - time.monotonic():
                            raise _Failure(kind)
                        await interruptible(asyncio.sleep(delay))
                    returned = data.get('model')
                    if isinstance(returned, str) and returned in sanitize_metadata({'api_returned_model':returned}).values():
                        md['api_returned_model'] = returned
                        if returned not in raw['served_models']:
                            raw['served_models'].append(returned)
                        if not equivalent_model(model, returned) and not cfg.allow_model_substitution:
                            raise _Failure('model_mismatch')
                    elif returned is not None:
                        raise _Failure('invalid_response')
                    md.update(sanitize_metadata({'system_fingerprint': data.get('system_fingerprint')}))
                    choices = data.get('choices')
                    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
                        raise _Failure('invalid_response')
                    choice = choices[0]
                    if choice.get('index') != 0 or isinstance(choice.get('index'), bool):
                        raise _Failure('invalid_response')
                    msg, finish = choice.get('message'), choice.get('finish_reason')
                    # Retain a bounded diagnostic label, never arbitrary provider strings.
                    known_finishes = ('stop', 'tool_calls', 'length', 'content_filter',
                                      'insufficient_system_resource', 'aborted')
                    log('response_finish', finish_reason=(
                        finish if isinstance(finish, str) and finish in known_finishes else 'unknown'))
                    if not isinstance(msg, dict) or msg.get('role') != 'assistant':
                        raise _Failure('invalid_response')
                    content, calls = msg.get('content'), msg.get('tool_calls')
                    if content is not None and not isinstance(content, str):
                        raise _Failure('invalid_response')
                    if not calls:
                        if finish != 'stop' or not isinstance(content, str) or not content.strip():
                            raise _Failure('invalid_response')
                        raw['text'] = content.replace(key, '<redacted>')
                        break
                    if finish != 'tool_calls' or not isinstance(calls, list):
                        raise _Failure('invalid_response')
                    batch, batch_ids = [], set()
                    for call in calls:
                        if not isinstance(call, dict):
                            raise _Failure('invalid_response')
                        cid, fn = call.get('id'), call.get('function')
                        if (not isinstance(cid, str) or not cid or len(cid) > 256 or cid in ids
                            or cid in batch_ids or call.get('type') != 'function'
                            or not isinstance(fn, dict) or not isinstance(fn.get('name'), str)
                            or not isinstance(fn.get('arguments'), str)):
                            raise _Failure('invalid_response')
                        batch_ids.add(cid)
                        try:
                            args = json.loads(fn['arguments'])
                            if not isinstance(args, dict):
                                raise ValueError()
                        except ValueError:
                            args = None
                        batch.append((cid, fn['name'], fn['arguments'], args))
                    if raw['tool_calls'] + len(batch) > (cfg.session_max_turns or 150):
                        raise _Failure('turn_limit_exceeded')
                    # Keep only protocol fields in volatile history, including private reasoning.
                    assistant = dict(role='assistant', content=content, tool_calls=calls)
                    if 'reasoning_content' in msg:
                        if not isinstance(msg['reasoning_content'], str):
                            raise _Failure('invalid_response')
                        assistant['reasoning_content'] = msg['reasoning_content']
                    messages.append(assistant)
                    ids.update(batch_ids)
                    for cid, name, arguments, args in batch:
                        check()
                        size = len(json.dumps(payload, ensure_ascii=False).encode('utf-8'))
                        if size + cfg.deepseek_api_max_tokens + DEEPSEEK_CONTEXT_MARGIN > cfg.deepseek_api_context_window:
                            raise _Failure('context_limit')
                        remaining = (cfg.budget_usd - self.ledger.run_budget_spent(run_id)
                                     if cfg.budget_usd is not None else budget)
                        if raw['cost_usd'] + md['unknown_reserved_usd'] >= min(budget, remaining):
                            raise _Failure('budget_reached')
                        sig = (name, arguments)
                        repeats = repeats + 1 if sig == last else 1
                        last = sig
                        if repeats > 4:
                            raise _Failure('tool_loop')
                        self._activity('DeepSeek tool step')
                        try:
                            result = tb.dispatch(name, args) if args is not None else 'ERROR: invalid arguments'
                        except ToolError:
                            result = 'ERROR: tool denied'
                        raw['tool_calls'] += 1
                        messages.append(dict(role='tool', tool_call_id=cid,
                                             content=bound_tool_result(result)))
        except _Failure as exc:
            raw['failure_kind'] = raw['stop_reason'] = exc.kind
        except httpx.HTTPError:
            raw['failure_kind'] = raw['stop_reason'] = 'unknown_retryable'
        except RunnerCancelled:
            raw['failure_kind'] = raw['stop_reason'] = 'cancelled'
        finally:
            # No volatile history or provider response is reachable from this summary.
            raw['metadata'] = sanitize_metadata(md)
        log('final', summary=raw)
        return raw

    def parse_envelope(self, raw: dict, *, model: str, prompt_sha256: str,
                       work_dir: Path) -> LLMResult:
        md = sanitize_metadata(raw['metadata'])
        served = tuple(raw['served_models'])
        return LLMResult(text=raw['text'], model=model, prompt_sha256=prompt_sha256,
            work_dir=work_dir, input_tokens=raw['input_tokens'], output_tokens=raw['output_tokens'],
            cost_usd=raw['cost_usd'], num_turns=raw['tool_calls'], stop_reason=raw['stop_reason'],
            is_error=bool(raw['failure_kind']), failure_kind=raw['failure_kind'], raw=raw,
            requested_model=model, served_model=served[0] if len(served) == 1 else None,
            served_models=served, metadata=md, cost_source='estimated_peak' if md['usage_complete'] and md['accounting_complete']
            else ('estimated_partial' if raw['cost_usd'] else 'unknown'))


def _process_alive(pid: int | None) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    if os.name == 'nt':
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        handle = kernel.OpenProcess(0x100000, False, pid)
        if not handle:
            return ctypes.get_last_error() == 5  # access denied: conservatively active
        try:
            return kernel.WaitForSingleObject(handle, 0) == 258
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def reconcile_journals(run_dir: Path, ledger: Ledger, run_id: str) -> None:
    """Recover one aggregate per orphan attempt; never restore private model history.

    A still-live owner blocks reconciliation. PID reuse can conservatively block a
    stale journal; an operator must resolve that ambiguity rather than reset spend.
    """
    directory = Path(run_dir) / '.argo_sessions'
    if not directory.exists():
        return
    if directory.is_symlink() or directory.resolve().parent != Path(run_dir).resolve():
        raise RunnerError('unsafe accounting directory', failure_kind='artifact_isolation_failed')
    for path in directory.glob('deepseek-*.jsonl'):
        if path.is_symlink() or path.stat().st_size > 16*1024*1024:
            raise RunnerError('unsafe accounting journal', failure_kind='invalid_response')
        records = []
        for line in path.read_bytes().splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                # A final torn append is expected after process termination.
                if line == path.read_bytes().splitlines()[-1]:
                    break
                raise RunnerError('malformed accounting journal', failure_kind='invalid_response') from None
            if not isinstance(record, dict) or record.get('run_id') != run_id:
                raise RunnerError('accounting journal run mismatch', failure_kind='invalid_response')
            records.append(record)
        if not records:
            continue
        last = records[-1]
        aid = last.get('accounting_id')
        if not sanitize_metadata({'accounting_id':aid}):
            raise RunnerError('invalid accounting identity', failure_kind='invalid_response')
        if ledger.has_accounting_id(aid):
            continue
        if last['event'] != 'final' and _process_alive(last.get('pid')):
            raise RunnerError('accounting owner is still active', failure_kind='artifact_isolation_failed')
        summary = next((r['summary'] for r in reversed(records) if 'summary' in r), {})
        md = sanitize_metadata(summary.get('metadata', {}))
        pending = {}
        for record in records:
            index = record['request_index']
            if record['event'] == 'intent':
                pending[index] = record['reserve_usd']
            elif record['event'] in ('observed', 'unknown', 'rejected'):
                pending.pop(index, None)
        extra = sum(pending.values())
        md.update(accounting_version=1, accounting_id=aid,
                  request_count=last['request_index'],
                  unknown_request_count=md.get('unknown_request_count',0)+len(pending),
                  unknown_reserved_usd=md.get('unknown_reserved_usd',0.)+extra)
        if pending or last['event'] != 'final':
            md.update(usage_complete=False, accounting_complete=False)
        md = sanitize_metadata(md)
        ledger.log_call(run_id=run_id, stage=last['stage'], model=last['model'],
            prompt_sha256=last.get('prompt_sha256', ''),
            input_tokens=summary.get('input_tokens',0), output_tokens=summary.get('output_tokens',0),
            cost_usd=summary.get('cost_usd',0.), num_turns=summary.get('tool_calls',0),
            failure_kind=summary.get('failure_kind') or ('interrupted' if last['event'] != 'final' else None),
            cost_source='estimated_peak' if md.get('usage_complete') else 'estimated_partial',
            served_models=summary.get('served_models',()), metadata=md, accounting_id=aid,
            unknown_reserved_usd=md['unknown_reserved_usd'], effort=md.get('resolved_effort'))
