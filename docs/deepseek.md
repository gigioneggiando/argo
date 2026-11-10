# DeepSeek API

`deepseek-api` is the cloud Chat Completions backend. It sends authorized source
and tool results to DeepSeek. A local DeepSeek through Codex OSS is a different
transport: cloud prices, key requirements and provider selection do not apply to it.

Set `ARGO_DEEPSEEK_API_KEY` in the executing process environment (or
`DEEPSEEK_API_KEY`). Explicit runtime `deepseek_api_key` takes precedence, followed
by those two variables. There is no key argument on the CLI. Credentials are
redacted from saved run configuration; HTTP input is excluded from responses and
settings. Resume and chat need a fresh runtime key after a process restart.

## Configuration

| PipelineConfig / HTTP field | Default | CLI (pipeline and show-routing) |
|---|---|---|
| deepseek_api_model | deepseek-flash | --deepseek-api-model |
| deepseek_thinking | enabled | --deepseek-thinking |
| deepseek_reasoning_effort | high | --deepseek-reasoning-effort |
| deepseek_api_max_tokens | 32768 | --deepseek-max-tokens |
| deepseek_api_context_window | 262144 | --deepseek-context-window |
| deepseek_api_max_requests | 128 | --deepseek-max-requests |

Thinking accepts `enabled` or `disabled`; effort accepts `low`, `high`, `max` and
is omitted on the wire when thinking is disabled. Output is 1–393216 tokens;
context is at most 1000000, and output plus an 8192-token margin must fit inside
it. These integer caps reject booleans. Context estimation includes the full
volatile history and tool schemas and deliberately overestimates using UTF-8 byte
length. There is no automatic compaction: `context_limit` stops before sending.
HTTP request caps include retries. Tool calls have a separate cap (150 when unset).

Use `--stage-model STAGE=MODEL` or HTTP `config.models` for individual stages.
Explicit stage selection wins over a flat model override, which wins over the
profile's base. Calibration selects Pro for a DeepSeek audit; smoke selects Flash
and one focus. Smoke still spends tokens and requires separate approval.

HTTP additionally accepts `session_timeout_s`, `session_max_turns`,
`session_max_cost_usd` and `max_focuses`. An explicit timeout cannot be enlarged by
the built-in stage timeout. Settings/profiles store preferences and never a key.

## Tools and transport

The shared toolbox exposes read/list/glob/grep and stage-authorized scratch
writes, with the bounds in [guardrails](guardrails.md#3a-api-runner-tool-boundary-argoapi_toolspy).
It provides a tool/path boundary, not an OS sandbox. The model has no shell,
process, browser, network or subagent tool. Entire tool batches are validated
before dispatch; ID collisions or an oversized batch produce no batch effects.
Unknown tools and invalid arguments receive bounded denials.

Research and corroboration require a separately selected web-capable route or an
explicit opt-out. The browser keeps those choices visible; source-only runs
disable both through the usual local-review workflow. Inference itself has egress.

The endpoint is fixed at `https://api.deepseek.com/chat/completions`. Each
invocation owns its TLS-verified HTTPX client, disables redirects and environment
proxies, bounds the response body to 16 MiB and applies one absolute deadline to
requests, keep-alive bytes and retry waits. Custom proxies/gateways/CA overrides
are outside this version. Cancellation interrupts HTTP and prevents further tools.

401 is `auth_failed`; 402 is `credits_exhausted` and only an already configured
alternative provider may be used. 400/422 are terminal `invalid_request`, with
no identical retry. 429 and 500/503 have at most three additional HTTP attempts;
valid Retry-After values must fit the remaining deadline. Error bodies and
private reasoning never enter diagnostics, activity, journals or result envelopes.
Length/refusal/empty/malformed responses are errors, never successful artifacts.

## Cost and recovery

An explicit finite run budget is required. Every request must fit an operational
reservation based on conservative input sizing and the configured output cap.
The peak pricing snapshot is `deepseek-2026-11-09-peak`, USD per million tokens:

| Alias | Cache hit input | Cache miss input | Output |
|---|---:|---:|---:|
| deepseek-flash | 0.006 | 0.30 | 1.20 |
| deepseek-v4-pro | 0.044 | 1.32 | 3.96 |

Cost is `(hit*hit_rate + miss*miss_rate + completion*output_rate)/1000000`.
Reasoning tokens are part of completion and are never counted twice. Missing or
inconsistent cache breakdown uses the full input at the miss rate. Missing usage
or an ambiguous request keeps its reservation separate from the known cost.
Labels are `estimated_peak`, `estimated_partial` or `unknown`, not provider invoices.
Budget gates include known cost plus unknown reserves. Concurrent sessions can
overshoot the global budget: this is not an atomic billing cap.

The accounting-only journal lives at the run's `.argo_sessions` outside tool
roots. Intent is fsynced before sending, observations afterward. Resume reconciles
orphan attempts into one ledger aggregate per accounting ID; already logged IDs
are ignored. An intent without an outcome retains a reserve. A live owner blocks
reconciliation; PID reuse may conservatively require operator investigation.
Recovery starts a new attempt and never loads private reasoning from disk.

Requested alias, API returned model, dated catalog declaration and fingerprint
remain distinct. `deepseek-v4-flash` is an official Flash alias. Neither model
supports a claimed physical pin. A different returned model fails closed unless
substitution was explicitly allowed; received usage is retained.

## Authorized live validation only

The following is an example for a separately approved synthetic fixture run;
do not execute it as a free discovery command:

```bash
python -m argo.cli pipeline --repo tests/fixtures/repo --runner deepseek-api --deepseek-api-model deepseek-flash --deepseek-thinking enabled --deepseek-reasoning-effort high --deepseek-max-tokens 32768 --budget 3 --session-budget 1 --timeout 360 --max-turns 60 --parallel 1 --max-focuses 1 --no-research --no-corroborate
```

Equivalent HTTP payload (also paid execution, not a second automatic test):

```json
{"repo":"tests/fixtures/repo","research":false,"config":{"runner":"deepseek-api","deepseek_api_model":"deepseek-flash","deepseek_thinking":"enabled","deepseek_reasoning_effort":"high","deepseek_api_max_tokens":32768,"budget_usd":3,"session_max_cost_usd":1,"session_timeout_s":360,"session_max_turns":60,"parallel":1,"max_focuses":1,"corroborate_enabled":false}}
```

Offline tests use MockTransport plus a loopback heartbeat server, synthetic keys,
schema validation and the real AgentRunner/factory path. They do not certify live
provider behavior. Before release, separately approve and run Flash and Pro with
thinking enabled/high and disabled, then a complete Flash fixture pipeline.
Recheck official availability/pricing then. Token streaming, web tools, strict
beta mode and automatic compaction remain outside this version.
