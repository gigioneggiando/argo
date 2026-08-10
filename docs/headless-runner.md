# Headless runner — driving the real `claude` CLI

`HeadlessClaudeRunner` (`argo/runner.py`) runs each LLM step as a non-interactive
`claude -p` subprocess. This is the one part the `MockClaudeRunner` cannot cover, so it was
hardened against the real CLI (Claude Code **v2.1.178**) and a live smoke run.

## The command

```
claude -p --output-format json --model <model> \
       --permission-mode bypassPermissions \
       [--max-budget-usd <cap>] \
       --add-dir <repo>  --allowedTools Read Grep Glob Write \
       --disallowedTools Bash Edit MultiEdit NotebookEdit WebFetch WebSearch Task ...
```

- `--output-format json` is used **only for metadata** (session id, cost, stop reason). Artifacts
  travel as files in the scratch cwd, never through stdout.
- `--permission-mode bypassPermissions` avoids interactive prompts that would hang a headless
  run. It does **not** widen the toolset: `--disallowedTools` still hard-blocks every
  network/mutation tool, and `--add-dir` provides a no-internet sandbox, so the blast radius is
  the writable scratch dir only.
- `--max-budget-usd` is the native per-session cost kill (see Caps).
- There is **no `--max-turns`** in this CLI version — turn limiting is done orchestrator-side.

The prompt is written to the process **stdin as UTF-8** (the assets contain characters such as
`→` that Windows' default cp1252 cannot encode).

## The result envelope

A real success envelope (`tests/fixtures/real_envelope.json`, captured from a live call):

```json
{ "type":"result", "subtype":"success", "is_error":false, "api_error_status":null,
  "num_turns":1, "result":"ok", "stop_reason":"end_turn",
  "session_id":"de1a…", "total_cost_usd":0.0160078,
  "usage":{"input_tokens":9,"output_tokens":42, …}, … }
```

`parse_result_envelope()` reads the **verified** field names:
`result`, `total_cost_usd`, `usage.{input,output}_tokens`, `num_turns`, `session_id`, `is_error`,
`stop_reason`/`subtype`/`terminal_reason`, `api_error_status`.

It is **strict on success envelopes**: a missing required field raises `RunnerError` ("CLI
output shape drift?") rather than silently logging a $0/0-token call. On `is_error` envelopes it
is lenient, so a dying session's partial output can still be recovered.

## Caps (Step 3)

| Cap | Mechanism |
|---|---|
| Per-session cost | native `--max-budget-usd` = `min(session cap, remaining run budget)` — kills the session mid-flight |
| Per-session turns | orchestrator tripwire (`session_max_turns`); aborts after the call with a clear error (no native pre-emption exists) |
| Per-session wall-clock | `subprocess` `timeout` (`config.timeout_for(stage)`) |
| **Per-run** budget | `--budget`: a hard ceiling checked against real ledger spend before each session; once hit, remaining sessions are skipped (logged) |

The per-run budget uses **real** cost — `cost_usd` in the ledger is the envelope's
`total_cost_usd`.

## Error handling (Step 4)

All failures produce a clear error with `run_id` + `stage`, never a silent crash:

- **API error** (`is_error` + `api_error_status`, e.g. auth/rate-limit) → logged, then `RunnerError`.
- **Recoverable error** (`is_error`, no `api_error_status`, e.g. budget/turn limit reached
  mid-write) → returned, so the stage can glob the scratch dir for partial artifacts.
- **Non-zero exit / empty / malformed stdout** → `RunnerError` with the stderr tail (this is what
  an auth/startup failure looks like).
- **Timeout** → `RunnerError` (now `retryable=True` — a hang is not assumed to be deterministic).

Every `RunnerError` these paths raise also carries a classified `failure_kind`
(`moderation_flagged`/`credits_exhausted`/`rate_limited`/`timeout`/`unknown_retryable`/`None`), so
`FallbackRunner` can apply a failure-appropriate cooldown instead of one flat default — see
[architecture.md](architecture.md#the-agentrunner-abstraction) for the full breakdown (this
classification applies to both backends via the shared `AgentRunner.run()`, not just Codex, even
though Codex's exit_1/0-token crash signature is where it matters most in practice).

**Partial recovery:** `stages/audit.py` and `stages/recon.py` catch a hard `RunnerError` and try
to recover whatever the session already wrote to its scratch dir before failing — so one timed-out
or crashed session does not lose a whole focus (audit) or the generated prompts (recon).

## Real-output robustness

Real models don't emit perfectly schema-clean JSON; these normalizations live in the stages
(all logged, never silent):

- **Ingest** strips `null`-valued optional fields before the schema gate (`"rate_limits": null`
  → absent).
- **Audit** validates **per finding** and keeps the conformant ones (one malformed finding no
  longer voids a whole focus), after coercing structured string-fields to strings, Title-casing
  enums (`CRITICAL` → `Critical`), and mapping common field aliases (`affected_files` →
  `affected`, `exploit_scenarios` → `exploit_scenario`).
- **Audit** also injects the actual `findings_schema.json` into the prompt, so the model emits the
  exact keys/enums instead of guessing them from the prose finding-format.

## Windows / cross-platform notes

- The launcher is resolved via `shutil.which("claude")` because on Windows `claude` is a
  `claude.CMD` npm shim and `subprocess` does not apply PATHEXT to a bare name. The resolved full
  path launches fine.
- Subprocess I/O is forced to `encoding="utf-8"` (see above).
- The pytest temp base is pinned (`pytest.ini`) so read-only repo copies don't trip Windows temp
  rotation.

## The `--smoke` run

`pipeline --smoke` is a de-risked, cheap, **real** end-to-end check that exercises the whole
headless seam. It uses the cheapest models (Sonnet for the guardrail-gated recon synthesis, Haiku
elsewhere), runs **one** audit focus, and applies a low budget + short timeout + tight caps. It
defaults `--brief`/`--repo` to the bundled fixtures, so `python -m argo.cli pipeline --smoke`
just works.

A successful run (against the fixture repo) produced, for ~$1 over 7 calls: a complete `REPORT.md`
with 3 confirmed findings + DRAFT bundles, with Stage 4 correctly **refuting** a stub finding —
validating ingest → recon → audit → validate → report on the real CLI.

Use `--smoke` as the first thing to run after changing anything in the runner, the flags, or the
envelope parsing.
