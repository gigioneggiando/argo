"""``runner = mistral-api``: Mistral models through the Mistral developer API, with an Argo-owned
tool loop. Platform-independent (Windows/Linux/macOS): no external agent CLI, no OS sandbox.

Why a native loop (Codex + a Mistral provider cannot write files on Windows: its sandbox blocks
the shell and it offers no apply_patch to non-OpenAI models): the Chat Completions API only *proposes*
tool calls -- nothing touches the host unless Argo executes them. So the safety boundary is this
module's dispatcher, which exposes exactly the capabilities Argo grants every backend:

  * ``read_file`` / ``list_dir`` / ``glob`` / ``grep`` -- read-only, confined to the audited repo copy
    and the session's scratch dir (paths resolved with ``realpath``, so a symlink pointing outside
    either root is refused);
  * ``write_file`` -- only inside the scratch dir, only when the stage grants ``Write``, size-capped,
    never through an existing symlink.

There is no shell, no process execution and no network tool: the networked OSINT stages
(``research``/``corroborate``) are refused up front (``unsupported_stage_tool``) -- route them to
another backend with ``--stage-runner``. The repo copy is additionally protected by ingest's chmod
and checked after every session by ``AgentRunner``'s repo-integrity fingerprint.

The key comes from ``config.mistral_api_key``, else ``ARGO_MISTRAL_API_KEY``, else
``MISTRAL_API_KEY``; it is only ever sent as the ``Authorization`` header and scrubbed from every
error/log string.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

import httpx

# The tool dispatcher (path policy, bounded IO/regex, atomic writes) is shared with the other
# API-native runners; re-exported here for existing importers.
from .api_tools import MAX_TOOL_RESULT_CHARS, Toolbox, ToolError  # noqa: F401
from .config import MISTRAL_API_BASE_URL, PipelineConfig, estimate_cost_usd, model_cost_source
from .ledger import Ledger
from .runner import AgentRunner, LLMResult, RunnerCancelled, RunnerError, _redact_secrets

DEFAULT_MAX_TURNS = 150
DEFAULT_CONTEXT_WINDOW = 128_000          # tokens; mistral-medium/large are >= 128k
CHARS_PER_TOKEN = 3.5                     # conservative estimate for budgeting the context
KEEP_RECENT_TOOL_RESULTS = 8              # never elide the most recent tool outputs
LOOP_REPEAT_LIMIT = 4                     # identical consecutive tool calls -> tool_loop
HTTP_TIMEOUT_S = 300
MAX_RATE_LIMIT_RETRIES = 8
MAX_TRANSIENT_RETRIES = 4
_ELIDED = "[earlier tool output elided to fit the context window; call the tool again if needed]"


def _system_prompt(tb: Toolbox) -> str:
    repo = f"The audited repository is at {tb.repo_real} (read-only). " if tb.repo_real else ""
    write = ("Write every output file with write_file; relative paths resolve to the working "
             f"directory {tb.work_real}. " if tb.allow_write else "This session cannot write files. ")
    return ("You are running inside Argo, an authorized source-code security audit pipeline. "
            "You act only through the provided tools: there is no shell, no code execution and no "
            f"network. {repo}{write}Read the code before making claims. When the task is "
            "complete, reply with your final answer as plain text and stop calling tools.")


# ===================================================================================== runner
class MistralApiRunner(AgentRunner):
    """Mistral Chat Completions + Argo-owned tool loop (see module docstring)."""

    def __init__(self, config: PipelineConfig, ledger: Ledger, *, client: httpx.Client | None = None,
                 sleep=time.sleep):
        super().__init__(config, ledger)
        self._client = client
        self._sleep = sleep

    # -- credentials ------------------------------------------------------------------------
    def _api_key(self) -> str:
        key = (self.config.mistral_api_key or os.environ.get("ARGO_MISTRAL_API_KEY")
               or os.environ.get("MISTRAL_API_KEY") or "").strip()
        if not key:
            raise RunnerError(
                "runner=mistral-api needs a Mistral API key: set ARGO_MISTRAL_API_KEY (or "
                "MISTRAL_API_KEY) in the environment", retryable=False,
                failure_kind="credential_bootstrap")
        return key

    def _scrub(self, text) -> str:
        try:
            key = self._api_key()
        except RunnerError:
            key = None
        return _redact_secrets(str(text), key)

    # -- HTTP -------------------------------------------------------------------------------
    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=HTTP_TIMEOUT_S)
        return self._client

    def _check_cancel(self, deadline: float, ctx: str):
        ev = self.cancel_event
        if ev is not None and ev.is_set():
            raise RunnerCancelled("session cancelled mid-stage")
        if time.monotonic() > deadline:
            raise RunnerError(f"mistral-api session timed out ({ctx})", retryable=True,
                              failure_kind="timeout")

    def _wait(self, seconds: float, deadline: float, ctx: str):
        """Back off in 1 s steps so a cancel or the session deadline interrupts the wait."""
        remaining = float(seconds)
        while remaining > 0:
            self._check_cancel(deadline, ctx)
            step = min(1.0, remaining)
            self._sleep(step)
            remaining -= step

    def _chat(self, payload: dict, *, deadline: float, ctx: str) -> dict:
        url = (self.config.mistral_api_base_url or MISTRAL_API_BASE_URL).rstrip("/") \
            + "/chat/completions"
        headers = {"Authorization": f"Bearer {self._api_key()}", "Content-Type": "application/json",
                   "Accept": "application/json"}
        rate_tries = transient_tries = 0
        while True:
            self._check_cancel(deadline, ctx)
            try:
                resp = self._http().post(url, headers=headers, json=payload,
                                         timeout=max(5.0, min(HTTP_TIMEOUT_S,
                                                              deadline - time.monotonic())))
            except httpx.HTTPError as exc:
                transient_tries += 1
                if transient_tries > MAX_TRANSIENT_RETRIES:
                    raise RunnerError(f"mistral-api network error ({ctx}): {self._scrub(exc)}",
                                      retryable=True, failure_kind="unknown_retryable") from None
                self._wait(2 ** transient_tries, deadline, ctx)
                continue
            status = resp.status_code
            if status == 200:
                try:
                    return resp.json()
                except ValueError:
                    raise RunnerError(f"mistral-api returned non-JSON ({ctx})", retryable=True,
                                      failure_kind="unknown_retryable") from None
            body = self._scrub(resp.text[:800])
            if status in (401, 403):
                raise RunnerError(f"Mistral rejected the API key (HTTP {status}, {ctx}); check "
                                  "ARGO_MISTRAL_API_KEY/MISTRAL_API_KEY -- not retrying",
                                  retryable=False, failure_kind="auth_failed")
            if status == 402:
                raise RunnerError(f"Mistral account has no usable credit (HTTP 402, {ctx}): {body}",
                                  retryable=True, failure_kind="credits_exhausted")
            if status == 429:
                rate_tries += 1
                if rate_tries > MAX_RATE_LIMIT_RETRIES:
                    raise RunnerError(f"mistral-api rate limited ({ctx}) after {rate_tries - 1} "
                                      f"waits: {body}", retryable=True, failure_kind="rate_limited",
                                      retry_after=resp.headers.get("retry-after"))
                try:
                    wait = float(resp.headers.get("retry-after", ""))
                except ValueError:
                    wait = min(60.0, 2.0 ** rate_tries)
                self._wait(max(1.0, min(wait, 120.0)), deadline, ctx)
                continue
            if status >= 500:
                transient_tries += 1
                if transient_tries > MAX_TRANSIENT_RETRIES:
                    raise RunnerError(f"mistral-api server error HTTP {status} ({ctx}): {body}",
                                      retryable=True, failure_kind="unknown_retryable")
                self._wait(2 ** transient_tries, deadline, ctx)
                continue
            raise RunnerError(f"mistral-api rejected the request HTTP {status} ({ctx}): {body}",
                              retryable=False, failure_kind="invalid_request")

    # -- context management -----------------------------------------------------------------
    def _fit_context(self, messages: list[dict]) -> int:
        """Elide the oldest tool outputs once the conversation nears the context window."""
        window = self.config.mistral_api_context_window or DEFAULT_CONTEXT_WINDOW
        budget = int(window * 0.7 * CHARS_PER_TOKEN)
        size = sum(len(m.get("content") or "") + len(json.dumps(m.get("tool_calls") or ""))
                   for m in messages)
        tool_idx = [i for i, m in enumerate(messages) if m.get("role") == "tool"]
        elided = 0
        for i in tool_idx[:-KEEP_RECENT_TOOL_RESULTS]:
            if size <= budget:
                break
            old = messages[i].get("content") or ""
            if old == _ELIDED:
                continue
            size -= len(old) - len(_ELIDED)
            messages[i]["content"] = _ELIDED
            elided += 1
        return elided

    # -- the loop ---------------------------------------------------------------------------
    def _invoke(self, *, prompt, work_dir, model, repo_dir, allowed, disallowed, policy=None,
                stage, run_id, label, session_budget_usd=None, timeout_s=None) -> dict:
        if policy is not None and policy.network:
            raise RunnerError(
                f"runner=mistral-api has no web tools, so stage {stage!r} cannot run on it: pass "
                f"--no-{stage} or route it elsewhere (--stage-runner {stage}=headless|codex|gemini)",
                retryable=False, failure_kind="unsupported_stage_tool")
        self._api_key()                           # fail before any work if the key is missing
        work_dir = Path(work_dir)
        work_dir.mkdir(parents=True, exist_ok=True)
        tb = Toolbox(repo_dir=Path(repo_dir) if repo_dir else None, work_dir=work_dir,
                     allow_write="Write" in (allowed or []))
        timeout = timeout_s or self.config.session_timeout_s
        deadline = time.monotonic() + timeout
        max_turns = self.config.session_max_turns or DEFAULT_MAX_TURNS
        # Outside the session's working dir, like Codex's event log: the model cannot read or
        # tamper with its own transcript.
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", label or stage)
        events = work_dir.parent / ".argo_sessions" / f"{work_dir.name}.mistral.{safe}.jsonl"
        events.parent.mkdir(parents=True, exist_ok=True)
        messages = [{"role": "system", "content": _system_prompt(tb)},
                    {"role": "user", "content": prompt}]
        tools = tb.schemas()
        in_tok = out_tok = turns = tool_calls_n = elided = 0
        served: list[str] = []
        last_sig, repeats = None, 0
        text, stop = "", "end_turn"
        with open(events, "a", encoding="utf-8") as ev:
            def log(obj):
                ev.write(self._scrub(json.dumps(obj, ensure_ascii=False)) + "\n")
                ev.flush()

            while True:
                ctx = f"stage={stage}, label={label}, turn={turns + 1}"
                elided += self._fit_context(messages)
                data = self._chat({"model": model, "messages": messages, "tools": tools,
                                   "tool_choice": "auto", "parallel_tool_calls": True},
                                  deadline=deadline, ctx=ctx)
                turns += 1
                usage = data.get("usage") or {}
                in_tok += int(usage.get("prompt_tokens") or 0)
                out_tok += int(usage.get("completion_tokens") or 0)
                if data.get("model") and data["model"] not in served:
                    served.append(data["model"])
                choice = (data.get("choices") or [{}])[0]
                msg = choice.get("message") or {}
                calls = msg.get("tool_calls") or []
                content = msg.get("content") or ""
                if isinstance(content, list):        # some models return content chunks
                    content = "".join(c.get("text", "") for c in content if isinstance(c, dict))
                log({"turn": turns, "finish_reason": choice.get("finish_reason"),
                     "tool_calls": [c.get("function", {}).get("name") for c in calls],
                     "usage": usage})
                if not calls:
                    text, stop = content, choice.get("finish_reason") or "stop"
                    break
                if session_budget_usd is not None and \
                        estimate_cost_usd(model, in_tok, out_tok) >= session_budget_usd:
                    # In-session cost cap (Claude has --max-budget-usd natively). Returns normally
                    # so the call is ledgered; artifacts written so far stay collectable.
                    log({"budget_stop": True, "cap_usd": session_budget_usd})
                    text, stop = content, "budget_exceeded"
                    break
                messages.append({"role": "assistant", "content": content, "tool_calls": calls})
                self._activity(content)                  # interim reasoning shown to a live viewer
                for call in calls:
                    fn = call.get("function") or {}
                    name, raw_args = fn.get("name", ""), fn.get("arguments") or "{}"
                    sig = (name, raw_args)
                    repeats = repeats + 1 if sig == last_sig else 1
                    last_sig = sig
                    if repeats >= LOOP_REPEAT_LIMIT:
                        raise RunnerError(
                            f"mistral-api tool loop: {name} called {repeats}x with identical "
                            f"arguments ({ctx}); events: {events}", retryable=True,
                            failure_kind="tool_loop")
                    self._activity(f"{name} {raw_args if isinstance(raw_args, str) else json.dumps(raw_args)}")
                    try:
                        args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                        result = tb.dispatch(name, args)
                        ok = True
                    except (ToolError, json.JSONDecodeError) as exc:
                        result, ok = f"ERROR: {exc}", False
                    except OSError as exc:
                        result, ok = f"ERROR: {type(exc).__name__}: {exc.strerror or exc}", False
                    if len(result) > MAX_TOOL_RESULT_CHARS:
                        result = result[:MAX_TOOL_RESULT_CHARS] + "\n...[tool output truncated]"
                    tool_calls_n += 1
                    log({"tool": name, "args": raw_args[:500], "ok": ok, "chars": len(result)})
                    messages.append({"role": "tool", "tool_call_id": call.get("id", ""),
                                     "name": name, "content": result})
                if tool_calls_n >= max_turns:
                    raise RunnerError(
                        f"mistral-api session hit the tool-call cap ({max_turns}) ({ctx}); "
                        f"events: {events}", retryable=False, failure_kind="turn_limit_exceeded")
        return {"_backend": "mistral-api", "text": text, "stop_reason": stop, "turns": turns,
                "tool_calls": tool_calls_n, "input_tokens": in_tok, "output_tokens": out_tok,
                "served_models": served, "elided_tool_results": elided, "events": str(events)}

    def parse_envelope(self, raw: dict, *, model: str, prompt_sha256: str,
                       work_dir: Path) -> LLMResult:
        served = tuple(raw.get("served_models") or ())
        effective = served[0] if len(served) == 1 else model
        # A rolling alias (`mistral-medium-latest`) legitimately resolves to a dated model; record
        # it in served_models but do not report it as a substitution (that check is fail-closed).
        single = served[0] if len(served) == 1 else None
        if single and single != model and model.endswith("-latest"):
            single = None
        in_tok, out_tok = int(raw.get("input_tokens", 0)), int(raw.get("output_tokens", 0))
        return LLMResult(
            text=raw.get("text") or "", model=model, prompt_sha256=prompt_sha256, work_dir=work_dir,
            input_tokens=in_tok, output_tokens=out_tok,
            cost_usd=estimate_cost_usd(effective, in_tok, out_tok),
            num_turns=int(raw.get("tool_calls", 0)), session_id=None,
            stop_reason=raw.get("stop_reason"), is_error=False, api_error_status=None, raw=raw,
            requested_model=model, served_model=single,
            served_models=served, cost_source=model_cost_source(effective))
