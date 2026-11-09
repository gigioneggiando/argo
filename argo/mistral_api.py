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

import fnmatch
import json
import os
import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from .config import MISTRAL_API_BASE_URL, PipelineConfig, estimate_cost_usd, model_cost_source
from .ledger import Ledger
from .runner import AgentRunner, LLMResult, RunnerCancelled, RunnerError, _redact_secrets
from .tool_errors import ToolError, validate_json_content

# --- caps (bounded tool results keep one session's context and cost predictable) ---------------
MAX_READ_LINES = 2000
MAX_READ_BYTES = 256 * 1024
MAX_LINE_CHARS = 2000
MAX_LIST_ENTRIES = 500
MAX_GLOB_RESULTS = 300
MAX_GREP_MATCHES = 200
MAX_GREP_FILE_BYTES = 2 * 1024 * 1024
MAX_GREP_FILES = 20000
MAX_WRITE_BYTES = 4 * 1024 * 1024
MAX_TOOL_RESULT_CHARS = 60_000
DEFAULT_MAX_TURNS = 150
DEFAULT_CONTEXT_WINDOW = 128_000          # tokens; mistral-medium/large are >= 128k
CHARS_PER_TOKEN = 3.5                     # conservative estimate for budgeting the context
KEEP_RECENT_TOOL_RESULTS = 8              # never elide the most recent tool outputs
LOOP_REPEAT_LIMIT = 4                     # identical consecutive tool calls -> tool_loop
HTTP_TIMEOUT_S = 300
MAX_RATE_LIMIT_RETRIES = 8
MAX_TRANSIENT_RETRIES = 4
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "target", "dist", "build"}
_ELIDED = "[earlier tool output elided to fit the context window; call the tool again if needed]"


# ============================================================================== tool dispatcher
@dataclass
class Toolbox:
    repo_dir: Path | None
    work_dir: Path
    allow_write: bool

    def __post_init__(self):
        self.work_real = Path(os.path.realpath(self.work_dir))
        self.repo_real = Path(os.path.realpath(self.repo_dir)) if self.repo_dir else None
        self.roots = [r for r in (self.work_real, self.repo_real) if r is not None]

    # -- path policy ------------------------------------------------------------------------
    @staticmethod
    def _inside(path: Path, root: Path) -> bool:
        try:
            return os.path.commonpath([os.path.normcase(str(path)), os.path.normcase(str(root))]) \
                == os.path.normcase(str(root))
        except ValueError:                      # different drives on Windows
            return False

    def _resolve_read(self, raw: str) -> Path:
        if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
            raise ToolError("path must be a non-empty string")
        p = Path(raw.strip())
        candidates = [p] if p.is_absolute() else [self.work_real / p] + (
            [self.repo_real / p] if self.repo_real else [])
        for cand in candidates:
            real = Path(os.path.realpath(cand))
            if any(self._inside(real, root) for root in self.roots):
                if real.exists():
                    return real
        for cand in candidates:                 # report the precise reason
            real = Path(os.path.realpath(cand))
            if not any(self._inside(real, root) for root in self.roots):
                raise ToolError(f"access denied: {raw} is outside the repository and the "
                                "working directory")
        raise ToolError(f"not found: {raw}")

    def _resolve_write(self, raw: str) -> Path:
        if not self.allow_write:
            raise ToolError("write_file is not available in this stage")
        if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
            raise ToolError("path must be a non-empty string")
        p = Path(raw.strip())
        target = p if p.is_absolute() else self.work_real / p
        parent_real = Path(os.path.realpath(target.parent))
        if not self._inside(parent_real, self.work_real):
            raise ToolError("access denied: files may only be written inside the working "
                            f"directory {self.work_real}")
        final = parent_real / target.name
        if final.is_symlink():
            raise ToolError("access denied: refusing to write through a symlink")
        if self.repo_real and self._inside(Path(os.path.realpath(final)), self.repo_real):
            raise ToolError("access denied: the repository is read-only")
        return final

    def _display(self, p: Path) -> str:
        return str(p)

    # -- tools ------------------------------------------------------------------------------
    def read_file(self, path: str, offset: int = 1, limit: int = MAX_READ_LINES) -> str:
        f = self._resolve_read(path)
        if f.is_dir():
            raise ToolError(f"{path} is a directory; use list_dir")
        if not f.is_file():
            raise ToolError(f"{path} is not a regular file")
        offset = max(1, int(offset or 1))
        limit = max(1, min(int(limit or MAX_READ_LINES), MAX_READ_LINES))
        out, size = [], 0
        with open(f, "r", encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, start=1):
                if n < offset:
                    continue
                if n >= offset + limit or size > MAX_READ_BYTES:
                    out.append(f"... [truncated at line {n - 1}; use offset={n} to continue]")
                    break
                line = line.rstrip("\n")
                if len(line) > MAX_LINE_CHARS:
                    line = line[:MAX_LINE_CHARS] + " ...[line truncated]"
                out.append(f"{n:6}\t{line}")
                size += len(line) + 8
        return "\n".join(out) if out else "(empty file or offset past end)"

    def list_dir(self, path: str = ".") -> str:
        d = self._resolve_read(path or ".")
        if not d.is_dir():
            raise ToolError(f"{path} is not a directory")
        entries = sorted(os.scandir(d), key=lambda e: (not e.is_dir(follow_symlinks=False), e.name))
        lines = [f"{e.name}/" if e.is_dir(follow_symlinks=False) else e.name
                 for e in entries[:MAX_LIST_ENTRIES]]
        if len(entries) > MAX_LIST_ENTRIES:
            lines.append(f"... [{len(entries) - MAX_LIST_ENTRIES} more entries]")
        return f"{d}:\n" + ("\n".join(lines) if lines else "(empty)")

    def _walk(self, base: Path):
        count = 0
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            dirnames[:] = sorted(n for n in dirnames if n not in _SKIP_DIRS)
            for name in sorted(filenames):
                path = Path(dirpath) / name
                if path.is_symlink():            # may point outside the allowed roots
                    continue
                count += 1
                if count > MAX_GREP_FILES:
                    return
                yield path

    def glob(self, pattern: str, path: str | None = None) -> str:
        if not pattern:
            raise ToolError("pattern is required")
        base = self._resolve_read(path) if path else (self.repo_real or self.work_real)
        if not base.is_dir():
            raise ToolError(f"{path} is not a directory")
        pat = pattern.replace("\\", "/")
        hits = []
        for f in self._walk(base):
            rel = f.relative_to(base).as_posix()
            if fnmatch.fnmatch(rel, pat) or ("/" not in pat and fnmatch.fnmatch(f.name, pat)) \
                    or (pat.startswith("**/") and fnmatch.fnmatch(rel, pat[3:])):
                hits.append(str(f))
                if len(hits) >= MAX_GLOB_RESULTS:
                    hits.append(f"... [stopped at {MAX_GLOB_RESULTS} results; narrow the pattern]")
                    break
        return "\n".join(hits) if hits else "(no matches)"

    def grep(self, pattern: str, path: str | None = None, glob: str | None = None,
             ignore_case: bool = False, max_results: int = MAX_GREP_MATCHES) -> str:
        if not pattern:
            raise ToolError("pattern is required")
        try:
            rx = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
        except re.error as exc:
            raise ToolError(f"invalid regex: {exc}") from None
        base = self._resolve_read(path) if path else (self.repo_real or self.work_real)
        files = [base] if base.is_file() else self._walk(base)
        cap = max(1, min(int(max_results or MAX_GREP_MATCHES), MAX_GREP_MATCHES))
        out = []
        for f in files:
            if glob and not (fnmatch.fnmatch(f.name, glob)
                             or fnmatch.fnmatch(f.as_posix(), "*" + glob.lstrip("*"))):
                continue
            try:
                if f.stat().st_size > MAX_GREP_FILE_BYTES:
                    continue
                with open(f, "r", encoding="utf-8", errors="strict") as fh:
                    for n, line in enumerate(fh, start=1):
                        if rx.search(line):
                            out.append(f"{f}:{n}: {line.rstrip()[:300]}")
                            if len(out) >= cap:
                                out.append(f"... [stopped at {cap} matches; narrow the search]")
                                return "\n".join(out)
            except (UnicodeDecodeError, OSError):
                continue                        # binary or unreadable file
        return "\n".join(out) if out else "(no matches)"

    def write_file(self, path: str, content: str) -> str:
        if not isinstance(content, str):
            raise ToolError("content must be a string")
        data = content.encode("utf-8")
        if len(data) > MAX_WRITE_BYTES:
            raise ToolError(f"content too large ({len(data)} bytes > {MAX_WRITE_BYTES})")
        target = self._resolve_write(path)
        if target.suffix.lower() == ".json":
            validate_json_content(content)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".argo-tmp",
                                        dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as tmp:
                tmp.write(data)
            os.replace(tmp_name, target)
        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
        return f"wrote {len(data)} bytes to {target}"

    # -- schema + dispatch ------------------------------------------------------------------
    def schemas(self) -> list[dict]:
        def fn(name, desc, props, required):
            return {"type": "function", "function": {
                "name": name, "description": desc,
                "parameters": {"type": "object", "properties": props, "required": required}}}
        s = {"type": "string"}
        i = {"type": "integer"}
        tools = [
            fn("read_file", "Read a text file (repository or working directory). Returns numbered "
               f"lines; at most {MAX_READ_LINES} lines per call, use offset to page.",
               {"path": s, "offset": i, "limit": i}, ["path"]),
            fn("list_dir", "List a directory (repository or working directory).",
               {"path": s}, []),
            fn("glob", "Find files by glob pattern, e.g. '**/*.java' or 'src/**/Auth*.go'. "
               "Defaults to the repository root.", {"pattern": s, "path": s}, ["pattern"]),
            fn("grep", "Search file contents with a Python regular expression. Optional path "
               "(file or directory) and glob filter on file names, e.g. '*.py'.",
               {"pattern": s, "path": s, "glob": s, "ignore_case": {"type": "boolean"},
                "max_results": i}, ["pattern"]),
        ]
        if self.allow_write:
            tools.append(fn("write_file", "Create or overwrite a file in the working directory "
                            "(relative paths resolve there). The repository is read-only.",
                            {"path": s, "content": s}, ["path", "content"]))
        return tools

    def dispatch(self, name: str, args: dict) -> str:
        impl = {"read_file": self.read_file, "list_dir": self.list_dir, "glob": self.glob,
                "grep": self.grep}
        if self.allow_write:
            impl["write_file"] = self.write_file
        if name not in impl:
            raise ToolError(f"unknown tool {name!r}; available: {', '.join(sorted(impl))}")
        if not isinstance(args, dict):
            raise ToolError("arguments must be a JSON object")
        try:
            return impl[name](**args)
        except TypeError as exc:
            raise ToolError(f"bad arguments for {name}: {exc}") from None


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
