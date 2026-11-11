"""ClaudeRunner abstraction + two implementations.

The runner is the single chokepoint for every LLM invocation, so it is where tool guardrails
and cost logging are enforced — a buggy stage cannot bypass them.

  * :class:`HeadlessClaudeRunner` shells out to ``claude -p`` (Claude Code headless) in the
    default permission mode: reads are confined to the scratch cwd and the repo (``--add-dir``),
    writes to the scratch cwd (path-scoped allow rules), and anything else is denied rather than
    prompted. Network/mutation tools are hard-blocked via ``--disallowedTools``.
  * :class:`MockClaudeRunner` writes fixture files into the scratch dir and returns a
    synthetic manifest — full-glue testing with zero token spend.

Swap implementations behind the :class:`ClaudeRunner` interface (BUILD_SPEC: "Make the runner
an interface so it can be swapped").
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .config import ARTIFACT_TOOLS, PipelineConfig, estimate_cost_usd, model_cost_source
from .guardrails import GuardrailError, assert_no_network_tools, enforce_session_tools, session_policy
from .ledger import Ledger
from .rendering import sha256_text


@dataclass
class LLMResult:
    text: str
    model: str
    prompt_sha256: str
    work_dir: Path
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    num_turns: int = 0
    session_id: str | None = None
    stop_reason: str | None = None
    is_error: bool = False
    api_error_status: str | None = None
    raw: dict = field(default_factory=dict)
    # Requested and served are intentionally separate. ``model`` remains the compatibility alias
    # for requested_model used by older stages and fixtures.
    requested_model: str | None = None
    served_model: str | None = None
    served_models: tuple[str, ...] = ()
    cost_source: str = "unknown"
    # Backend-classified diagnostics, never raw vendor error text. Optional for legacy backends.
    failure_kind: str | None = None
    metadata: dict = field(default_factory=dict)


#: Best-effort classification of WHY a backend call failed, so a caller (FallbackRunner, a future
#: orchestrator-level retry) can apply a failure-appropriate recovery instead of treating every
#: retryable error identically. Distinct from ``retryable`` (whether to retry AT ALL) — this is
#: about HOW: a rate limit wants to wait out its own reset hint; a moderation flag wants a real
#: time gap before hitting the same classifier again (immediate retries of the same prompt have
#: been observed to flag on every attempt even when a spaced-out one-off call succeeds); credits
#: exhaustion on THIS backend won't resolve itself no matter how long you wait, so it should fall
#: through to a genuinely different backend rather than being retried in place; a timeout might
#: just need a longer budget next time. ``unknown_retryable`` is the conservative fallback for a
#: failure that looks transient (matched a generic hint, or matched nothing distinctive) but isn't
#: one of the specifically-recognized shapes above.
FailureKind = str  # Literal["moderation_flagged", "credits_exhausted", "rate_limited",
                    #         "timeout", "unknown_retryable"] -- kept as `str` (not typing.Literal)
                    # so a new signature can be added without a call-site type-check ripple.


#: Failure kinds that a same-backend retry cannot fix (exhausted credits, a rejected or missing
#: key, an invalid request, a stage the backend cannot serve, a repo mutation, a model pin
#: mismatch). Stage-internal retry loops stop on these; FallbackRunner may still try ANOTHER backend.
TERMINAL_FAILURE_KINDS = frozenset({"credits_exhausted", "auth_failed", "credential_bootstrap",
                                    "invalid_request", "unsupported_stage_tool", "repo_mutated",
                                    "model_mismatch", "model_unavailable", "budget_reached"})

#: Codex CLI refusals that mean "this model is not usable with THIS login/profile" (observed with
#: codex-cli 0.166, 2026-11-06). Same-account retries cannot help; another account in a
#: --codex-accounts chain (different plan, or daybreak off) can.
_CODEX_MODEL_UNAVAILABLE = (
    (re.compile(r"Daybreak is unavailable for model", re.I),
     "the Codex profile has `daybreak = true`, which only allows Daybreak-compatible models "
     "(e.g. gpt-6-sol, gpt-5.6-sol): turn daybreak off in that CODEX_HOME's config.toml or pick "
     "a compatible --codex-model"),
    (re.compile(r"model is not supported when using Codex with a ChatGPT account", re.I),
     "this ChatGPT plan does not include the model in Codex: use another --codex-model, another "
     "account (--codex-accounts), or an API key (--codex-api-key)"),
)


def _codex_error_events(stdout: str) -> str:
    """Concatenate the messages of `codex exec --json` ``error``/``turn.failed`` events only."""
    out: list[str] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if not isinstance(ev, dict) or ev.get("type") not in {"error", "turn.failed"}:
            continue
        msg = ev.get("message")
        err = ev.get("error")
        if isinstance(err, dict):
            msg = err.get("message") or msg
        if msg:
            out.append(str(msg))
    return " ".join(out)


def _codex_model_unavailable(text: str) -> str | None:
    for rx, advice in _CODEX_MODEL_UNAVAILABLE:
        if rx.search(text or ""):
            return advice
    return None


class RunnerError(RuntimeError):
    def __init__(self, message: str, *, retry_after: str | None = None,
                 retryable: bool = False, failure_kind: FailureKind | None = None):
        super().__init__(message)
        self.retry_after = retry_after
        self.retryable = retryable
        self.failure_kind = failure_kind


class BudgetExceeded(RunnerError):
    """The per-run budget is spent: no further session may launch. Not retryable (on any
    backend: FallbackRunner re-raises it instead of falling through)."""

    def __init__(self, message: str):
        super().__init__(message, retryable=False, failure_kind="budget_reached")


def repo_fingerprint(repo_dir: Path | str | None) -> str | None:
    """Metadata fingerprint of the audited repo copy: every entry's relative path, type, size,
    mtime_ns and mode, symlinks not followed. Any write, create, delete, rename, chmod or symlink
    swap changes it. Metadata-only (no content hashing) keeps it cheap enough to run around every
    session; a same-size write that also restores mtime_ns would need deliberate timestamp forgery,
    which the read-only copy's tool policy/sandbox already forbids. None when there is no repo."""
    if repo_dir is None:
        return None
    root = Path(repo_dir)
    if not root.is_dir():
        return None
    h = hashlib.sha256()
    stack = [root]
    while stack:
        cur = stack.pop()
        try:
            entries = sorted(os.scandir(cur), key=lambda e: e.name)
        except OSError as exc:            # unreadable dir: record it, so a later change still shows
            h.update(f"!{cur.relative_to(root).as_posix()}:{exc.errno}\n".encode())
            continue
        for e in entries:
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            rel = Path(e.path).relative_to(root).as_posix()
            kind = "l" if e.is_symlink() else ("d" if e.is_dir(follow_symlinks=False) else "f")
            if kind == "d":
                # Directory size/mtime are NOT hashed: NTFS updates them lazily after a child is
                # written (flaky false positives), and any child create/delete/rename already shows
                # up in the recursive entry listing itself.
                h.update(f"d|{rel}|{st.st_mode}\n".encode())
            else:
                h.update(f"{kind}|{rel}|{st.st_size}|{st.st_mtime_ns}|{st.st_mode}\n".encode())
            if kind == "l":
                try:
                    h.update(f"->{os.readlink(e.path)}\n".encode())
                except OSError:
                    pass
            elif kind == "d":
                stack.append(Path(e.path))
    return h.hexdigest()


def _assert_repo_unchanged(repo_dir, before: str | None, *, stage: str, label: str | None,
                           cause: BaseException | None = None) -> None:
    if before is None:
        return
    after = repo_fingerprint(repo_dir)
    if after != before:
        raise RunnerError(
            f"audited repo copy was modified during the session (stage={stage}, label={label}); "
            "the repo must stay read-only on every backend -- refusing to use this session's output",
            retryable=False, failure_kind="repo_mutated") from cause


def _redact_secrets(text: str | None, *secrets: str | None) -> str:
    """Remove configured credential values from untrusted child diagnostics."""
    scrubbed = text or ""
    for secret in secrets:
        if secret:
            scrubbed = scrubbed.replace(secret, "<redacted>")
    return scrubbed


def _safe_account_component(value: str | None) -> str:
    """Return a non-secret, stable account label component.

    Account directories are configuration, not credentials, but logging the full path would still
    leak usernames and machine layout into run artifacts. Keep only the final directory name and
    restrict it to a small portable alphabet. API-key-backed accounts are labelled as api-key and
    never pass the key itself here.
    """
    if not value:
        return "default"
    # Normalize both separator styles before taking the leaf.  CI may exercise a Windows-shaped
    # configured path on Linux (and vice versa), so host-native ``Path.name`` alone can leak the
    # whole foreign path into the label.
    raw = os.path.expanduser(str(value)).replace("\\", "/").rstrip("/")
    leaf = raw.rsplit("/", 1)[-1] if raw else ""
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", leaf).strip(".-")
    return (safe[:64] or "default")


def _derived_account_label(config: PipelineConfig) -> str:
    """Derive a redaction-safe account label when the builder did not provide an indexed one."""
    backend = config.runner
    if backend == "codex":
        if config.codex_home:
            return f"codex:{_safe_account_component(config.codex_home)}"
        if config.codex_api_key:
            return "codex:api-key"
        return "codex:ambient"
    if backend == "headless":
        if config.claude_config_dir:
            return f"claude:{_safe_account_component(config.claude_config_dir)}"
        if config.claude_api_key:
            return "claude:api-key"
        return "claude:ambient"
    if backend == "gemini":
        return "gemini:api-key" if config.gemini_api_key else "gemini:ambient"
    if backend == "mistral-api":
        return "mistral-api:api-key" if config.mistral_api_key else "mistral-api:ambient"
    if backend == "mistral-vibe":
        return "mistral-vibe:api-key" if config.mistral_vibe_api_key else "mistral-vibe:ambient"
    return f"{backend}:default"


class RunnerCancelled(RuntimeError):
    """The session's process was killed because the run was cancelled mid-stage. Deliberately NOT
    a :class:`RunnerError`, so stage-level ``except RunnerError`` partial-recovery does not swallow
    it — it propagates to the orchestrator, which marks the run cancelled."""


class SessionGuardTripped(RuntimeError):
    """A streaming session guard (see :meth:`AgentRunner._exec` ``on_stdout_line``) killed the
    session mid-flight. Internal to the runner: backends translate it into a :class:`RunnerError`
    with a precise ``failure_kind`` so stage partial-recovery still runs."""

    def __init__(self, reason: str, *, stdout: str = "", stderr: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.stdout = stdout
        self.stderr = stderr


# Field paths verified against the REAL claude v2.1.178 `--output-format json` envelope
# (see tests/fixtures/real_envelope.json). On a SUCCESS envelope these MUST all be present;
# their absence means the CLI output shape drifted and we fail loudly rather than logging a
# silent $0/0-token call.
_REQUIRED_SUCCESS_FIELDS = ("result", "total_cost_usd", "usage", "num_turns", "session_id")


def parse_result_envelope(raw: dict, *, model: str, prompt_sha256: str,
                          work_dir: Path) -> LLMResult:
    """Parse a claude `--output-format json` envelope into an :class:`LLMResult`.

    Strict on success envelopes (any missing required field raises :class:`RunnerError`);
    lenient on ``is_error`` envelopes (a dying session may omit fields — we still capture what
    is there so partial artifacts can be recovered). Uses the real field names verified from a
    live call: ``result``, ``total_cost_usd``, ``usage.{input,output}_tokens``, ``num_turns``,
    ``session_id``, ``stop_reason``/``subtype``/``terminal_reason``, ``api_error_status``.
    """
    if not isinstance(raw, dict) or "is_error" not in raw:
        raise RunnerError(
            f"unrecognized claude result envelope (no 'is_error' field): {str(raw)[:300]!r}")
    is_error = bool(raw.get("is_error"))
    if not is_error:
        missing = [f for f in _REQUIRED_SUCCESS_FIELDS if f not in raw]
        if missing:
            raise RunnerError(
                f"claude success envelope missing required field(s) {missing} — CLI output "
                f"shape drift for this version? present keys: {sorted(raw)}")
    usage = raw.get("usage") or {}
    served = raw.get("model") or raw.get("model_id")
    return LLMResult(
        text=raw.get("result") or "",
        model=model,
        prompt_sha256=prompt_sha256,
        work_dir=work_dir,
        input_tokens=int(usage.get("input_tokens", 0) or 0),
        output_tokens=int(usage.get("output_tokens", 0) or 0),
        cost_usd=float(raw.get("total_cost_usd", 0.0) or 0.0),
        num_turns=int(raw.get("num_turns", 0) or 0),
        session_id=raw.get("session_id"),
        stop_reason=raw.get("stop_reason") or raw.get("subtype") or raw.get("terminal_reason"),
        is_error=is_error,
        api_error_status=raw.get("api_error_status"),
        raw=raw,
        requested_model=model,
        served_model=str(served) if served else None,
        served_models=(str(served),) if served else (),
        cost_source="provider_authoritative" if "total_cost_usd" in raw else "unknown",
    )


class AgentRunner(ABC):
    """Backend-neutral base: derives the session policy, applies guardrails, logs every call, then
    delegates to ``_invoke`` (per-backend launch) and ``parse_envelope`` (per-backend result).
    Subclasses: :class:`HeadlessClaudeRunner` (Claude Code), :class:`CodexRunner` (Codex CLI /
    OpenAI / OSS), :class:`MockClaudeRunner` (fixtures)."""

    def __init__(self, config: PipelineConfig, ledger: Ledger, *, account_label: str | None = None):
        self.config = config
        self.ledger = ledger
        # Deliberately an opaque, human-readable label (never a credential or full path).
        # Expanded account chains pass an indexed label; direct construction gets a safe default.
        self.account_label = account_label or _derived_account_label(config)
        # Set by the orchestrator for the duration of a run; when it fires, an in-flight CLI
        # subprocess is killed (mid-stage cancellation). None => not cancellable (e.g. CLI runs).
        self.cancel_event = None
        # Optional live-activity sink (chat UI): receives short one-line progress strings (a tool
        # call, an interim agent message) WHILE a session runs. Purely informational: never part
        # of the result, the ledger or the guardrails; a failing sink is ignored.
        self.on_activity = None

    def _activity(self, text) -> None:
        sink = self.on_activity
        if sink is None or not text:
            return
        try:
            sink(" ".join(str(text).split())[:_ACTIVITY_MAX_CHARS])
        except Exception:  # noqa: BLE001 -- a UI sink must never break a session
            pass

    def _with_activity(self, on_line, parse):
        """Wrap an ``_exec`` stdout-line callback so each line also feeds ``parse`` -> activity."""
        if self.on_activity is None:
            return on_line

        def line(raw: str):
            try:
                self._activity(parse(raw))
            except Exception:  # noqa: BLE001
                pass
            return on_line(raw) if on_line is not None else None
        return line

    # ---------------------------------------------------------------- cancellable subprocess
    def _exec(self, cmd: list[str], *, prompt: str, cwd, timeout: float,
              env: dict | None = None,
              on_stdout_line=None) -> subprocess.CompletedProcess:
        """Run a backend CLI as a **cancellable** subprocess: if ``self.cancel_event`` fires (the
        user hit Cancel mid-stage) or the timeout elapses, kill the whole process **tree** and raise.

        ``on_stdout_line`` (optional) streams stdout: it is called with every line as it arrives
        and may return a non-empty reason string to **abort the session mid-flight** (process tree
        killed, :class:`SessionGuardTripped` raised carrying the reason and the stdout seen so far).
        Without it, stdout is buffered exactly as before.

        Returns a ``CompletedProcess`` (stdout/stderr captured as text). Raises
        ``subprocess.TimeoutExpired`` on timeout and :class:`RunnerCancelled` on cancellation —
        keeping the same surface the previous ``subprocess.run`` calls relied on.
        """
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        preexec = os.setsid if os.name != "nt" else None      # own process group on POSIX
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", cwd=str(cwd),
            env=env, creationflags=creationflags, preexec_fn=preexec)
        box: dict = {}
        out_lines: list[str] = []
        threads: list[threading.Thread] = []

        if on_stdout_line is None:
            def _pump():
                try:
                    box["out"], box["err"] = proc.communicate(input=prompt)
                except Exception as exc:               # pragma: no cover - defensive
                    box["exc"] = exc
            threads.append(threading.Thread(target=_pump, daemon=True))
        else:
            def _feed():
                try:
                    proc.stdin.write(prompt)
                    proc.stdin.close()
                except (OSError, ValueError):          # child exited before reading all input
                    pass

            def _read_out():
                try:
                    for line in proc.stdout:
                        out_lines.append(line)
                        if "abort" in box:
                            continue
                        try:
                            reason = on_stdout_line(line)
                        except Exception as exc:       # a guard bug must never hang the session
                            reason = None
                            box.setdefault("guard_exc", exc)
                        if reason:
                            box["abort"] = reason
                except Exception as exc:               # pragma: no cover - defensive
                    box["exc"] = exc

            def _read_err():
                try:
                    box["err"] = proc.stderr.read()
                except Exception:                      # pragma: no cover - defensive
                    box["err"] = ""
            threads += [threading.Thread(target=f, daemon=True)
                        for f in (_feed, _read_out, _read_err)]

        for th in threads:
            th.start()
        ev = self.cancel_event
        deadline = time.monotonic() + timeout

        def _alive() -> bool:
            return any(t.is_alive() for t in threads) or (
                on_stdout_line is not None and proc.poll() is None)

        while _alive():
            threads[-1].join(0.2) if on_stdout_line is None else time.sleep(0.2)
            if ev is not None and ev.is_set():
                self._kill_tree(proc); [t.join(5) for t in threads]
                raise RunnerCancelled("session cancelled mid-stage")
            if "abort" in box:
                self._kill_tree(proc); [t.join(5) for t in threads]
                raise SessionGuardTripped(box["abort"], stdout="".join(out_lines),
                                          stderr=box.get("err", ""))
            if time.monotonic() > deadline:
                self._kill_tree(proc); [t.join(5) for t in threads]
                exc = subprocess.TimeoutExpired(cmd, timeout)
                exc.partial_stdout = "".join(out_lines)
                raise exc
        if "exc" in box:                           # pragma: no cover - defensive
            raise box["exc"]
        if "abort" in box:   # tripped on the very last lines, after the child had already exited
            raise SessionGuardTripped(box["abort"], stdout="".join(out_lines),
                                      stderr=box.get("err", ""))
        out = box.get("out", "") if on_stdout_line is None else "".join(out_lines)
        return subprocess.CompletedProcess(cmd, proc.wait(), out, box.get("err", ""))

    @staticmethod
    def _kill_tree(proc: subprocess.Popen) -> None:
        """Kill the subprocess AND its descendants (the CLI spawns a node/runtime child)."""
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                               capture_output=True)
            else:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:                          # pragma: no cover - best effort
            try:
                proc.kill()
            except Exception:
                pass

    def parse_envelope(self, raw: dict, *, model: str, prompt_sha256: str,
                       work_dir: Path) -> LLMResult:
        """Parse a backend's raw result into an :class:`LLMResult`. Default = the Claude envelope;
        the Codex runner overrides this."""
        return parse_result_envelope(raw, model=model, prompt_sha256=prompt_sha256,
                                     work_dir=work_dir)

    def run(
        self,
        *,
        prompt: str,
        run_dir: Path,
        work_dir: Path,
        model: str,
        stage: str,
        run_id: str,
        repo_dir: Path | None = None,
        allowed_tools: tuple[str, ...] = ARTIFACT_TOOLS,
        label: str | None = None,
        neutral_prompt: str | None = None,
    ) -> LLMResult:
        """Run one session; on a moderation-flagged failure, retry ONCE on this SAME backend with
        ``neutral_prompt`` (a caller-supplied differently-worded variant of ``prompt``) if one was
        supplied. Bounded to exactly one retry (no recursion). Both attempts are logged
        independently via the normal ledger/jsonl path in :meth:`_run_attempt`, so the audit trail
        shows the flag and the recovery. A caller that never passes ``neutral_prompt`` sees
        byte-identical behavior to a plain single attempt. This is orthogonal to (and unaware of)
        :class:`FallbackRunner`'s cross-backend retry and the orchestrator's whole-stage
        auto-retry — three independent layers, see docs/architecture.md."""
        try:
            return self._run_attempt(
                prompt=prompt, run_dir=run_dir, work_dir=work_dir, model=model, stage=stage,
                run_id=run_id, repo_dir=repo_dir, allowed_tools=allowed_tools, label=label,
            )
        except RunnerError as exc:
            if exc.failure_kind != "moderation_flagged" or neutral_prompt is None:
                raise
            print(f"[runner] stage={stage} label={label!r} was moderation-flagged; retrying once "
                  f"in {_NEUTRAL_RETRY_DELAY_S:.0f}s with a neutral-register prompt variant",
                  file=sys.stderr)
            time.sleep(_NEUTRAL_RETRY_DELAY_S)
            return self._run_attempt(
                prompt=neutral_prompt, run_dir=run_dir, work_dir=work_dir, model=model,
                stage=stage, run_id=run_id, repo_dir=repo_dir, allowed_tools=allowed_tools,
                label=f"{label}-neutral-retry" if label else "neutral-retry",
            )

    def _run_attempt(
        self,
        *,
        prompt: str,
        run_dir: Path,
        work_dir: Path,
        model: str,
        stage: str,
        run_id: str,
        repo_dir: Path | None = None,
        allowed_tools: tuple[str, ...] = ARTIFACT_TOOLS,
        label: str | None = None,
    ) -> LLMResult:
        # --- guardrails ---------------------------------------------------------------
        # One backend-neutral policy ("no network except research; repo never writable"); each
        # runner translates it. We also sanitize the requested tool list (Claude semantics, and a
        # neutral sanity check that no stage but research requested a network tool).
        policy = session_policy(stage)
        allowed, disallowed = enforce_session_tools(list(allowed_tools), stage=stage)
        assert_no_network_tools(allowed, stage=stage)  # hard stop right before launch

        # Budget gate at the launch chokepoint (every backend, every stage): a stage's own
        # pre-loop check cannot see spend from sessions that finish while it is fanning out.
        if self.config.budget_usd is not None:
            spent = self.ledger.run_cost(run_id)
            if spent >= self.config.budget_usd:
                raise BudgetExceeded(
                    f"Per-run budget ${self.config.budget_usd:.2f} reached (spent ${spent:.4f}); "
                    f"not launching stage={stage} label={label!r}")

        work_dir.mkdir(parents=True, exist_ok=True)
        prompt_sha = sha256_text(prompt)

        # Backend-agnostic repo-integrity check: the audited copy must be byte-for-byte untouched by
        # the session. Claude/Gemini rely on a tool allowlist/policy and ingest's best-effort chmod;
        # Codex on its OS sandbox. This DETECTS a mutation on every backend (fail-closed) instead
        # of trusting each enforcement mechanism.
        repo_before = repo_fingerprint(repo_dir)
        started = time.monotonic()
        try:
            raw = self._invoke(
                prompt=prompt,
                work_dir=work_dir,
                model=model,
                repo_dir=repo_dir,
                allowed=allowed,
                disallowed=disallowed,
                policy=policy,
                stage=stage,
                run_id=run_id,
                label=label,
                session_budget_usd=self._session_budget(run_id),
                timeout_s=self.config.timeout_for(stage),
            )
        except RunnerError as exc:
            _assert_repo_unchanged(repo_dir, repo_before, stage=stage, label=label, cause=exc)
            # A session that died without an envelope (timeout, startup failure) is still a call:
            # ledger it so the failure is queryable. Its spend is unknown (cost 0, source unknown).
            try:
                self.ledger.log_call(
                    run_id=run_id, stage=stage, model=model, prompt_sha256=prompt_sha,
                    duration_ms=int((time.monotonic() - started) * 1000),
                    failure_kind=exc.failure_kind or "session_error", label=label,
                    requested_model=model, cost_source="unknown")
                if self.config.runner == "mistral-vibe":
                    self._append_jsonl(run_dir, {
                        "stage": stage, "label": label, "backend": "mistral-vibe",
                        "backend_account": self.account_label, "model": model,
                        "requested_model": model, "prompt_sha256": prompt_sha,
                        "is_error": True, "failure_kind": exc.failure_kind or "session_error",
                        "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0,
                        "cost_source": "unknown", "num_turns": 0,
                        "duration_ms": int((time.monotonic() - started) * 1000),
                        "mistral_vibe_auth": self.config.mistral_vibe_auth,
                        "auth_source": "unknown", "vibe_version": None,
                    })
            except Exception:  # noqa: BLE001 -- logging must never mask the session error
                pass
            raise
        # checked now, raised only after the call is logged (its tokens/cost were still spent)
        repo_mutation: RunnerError | None = None
        try:
            _assert_repo_unchanged(repo_dir, repo_before, stage=stage, label=label)
        except RunnerError as exc:
            repo_mutation = exc
        duration_ms = int((time.monotonic() - started) * 1000)

        # Per-backend parse into the common LLMResult (Claude-strict by default; Codex overrides).
        result = self.parse_envelope(raw, model=model, prompt_sha256=prompt_sha,
                                     work_dir=work_dir)

        # --- failure classification, computed ONCE and reused by every branch below -----
        # (previously duplicated: the "hard API error" and "recoverable error" branches each
        # called _classify_failure_text separately with slightly different input text; now
        # persisted regardless of which branch fires, so a refusal rate is queryable after the
        # fact from the ledger/jsonl instead of only visible inside a raised exception's message.)
        reset_hint = _extract_session_reset_hint(result.text) if result.is_error else None
        failure_kind = None
        if result.is_error:
            classify_text = (f"{result.api_error_status} {result.text}" if result.api_error_status
                             else result.text)
            failure_kind = result.failure_kind or _classify_failure_text(classify_text)
            if failure_kind is None and result.api_error_status and "429" in str(result.api_error_status):
                failure_kind = "rate_limited"
        model_mismatch = bool(result.served_model and result.served_model != model)
        if repo_mutation is not None:
            failure_kind = "repo_mutated"

        # --- cost/latency/refusal logging (ledger + per-run JSONL) — ALWAYS, even on error -----
        self.ledger.log_call(
            run_id=run_id,
            stage=stage,
            model=model,
            prompt_sha256=prompt_sha,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            cost_usd=result.cost_usd,
            num_turns=result.num_turns,
            session_id=result.session_id,
            stop_reason=result.stop_reason,
            duration_ms=duration_ms,
            failure_kind=failure_kind,
            label=label,
            requested_model=result.requested_model or model,
            served_model=result.served_model,
            served_models=result.served_models,
            cost_source=result.cost_source,
            model_mismatch=model_mismatch,
            effort=self.config.stage_effort.get(stage, "provider_default"),
        )
        self._append_jsonl(run_dir, {
            "stage": stage,
            "label": label,
            "backend": self.config.runner,
            "backend_account": self.account_label,
            "model": model,
            "requested_model": result.requested_model or model,
            "served_model": result.served_model,
            "served_models": list(result.served_models),
            "cost_source": result.cost_source,
            "model_mismatch": model_mismatch,
            "effort": self.config.stage_effort.get(stage, "provider_default"),
            "prompt_sha256": prompt_sha,
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
            "cost_usd": result.cost_usd,
            "num_turns": result.num_turns,
            "session_id": result.session_id,
            "stop_reason": result.stop_reason,
            "is_error": result.is_error,
            "api_error_status": result.api_error_status,
            "session_limit_reset_hint": reset_hint,
            "duration_ms": duration_ms,
            "failure_kind": failure_kind,
            **{name: result.metadata[name]
               for name in ("mistral_vibe_auth", "auth_source", "vibe_version")
               if name in result.metadata},
        })

        if repo_mutation is not None:
            raise repo_mutation

        if model_mismatch and not self.config.allow_model_substitution:
            raise RunnerError(
                f"requested model {model!r} was served as {result.served_model!r}; "
                "exact model pins are fail-closed (use --allow-model-substitution only for "
                "an explicitly best-effort run)",
                retryable=False, failure_kind="model_mismatch")

        # --- surface hard API errors LOUDLY (auth / rate-limit / overloaded) -----------
        # These carry api_error_status and cannot produce usable artifacts -> abort clearly.
        if result.is_error and result.api_error_status:
            reset_suffix = f", session_limit_reset_hint={reset_hint!r}" if reset_hint else ""
            raise RunnerError(
                f"claude session API error (stage={stage}, run_id={run_id}, label={label}): "
                f"api_error_status={result.api_error_status!r}, stop_reason="
                f"{result.stop_reason!r}, detail={result.text[:300]!r}{reset_suffix}",
                retry_after=reset_hint, failure_kind=failure_kind)

        # --- per-session caps (no native --max-turns in v2.1.178) ----------------------
        mt = self.config.session_max_turns
        if mt is not None and result.num_turns > mt:
            raise RunnerError(
                f"session exceeded max_turns cap {mt} (num_turns={result.num_turns}, "
                f"stage={stage}, run_id={run_id}, label={label})")
        mc = self.config.session_max_cost_usd
        if mc is not None and result.cost_usd > mc:
            raise RunnerError(
                f"session exceeded per-session cost cap ${mc:.4f} "
                f"(cost=${result.cost_usd:.4f}, stage={stage}, run_id={run_id}, label={label})")

        # Recoverable error (no api_error_status): raise so FallbackRunner can retry/fall back.
        # Stages that know how to salvage partial scratch artifacts still catch RunnerError.
        if result.is_error:
            reset_suffix = f", session_limit_reset_hint={reset_hint!r}" if reset_hint else ""
            raise RunnerError(
                f"recoverable is_error session (stage={stage}, run_id={run_id}, label={label}, "
                f"stop_reason={result.stop_reason!r}, detail={result.text[:300]!r}{reset_suffix})",
                retry_after=reset_hint,
                retryable=(not result.failure_kind
                           or failure_kind in {"credits_exhausted", "model_unavailable"}
                           or failure_kind not in TERMINAL_FAILURE_KINDS),
                failure_kind=failure_kind or "unknown_retryable",
            )
        return result

    def _session_budget(self, run_id: str) -> float | None:
        """Per-session dollar cap handed to the CLI as --max-budget-usd: the tighter of the
        configured per-session cap and the REMAINING per-run budget (real spend from ledger)."""
        caps: list[float] = []
        if self.config.session_max_cost_usd is not None:
            caps.append(self.config.session_max_cost_usd)
        if self.config.budget_usd is not None:
            caps.append(max(0.0, self.config.budget_usd - self.ledger.run_cost(run_id)))
        return min(caps) if caps else None

    @staticmethod
    def _append_jsonl(run_dir: Path, record: dict) -> None:
        run_dir.mkdir(parents=True, exist_ok=True)
        with (run_dir / "llm_log.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")

    @abstractmethod
    def _invoke(self, *, prompt, work_dir, model, repo_dir, allowed, disallowed, policy,
                stage, run_id, label, session_budget_usd=None,
                timeout_s=None) -> dict:  # pragma: no cover - interface
        ...


# Backward-compatible alias: the base class was historically named ClaudeRunner; it is now the
# backend-neutral base for Claude, Codex, and the mock. Existing imports keep working.
ClaudeRunner = AgentRunner


# --------------------------------------------------------------------------- headless
#: Claude file tools that read. In the default permission mode they need no allow rule inside the
#: session's working directories (the scratch cwd and the ``--add-dir`` repo) and are denied
#: elsewhere, so they are NOT passed to ``--allowedTools``: an unscoped ``Read`` rule would
#: approve reads anywhere on disk.
_CLAUDE_READ_TOOLS = frozenset({"Read", "Grep", "Glob", "LS"})
#: Claude file tools that write: allowed only under the scratch cwd. Claude Code checks every file
#: write (Write included) against ``Edit(...)`` rules; a ``Write(...)`` path rule is not consulted
#: (verified: ``Write(./**)`` denied an absolute path inside the cwd, ``Edit(./**)`` allowed it and
#: still denied paths outside). The Edit/MultiEdit TOOLS stay in --disallowedTools.
_CLAUDE_WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})


def scope_claude_allowed(allowed) -> list[str]:
    """Translate an Argo tool allowlist into path-scoped Claude Code allow rules.

    ``--add-dir`` is not a sandbox and ``bypassPermissions``/``acceptEdits`` approve file tools
    on ANY path (verified with a canary session: writes and reads outside both the cwd and the
    added dir succeeded). The default mode in ``-p`` denies whatever is not pre-approved, so the
    allow rules themselves must carry the scope."""
    out: list[str] = []
    for tool in allowed or ():
        if "(" in tool:                      # already a scoped rule: keep it as given
            out.append(tool)
        elif tool in _CLAUDE_READ_TOOLS:
            continue
        elif tool in _CLAUDE_WRITE_TOOLS:
            out.append("Edit(./**)")
        else:
            out.append(tool)
    return list(dict.fromkeys(out))


class HeadlessClaudeRunner(AgentRunner):
    """Runs ``claude -p`` non-interactively."""

    def __init__(self, config: PipelineConfig, ledger: Ledger, claude_bin: str = "claude"):
        super().__init__(config, ledger)
        self.claude_bin = claude_bin
        self._resolved_bin: str | None = None

    def _bin(self) -> str:
        """Resolve the CLI to a full path. On Windows the launcher is a ``claude.CMD`` npm
        shim; ``subprocess`` does NOT apply PATHEXT to a bare name, so we must resolve it via
        ``shutil.which`` (the resolved full path launches fine as argv[0])."""
        if self._resolved_bin is None:
            resolved = shutil.which(self.claude_bin)
            if not resolved:
                raise RunnerError(
                    f"claude CLI not found on PATH (looked for {self.claude_bin!r}); "
                    "install Claude Code or pass an explicit path to HeadlessClaudeRunner")
            self._resolved_bin = resolved
        return self._resolved_bin

    def _build_cmd(self, *, model, repo_dir, allowed, disallowed,
                   session_budget_usd=None, effort=None, stream=False) -> list[str]:
        cmd = [
            self._bin(),
            "-p",
            # json = one metadata envelope at exit. stream-json (only when a live viewer is
            # attached, e.g. chat) = one event per line; its final ``type: "result"`` event carries
            # the SAME envelope fields (verified against claude 2.1.319), so parsing is unchanged.
            *(("--output-format", "stream-json", "--verbose") if stream
              else ("--output-format", "json")),
            "--model", model,
            # Default mode: in -p an action that would need approval is DENIED, not prompted,
            # so a headless run never hangs. Reads stay inside the cwd + --add-dir; writes are
            # allowed only by the path-scoped rules from scope_claude_allowed(). Never
            # bypassPermissions/acceptEdits: both approve file tools on any path.
            "--permission-mode", "default",
        ]
        # Native mid-session cost kill (v2.1.178 has --max-budget-usd; it has NO --max-turns).
        if session_budget_usd is not None:
            cmd += ["--max-budget-usd", f"{session_budget_usd:.4f}"]
        if effort:
            cmd += ["--effort", effort]
        if repo_dir is not None:
            cmd += ["--add-dir", str(Path(repo_dir).resolve())]
        scoped = scope_claude_allowed(allowed)
        if scoped:
            cmd += ["--allowedTools", *scoped]
        if disallowed:
            cmd += ["--disallowedTools", *disallowed]
        return cmd

    def _invoke(self, *, prompt, work_dir, model, repo_dir, allowed, disallowed, policy=None,
                stage, run_id, label, session_budget_usd=None, timeout_s=None) -> dict:
        stream = self.on_activity is not None
        cmd = self._build_cmd(model=model, repo_dir=repo_dir, allowed=allowed,
                              disallowed=disallowed, session_budget_usd=session_budget_usd,
                              effort=self.config.stage_effort.get(stage), stream=stream)
        timeout = timeout_s or self.config.session_timeout_s
        # Multi-account: point this invocation at a specific Claude credential store so an
        # account-fallback can switch accounts (limits are per-account). See build_runner.
        # claude_api_key is a SEPARATE, additive mechanism (an env var, not a directory) -- both
        # can be set at once with no collision, so both get injected when present. A bare
        # ANTHROPIC_API_KEY is enough on its own (confirmed empirically: no `claude login` needed),
        # unlike Codex's stateful login requirement -- see CodexRunner._codex_home_env_value.
        env = None
        if self.config.claude_config_dir or self.config.claude_api_key:
            env = dict(os.environ)
            if self.config.claude_config_dir:
                # Normalize to a native absolute path (expanduser handles ~; a bash-style /c/..
                # path the launched CLI cannot resolve is made absolute). Pass via CLAUDE_CONFIG_DIR.
                cfg_dir = os.path.abspath(os.path.expanduser(str(self.config.claude_config_dir)))
                env["CLAUDE_CONFIG_DIR"] = cfg_dir
            if self.config.claude_api_key:
                env["ANTHROPIC_API_KEY"] = self.config.claude_api_key
        try:
            proc = self._exec(cmd, prompt=prompt, cwd=work_dir, timeout=timeout, env=env,
                              on_stdout_line=(self._with_activity(None, _claude_activity)
                                              if stream else None))
        except subprocess.TimeoutExpired as exc:  # pragma: no cover - real-runner path
            raise RunnerError(
                f"claude session timed out after {timeout}s "
                f"(stage={stage}, run_id={run_id}, label={label}); the scratch dir may hold "
                "partial artifacts but no metadata envelope was returned",
                retryable=True, failure_kind="timeout",
            ) from exc

        # A result envelope may arrive WITH a non-zero exit (e.g. is_error / budget-exceeded);
        # prefer parsing stdout, and only fall back to a hard error if there is no usable JSON.
        out = (proc.stdout or "").strip()
        if out and stream:
            envelope = _claude_stream_result(out)
            if envelope is not None:
                return envelope
        elif out:
            try:
                envelope = json.loads(out)
            except json.JSONDecodeError:
                envelope = None
            if isinstance(envelope, dict):
                return envelope  # base run() validates shape + classifies is_error/api errors

        stderr = _redact_secrets(proc.stderr, self.config.claude_api_key)
        stdout = _redact_secrets(out, self.config.claude_api_key)
        raise RunnerError(
            f"claude produced no parseable JSON envelope (stage={stage}, run_id={run_id}, "
            f"label={label}, exit={proc.returncode}). This usually means an auth/startup "
            f"failure.\nstderr tail:\n{stderr[-1500:]}\n"
            f"stdout tail:\n{stdout[-500:]}")


def _claude_stream_result(stdout: str) -> dict | None:
    """The final ``{"type": "result", ...}`` event of a ``--output-format stream-json`` session:
    the same envelope ``--output-format json`` prints, or None if the stream never finished."""
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(ev, dict) and ev.get("type") == "result":
            return ev
    return None


def _claude_activity(line: str) -> str | None:
    """One progress line from a Claude ``stream-json`` event: a tool call or interim text."""
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        return None
    if ev.get("type") != "assistant" or not isinstance(ev.get("message"), dict):
        return None
    parts = []
    for c in ev["message"].get("content") or []:
        if not isinstance(c, dict):
            continue
        if c.get("type") == "tool_use":
            args = c.get("input") if isinstance(c.get("input"), dict) else {}
            detail = next((str(args[k]) for k in ("command", "file_path", "pattern", "path", "url")
                           if args.get(k)), "")
            parts.append(f"{c.get('name', 'tool')} {detail}".strip())
        elif c.get("type") == "text" and (c.get("text") or "").strip():
            parts.append(c["text"])
    return " · ".join(parts) or None


def _gemini_events(stdout: str):
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(ev, dict):
                yield ev


def _gemini_stream_envelope(stdout: str) -> dict | None:
    """Rebuild the ``--output-format json`` envelope from a ``stream-json`` session (gemini CLI
    0.66, verified 2026-11-06): ``response`` = the assistant deltas after the last tool result,
    ``stats.models`` mapped to the json shape ({tokens: {prompt, candidates}}; stream
    ``input_tokens`` already includes cached tokens, like json ``prompt``), and a non-success
    result becomes ``error``. None when the stream never reached its ``result`` event."""
    session_id, chunks, result = None, [], None
    for ev in _gemini_events(stdout):
        kind = ev.get("type")
        if kind == "init":
            session_id = ev.get("session_id")
        elif kind == "tool_result":
            chunks = []                               # only the answer after the last tool counts
        elif kind == "message" and ev.get("role") == "assistant":
            chunks.append(str(ev.get("content") or ""))
        elif kind == "result":
            result = ev
    if result is None:
        return None
    stats = result.get("stats") if isinstance(result.get("stats"), dict) else {}
    models = {
        name: {"tokens": {"prompt": int((e or {}).get("input_tokens", 0) or 0),
                          "candidates": int((e or {}).get("output_tokens", 0) or 0)}}
        for name, e in (stats.get("models") or {}).items()
    }
    env: dict = {"session_id": session_id, "response": "".join(chunks),
                 "stats": {"models": models} if models else {}}
    if result.get("status") != "success":
        err = result.get("error")
        env["error"] = err if isinstance(err, dict) else {
            "message": str(err or f"gemini stream ended with status {result.get('status')!r}")}
    return env


def _gemini_activity(line: str) -> str | None:
    """One progress line from a Gemini ``stream-json`` event: a tool call (deltas are too fine)."""
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        return None
    if ev.get("type") != "tool_use":
        return None
    params = ev.get("parameters") if isinstance(ev.get("parameters"), dict) else {}
    detail = next((str(params[k]) for k in ("command", "file_path", "pattern", "dir_path", "path",
                                            "query", "url") if params.get(k)), "")
    return f"{ev.get('tool_name', 'tool')} {detail}".strip()


# -------------------------------------------------------------------------------- codex
#: TOML config path that re-enables network egress inside the workspace-write sandbox. Used ONLY
#: for the research stage; isolated as a constant so a Codex-version key change is a one-line fix.
_CODEX_NETWORK_CFG = "sandbox_workspace_write.network_access=true"
#: Offline stages: also switch off Codex's built-in web_search tool (values: disabled | cached |
#: indexed | live -- verified against codex-cli 0.166.0, which rejects any other variant).
_CODEX_WEB_SEARCH_OFF = 'web_search="disabled"'


def _scan_codex_tokens(stdout_jsonl: str) -> tuple[int, int]:
    """Best-effort token counts from Codex `--json` JSONL events (Codex reports tokens, not USD).
    Defensive: tolerates schema variation, returns the max seen (token events often carry running
    totals); (0, 0) if nothing parseable."""
    in_tok = out_tok = 0
    for line in (stdout_jsonl or "").splitlines():
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        u = ev.get("usage") if isinstance(ev.get("usage"), dict) else ev
        it = u.get("input_tokens") or u.get("prompt_tokens")
        ot = u.get("output_tokens") or u.get("completion_tokens")
        if isinstance(it, int):
            in_tok = max(in_tok, it)
        if isinstance(ot, int):
            out_tok = max(out_tok, ot)
    return in_tok, out_tok


def _scan_codex_models(stdout_jsonl: str) -> tuple[str, ...]:
    """Extract served model IDs from Codex JSONL without guessing from the command line."""
    found: list[str] = []
    for line in (stdout_jsonl or "").splitlines():
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        candidates = [event.get("model"), event.get("model_id"),
                      (event.get("response") or {}).get("model")
                      if isinstance(event.get("response"), dict) else None]
        for candidate in candidates:
            if isinstance(candidate, str) and candidate.strip() and candidate not in found:
                found.append(candidate.strip())
    return tuple(found)


#: Codex `--json` item types that are NOT a tool call (everything else completed by the agent --
#: command_execution, file_change, mcp_tool_call, web_search, collab_tool_call, ... -- counts as one
#: turn, the closest equivalent of Claude's ``num_turns``).
_CODEX_NON_TOOL_ITEMS = frozenset({"agent_message", "reasoning", "error", "todo_list"})
#: The same tool call with the same result this many times IN A ROW is a loop, not progress.
#: Observed live (Qwen3-Coder-Next via Ollama, 2026-11-05): >1000 near-identical short calls that
#: grew one session to the 131K context limit before any artifact was written.
_CODEX_LOOP_REPEAT = 6
#: Consecutive FAILED tool calls (non-zero exit / failed status) before the session is declared
#: stuck -- e.g. a sandbox that rejects every command, which a weak model just keeps retrying.
_CODEX_FAIL_STREAK = 20


def _codex_tool_items(stdout_jsonl: str):
    """Yield every completed tool-call item from Codex `--json` output."""
    for line in (stdout_jsonl or "").splitlines():
        item = _codex_completed_tool_item(line)
        if item is not None:
            yield item


def _codex_completed_tool_item(line: str) -> dict | None:
    line = line.strip()
    if not line or line[0] != "{":
        return None
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        return None
    if ev.get("type") != "item.completed" or not isinstance(ev.get("item"), dict):
        return None
    item = ev["item"]
    return None if item.get("type") in _CODEX_NON_TOOL_ITEMS else item


#: Longest activity line shown to a live viewer (a command or an interim message, one line).
_ACTIVITY_MAX_CHARS = 200


def _codex_activity(line: str) -> str | None:
    """One human-readable progress line from a Codex ``--json`` event, or None.

    A started command / file change / tool call, or a completed interim agent message."""
    line = line.strip()
    if not line or line[0] != "{":
        return None
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        return None
    item = ev.get("item") if isinstance(ev.get("item"), dict) else None
    if item is None:
        return None
    kind = item.get("type")
    if ev.get("type") == "item.started":
        if kind == "command_execution":
            return "$ " + str(item.get("command") or "")
        if kind == "file_change":
            paths = [c.get("path") for c in item.get("changes") or [] if isinstance(c, dict)]
            return "edit " + ", ".join(p for p in paths if p) if paths else "edit"
        if kind in {"mcp_tool_call", "web_search"}:
            return str(item.get("tool") or item.get("query") or kind)
    if ev.get("type") == "item.completed" and kind == "agent_message":
        return str(item.get("text") or "") or None
    return None


def _codex_events_path(work_dir: Path, label: str) -> Path:
    """``<work parent>/.argo_sessions/<work name>.codex.<label>.jsonl`` -- next to, never inside,
    the session's scratch cwd."""
    work_dir = Path(work_dir)
    return work_dir.parent / ".argo_sessions" / f"{work_dir.name}.codex.{label}.jsonl"


def _count_codex_turns(stdout_jsonl: str) -> int:
    return sum(1 for _ in _codex_tool_items(stdout_jsonl))


class _CodexSessionGuard:
    """Streaming tripwire for one `codex exec --json` session (fed line by line by ``_exec``).

    Codex has no native turn cap and Argo previously only saw its output after exit, so
    ``session_max_turns`` was never enforced for this backend (``num_turns`` was hard-coded 0) and a
    looping local model could run until the stage timeout. This guard returns an abort reason as
    soon as the cap is exceeded or the agent is visibly looping, and tees every event line to
    ``events_path`` so a failed session can be diagnosed afterwards."""

    def __init__(self, *, max_turns: int | None, events_path: Path | None = None):
        self.max_turns = max_turns
        self.events_path = events_path
        self.turns = 0
        self.kind: str | None = None
        self._last_sig: str | None = None
        self._repeat = 0
        self._fail_streak = 0
        self._fh = None
        if events_path is not None:
            try:
                events_path.parent.mkdir(parents=True, exist_ok=True)
                self._fh = events_path.open("a", encoding="utf-8")
            except OSError:
                self._fh = None

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None

    def __call__(self, line: str) -> str | None:
        if self._fh is not None:
            try:
                self._fh.write(line if line.endswith("\n") else line + "\n")
                self._fh.flush()
            except OSError:
                pass
        item = _codex_completed_tool_item(line)
        if item is None:
            return None
        self.turns += 1
        if self.max_turns is not None and self.turns > self.max_turns:
            self.kind = "turn_cap"
            return f"session exceeded max_turns cap {self.max_turns} (num_turns={self.turns})"
        call = item.get("command") or item.get("tool") or item.get("server") or ""
        sig = json.dumps([item.get("type"), call, item.get("exit_code"),
                          str(item.get("aggregated_output") or item.get("status") or "")[:300]])
        self._repeat = self._repeat + 1 if sig == self._last_sig else 1
        self._last_sig = sig
        if self._repeat >= _CODEX_LOOP_REPEAT:
            self.kind = "tool_loop"
            return (f"agent repeated the same tool call {self._repeat}x in a row "
                    f"({item.get('type')}: {str(call)[:120]!r})")
        failed = (item.get("exit_code") not in (None, 0)) or item.get("status") == "failed"
        self._fail_streak = self._fail_streak + 1 if failed else 0
        if self._fail_streak >= _CODEX_FAIL_STREAK:
            self.kind = "tool_loop"
            return (f"{self._fail_streak} consecutive failed tool calls (last: "
                    f"{str(call)[:120]!r}); the sandbox or tool contract is likely broken")
        return None


_CODEX_HOME_CACHE_ROOT = Path.home() / ".argo" / "codex_homes"

# Serializes bootstrap of a given key's CODEX_HOME across concurrent CodexRunner instances IN THIS
# PROCESS (Argo's fan-out is thread-based -- ThreadPoolExecutor in audit.py/validate.py/
# corroborate.py/deep_verify.py/benchmark.py -- never multiprocessing, so a plain threading.Lock
# genuinely serializes every real caller). Does NOT protect against two SEPARATE `argo` process
# invocations racing the same key at the same time -- an accepted, low-severity residual: both
# would attempt the same login with the same key and land on the same correct end state, at worst
# wasting one redundant `codex login` call, never corrupting or mismatching credentials.
_codex_api_key_locks: dict[str, threading.Lock] = {}
_codex_api_key_locks_guard = threading.Lock()


def _codex_home_for_api_key(key: str, *, cache_root: Path | None = None) -> Path:
    """Deterministic cache dir for a given OpenAI API key -- keyed by a HASH so the literal key
    value never appears in a filesystem path (process listings, shell history expansions, `ls`
    output, backup tooling, crash dumps that include argv/cwd). Same key -> same directory ->
    bootstrap runs at most once per key per machine (cache_root lets tests point elsewhere)."""
    root = cache_root if cache_root is not None else _CODEX_HOME_CACHE_ROOT
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return root / digest


def _run_codex_cli(args: list[str], *, codex_home: Path, input_text: str | None = None,
                   timeout: int = 30) -> subprocess.CompletedProcess:
    """Thin, mockable wrapper around a short-lived (non-session) Codex CLI call -- login / login
    status. Deliberately NOT AgentRunner._exec: that machinery models a cancellable LLM session
    with ledger/jsonl logging and a cancel_event; this is a one-off setup step that must never be
    logged as an LLM call (no tokens, no cost, no prompt) and has no cancellation semantics."""
    env = {**os.environ, "CODEX_HOME": str(codex_home)}
    return subprocess.run(args, input=input_text, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=env, timeout=timeout)


def _codex_login_status_ok(codex_home: Path, *, codex_bin: str = "codex") -> bool:
    """Idempotency check: ask the CLI itself (`codex login status`) rather than inferring from an
    auth-file's presence/name/format, which is an internal implementation detail that can change
    across Codex CLI versions. Best-effort: ANY failure (timeout, missing binary, ambiguous exit)
    is treated as "not logged in", so the caller falls through to a (re-)bootstrap rather than
    silently trusting a broken/expired login."""
    try:
        proc = _run_codex_cli([codex_bin, "login", "status"], codex_home=codex_home, timeout=20)
    except Exception:
        return False
    out = f"{proc.stdout or ''}\n{proc.stderr or ''}".lower()
    return proc.returncode == 0 and "not logged in" not in out


def _ensure_codex_api_key_home(key: str, *, codex_bin: str = "codex",
                               cache_root: Path | None = None) -> Path:
    """Idempotently bootstrap (or reuse) a CODEX_HOME directory authenticated against `key` via
    `codex login --with-api-key`, piping the key over STDIN only -- NEVER as an argv element (argv
    is visible in process listings / crash dumps / some shell histories; stdin is not). Returns the
    CODEX_HOME path; callers plug it straight into the SAME env["CODEX_HOME"] slot the existing
    codex_home/codex_accounts mechanism already uses (CodexRunner._codex_home_env_value) -- every
    other line of CodexRunner._invoke/_build_codex_cmd needs ZERO changes.

    Serialized per key-digest (module-level lock, not per-runner-instance): multiple CodexRunner
    instances built from the SAME key (e.g. a --codex-api-keys chain reused across --parallel-cases
    threads) must never race two concurrent `codex login --with-api-key` calls into the same
    directory. Different keys bootstrap fully in parallel (no cross-key contention).
    """
    home = _codex_home_for_api_key(key, cache_root=cache_root)
    digest = home.name
    with _codex_api_key_locks_guard:
        lock = _codex_api_key_locks.setdefault(digest, threading.Lock())
    with lock:
        root = home.parent
        try:
            root.mkdir(parents=True, exist_ok=True)
            home.mkdir(exist_ok=True)
        except OSError as exc:
            raise RunnerError(
                f"could not create Codex credential cache directory {home}: {exc}",
                failure_kind="credential_bootstrap") from exc
        for directory in (root, home):
            info = directory.lstat()
            is_reparse = bool(getattr(info, "st_file_attributes", 0)
                              & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
            if stat.S_ISLNK(info.st_mode) or is_reparse or not stat.S_ISDIR(info.st_mode):
                raise RunnerError(
                    f"refusing unsafe Codex credential cache path: {directory}",
                    failure_kind="credential_bootstrap")
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise RunnerError(
                    f"refusing Codex credential cache path not owned by the current user: "
                    f"{directory}", failure_kind="credential_bootstrap")
        if os.name == "posix":
            try:
                os.chmod(root, 0o700)
                os.chmod(home, 0o700)
            except OSError as exc:
                raise RunnerError(
                    f"could not secure Codex credential cache directory {home}: {exc}",
                    failure_kind="credential_bootstrap") from exc
            for directory in (root, home):
                if stat.S_IMODE(directory.stat().st_mode) != 0o700:
                    raise RunnerError(
                        f"Codex credential cache directory is not private (expected mode 0700): "
                        f"{directory}", failure_kind="credential_bootstrap")
        if _codex_login_status_ok(home, codex_bin=codex_bin):
            return home
        try:
            proc = _run_codex_cli([codex_bin, "login", "--with-api-key"], codex_home=home,
                                  input_text=key, timeout=60)
        except Exception as exc:
            raise RunnerError(
                f"codex login --with-api-key failed to run while bootstrapping a Codex API-key "
                f"session (codex_home={home}): "
                f"{_redact_secrets(str(exc), key)}",
                failure_kind="credential_bootstrap") from exc
        if proc.returncode != 0:
            raise RunnerError(
                f"codex login --with-api-key exited {proc.returncode} while bootstrapping a Codex "
                f"API-key session (codex_home={home}); stderr tail:\n"
                f"{_redact_secrets(proc.stderr, key)[-1500:]}",
                failure_kind="credential_bootstrap")
        return home


class CodexRunner(AgentRunner):
    """Runs the **Codex CLI** (`codex exec`) — OpenAI models, or local/open-source via `--oss`.

    The guardrails map onto Codex's **OS sandbox** instead of a tool allowlist:
      * ``-s workspace-write`` — the model may write ONLY inside its workspace (the scratch cwd) and
        the network is denied; the target repo lives OUTSIDE the workspace (and is chmod read-only by
        ingest), so it is readable but never writable;
      * ``-a never`` — no approval escalation (non-interactive), failures returned to the model;
      * the network is re-enabled **only** for the ``research`` stage, via ``_CODEX_NETWORK_CFG``.
    It never uses ``danger-full-access`` or ``--dangerously-bypass-*``. Cost is **estimated** from
    token usage (Codex reports tokens, not dollars) — see ``config.estimate_cost_usd``.
    """

    def __init__(self, config: PipelineConfig, ledger: Ledger, codex_bin: str = "codex"):
        super().__init__(config, ledger)
        self.codex_bin = codex_bin
        self._resolved_bin: str | None = None
        self._resolved_api_key_home: Path | None = None  # memoized across many _invoke calls

    def _bin(self) -> str:
        if self._resolved_bin is None:
            resolved = shutil.which(self.codex_bin)
            if not resolved:
                raise RunnerError(f"codex CLI not found on PATH (looked for {self.codex_bin!r}); "
                                  "install the Codex CLI or use --runner headless/mock")
            self._resolved_bin = resolved
        return self._resolved_bin

    def _codex_home_env_value(self) -> str | None:
        """codex_home (an explicit, already-set-up directory) always wins over codex_api_key -- both
        ultimately resolve to one CODEX_HOME value, a real collision, and an explicit directory is
        the stronger signal. Bootstrap is LAZY (first real call, not __init__): _expand_backend
        builds one CodexRunner per --codex-api-keys entry up front, most of which may never actually
        fire in a FallbackRunner chain -- eager bootstrap in __init__ would force a real subprocess
        call (and a `codex` CLI PATH requirement) for every configured account."""
        if self.config.codex_home:
            return os.path.abspath(os.path.expanduser(str(self.config.codex_home)))
        if self.config.codex_api_key:
            if self._resolved_api_key_home is None:
                self._resolved_api_key_home = _ensure_codex_api_key_home(
                    self.config.codex_api_key, codex_bin=self._bin())
            return str(self._resolved_api_key_home)
        return None

    def _effective_model_label(self) -> str:
        return repr(self.config.codex_model) if self.config.codex_model else "(CLI default)"

    def _build_codex_cmd(self, *, model, policy, last_msg_file: Path) -> list[str]:
        cmd = [self._bin(), "exec",            # `exec` is non-interactive (never prompts for approval)
               "-s", "workspace-write",        # write only the scratch cwd; network off by default
               "--skip-git-repo-check",        # the scratch cwd is not a git repo
               "--ephemeral",                  # do not persist session files
               "--json",                       # JSONL events on stdout (token usage)
               "-o", str(last_msg_file)]       # final agent message -> file
        if self.config.codex_oss:
            cmd.append("--oss")
            if self.config.codex_local_provider:
                cmd += ["--local-provider", self.config.codex_local_provider]
        if self.config.codex_model:
            cmd += ["-m", self.config.codex_model]
        # Tools Argo never wants: multi_agent lets the model spawn sub-agents whose tool calls,
        # tokens and turns never appear in this session's event stream (observed live: a recon
        # session delegated its work to an invisible child) -- that defeats every per-session cap.
        for feature in self.config.codex_disable_features:
            cmd += ["--disable", feature]
        # Local models are unknown to Codex ("Model metadata ... not found; defaulting to fallback
        # metadata"), so it cannot auto-compact before the server's own context limit, and Ollama
        # then silently discards the oldest half of the conversation (context shift). Declaring the
        # real window lets Codex compact in time.
        window = self.config.codex_context_window
        if window:
            cmd += ["-c", f"model_context_window={int(window)}",
                    "-c", f"model_auto_compact_token_limit={int(window * 0.8)}"]
        if policy is not None and policy.network:   # ONLY the research stage gets network egress
            cmd += ["-c", _CODEX_NETWORK_CFG]
        else:
            # The sandbox's network denial does NOT cover Codex's provider-side web_search tool:
            # observed live, an offline audit session searched the web and Ollama forwarded it to
            # its cloud endpoint (/api/experimental/web_search; it failed only for lack of login).
            cmd += ["-c", _CODEX_WEB_SEARCH_OFF]
        cmd.append("-")                         # read the prompt (instructions) from stdin
        return cmd

    def _invoke(self, *, prompt, work_dir, model, repo_dir, allowed, disallowed, policy=None,
                stage, run_id, label, session_budget_usd=None, timeout_s=None) -> dict:
        last_msg = Path(work_dir) / ".codex_last_message.txt"
        cmd = self._build_codex_cmd(model=model, policy=policy, last_msg_file=last_msg)
        timeout = timeout_s or self.config.session_timeout_s
        # Multi-account: point this invocation at a specific Codex config home (CODEX_HOME) so an
        # account-fallback can switch Codex accounts (limits are per-account). See build_runner.
        # codex_api_key resolves (once, memoized, cached on disk) to a bootstrapped CODEX_HOME via
        # _codex_home_env_value -- see that method for the codex_home-wins precedence rule.
        env = None
        home_value = self._codex_home_env_value()
        if home_value:
            env = {**os.environ, "CODEX_HOME": home_value}
        events_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", label or stage)
        guard = _CodexSessionGuard(
            max_turns=self.config.session_max_turns,
            # OUTSIDE the session's cwd: inside it the model lists and `cat`s its own growing event
            # log (observed live), feeding the transcript back into its context. The sibling dir
            # is also outside the workspace-write root, so the model cannot tamper with it.
            events_path=_codex_events_path(Path(work_dir), events_name))
        try:
            proc = self._exec(cmd, prompt=prompt, cwd=work_dir, timeout=timeout, env=env,
                              on_stdout_line=self._with_activity(guard, _codex_activity))
        except SessionGuardTripped as exc:
            # turn_cap keeps the historical non-retryable semantics of the post-hoc cap check;
            # a tool loop is stochastic for a local model, so one fresh attempt is reasonable.
            raise RunnerError(
                f"codex session stopped by guard: {exc.reason} (stage={stage}, run_id={run_id}, "
                f"label={label}); events: {guard.events_path}",
                retryable=guard.kind == "tool_loop",
                failure_kind=guard.kind or "tool_loop") from exc
        except subprocess.TimeoutExpired as exc:  # pragma: no cover - real-runner path
            # A genuine hang-then-kill is not a deterministic failure -- the same call could well
            # succeed on a retry (this backend again, after a cooldown, or a fallback). Previously
            # NOT marked retryable, so a single hang killed the whole run with no fallback attempt.
            raise RunnerError(
                f"codex session timed out after {timeout}s (stage={stage}, "
                f"run_id={run_id}, label={label}, tool_calls={guard.turns})",
                retryable=True, failure_kind="timeout") from exc
        finally:
            guard.close()
        text = last_msg.read_text(encoding="utf-8", errors="replace") if last_msg.exists() else ""
        if proc.returncode != 0 and not text and not (proc.stdout or "").strip():
            # "No output at all" is the exact shape of BOTH an immediate moderation flag (fires
            # before any tool call ran) and credits exhaustion (every call after the account runs
            # dry exits instantly, 0 tokens) -- the two are structurally identical here and only
            # distinguishable by the actual stderr text. Classify it either way. Previously this
            # path was NOT marked retryable at all, so Argo never even tried a configured fallback
            # backend on exactly the failure shape fallback exists for -- fixed: always retryable,
            # a wasted retry here costs ~0 tokens and sub-second wall clock either way.
            stderr = _redact_secrets(proc.stderr, self.config.codex_api_key)
            advice = _codex_model_unavailable(stderr)
            if advice:
                raise RunnerError(
                    f"codex model {self._effective_model_label()} unavailable for this account "
                    f"(stage={stage}, label={label}): {advice}",
                    retryable=True, failure_kind="model_unavailable")
            kind = _classify_failure_text(stderr) or "unknown_retryable"
            raise RunnerError(
                f"codex produced no output (stage={stage}, run_id={run_id}, label={label}, "
                f"exit={proc.returncode}); likely auth/startup failure.\nstderr tail:\n"
                f"{stderr[-1500:]}",
                retryable=True, failure_kind=kind)
        stdout = _redact_secrets(proc.stdout, self.config.codex_api_key)
        stderr = _redact_secrets(proc.stderr, self.config.codex_api_key)
        if proc.returncode != 0:
            # stderr and CLI error events only: stdout also carries tool output (target files),
            # which must not be able to classify the failure.
            advice = _codex_model_unavailable(f"{_codex_error_events(stdout)} {stderr}")
            if advice:
                # retryable=True so FallbackRunner can try the next account/backend; the failure
                # kind is terminal, so recon/audit do not re-run it on this same account.
                raise RunnerError(
                    f"codex model {self._effective_model_label()} unavailable for this account "
                    f"(stage={stage}, label={label}): {advice}",
                    retryable=True, failure_kind="model_unavailable")
        return {"_backend": "codex", "returncode": proc.returncode, "text": text,
                "stdout": stdout, "stderr": stderr[-2000:]}

    def parse_envelope(self, raw: dict, *, model: str, prompt_sha256: str,
                       work_dir: Path) -> LLMResult:
        rc = int(raw.get("returncode", 0) or 0)
        text = raw.get("text") or ""
        stdout = raw.get("stdout", "")
        in_tok, out_tok = _scan_codex_tokens(stdout)
        served_models = _scan_codex_models(stdout)
        served = served_models[0] if len(served_models) == 1 else None
        effective_model = served or model
        return LLMResult(
            text=text, model=model, prompt_sha256=prompt_sha256, work_dir=work_dir,
            input_tokens=in_tok, output_tokens=out_tok,
            cost_usd=estimate_cost_usd(effective_model, in_tok, out_tok),   # estimated (token-based)
            num_turns=_count_codex_turns(stdout), session_id=None, stop_reason=f"exit_{rc}",
            is_error=(rc != 0),   # non-zero -> recoverable (the stage globs scratch for partials)
            api_error_status=None, raw=raw, requested_model=model,
            served_model=served, served_models=served_models,
            cost_source=model_cost_source(effective_model),
        )


# ------------------------------------------------------------------------------- gemini
#: Policy Engine TOML (see docs/backends.md "Gemini specifics"). A DENY-list, not an allow-list:
#: enumerating every Gemini tool name Claude's ARTIFACT_TOOLS would map onto is unnecessary and
#: fragile (some names, e.g. an Edit/MultiEdit equivalent, are unconfirmed) — a small, well-
#: confirmed deny-list is simpler AND safer. run_shell_command is denied unconditionally (Argo never
#: needs shell, mirrors Bash living in ALWAYS_DISALLOWED); everything else --approval-mode yolo
#: auto-approves. Confirmed live 2026-08-17 (gemini-cli v0.49.0): a denied tool is removed from the
#: model's declared tool set entirely (it reports having no such tool), not merely blocked post-call
#: — clean, headless-safe, and unlike --sandbox has zero external (Docker/Podman) dependency.
#:
#: Repo-write safety does NOT depend on this policy: argo/stages/ingest.py:_make_readonly already
#: os.chmod's the acquired repo copy read-only, backend-agnostically, before any runner touches it —
#: a write_file call into repo_dir fails at the OS level regardless of what this policy allows.
_GEMINI_POLICY_OFFLINE = """\
[[rule]]
toolName = "run_shell_command"
decision = "deny"
priority = 100

[[rule]]
toolName = ["google_web_search", "web_fetch"]
decision = "deny"
priority = 100
"""

#: Network carve-out for the research/corroborate stages ONLY — same two tools the OSINT_TOOLS
#: exception permits on Claude, mirroring CodexRunner._build_codex_cmd's exact
#: `if policy is not None and policy.network:` branch shape (an extra sandbox cfg flag there;
#: here, simply omitting the two web-tool deny rules). Shell stays denied even here — no stage
#: is ever permitted a shell tool, network or not.
_GEMINI_POLICY_NETWORK = """\
[[rule]]
toolName = "run_shell_command"
decision = "deny"
priority = 100
"""

#: Gemini's soft safety refusals arrive as ordinary first-person declining prose inside a NORMAL,
#: success-shaped envelope (confirmed live 2026-08-17 against gemini-cli v0.49.0 — no structured
#: finishReason field is surfaced by the CLI's --output-format json output, unlike the raw Gemini
#: API). Unlike Claude's/Codex's fixed classifier-boilerplate signatures, there is no stable marker
#: string to match reliably on its own ("I cannot provide ..." also shows up in mundane, non-refusal
#: replies) — so this requires a first-person refusal phrase to CO-OCCUR with a safety/
#: authorization-flavored word. A conservative heuristic that trades recall for precision: a genuine
#: refusal phrased unusually may be missed and surface as a downstream "no artifact produced"
#: failure instead of a clean moderation_flagged one — a known, documented gap, not a silent one.
_GEMINI_REFUSAL_PHRASES = ("i cannot provide", "i can't provide", "i cannot assist", "i can't assist",
                          "i'm not able to provide", "i am not able to provide",
                          "i cannot help with", "i can't help with")
_GEMINI_REFUSAL_CONTEXT_WORDS = ("unauthorized", "malicious", "attack", "destroy", "exploit",
                                 "illegal", "harmful", "victim")
#: Argo-owned marker prepended to a detected soft refusal's text, so the SHARED, module-level
#: _classify_failure_text (called from the base class's generic is_error path, which this backend
#: cannot override in isolation) has something concrete to match — the same bridge mechanism
#: Claude's/Codex's own fixed signatures use, just fed by a heuristic instead of a literal string.
_GEMINI_MODERATION_MARKER = "argo-gemini-heuristic-refusal-detected"


def _looks_like_gemini_refusal(text: str) -> bool:
    s = (text or "").lower()
    return (any(p in s for p in _GEMINI_REFUSAL_PHRASES)
            and any(w in s for w in _GEMINI_REFUSAL_CONTEXT_WORDS))


def _gemini_tool_calls(raw: dict) -> int:
    """Tool calls the Gemini CLI reports in ``stats.tools.totalCalls`` (0 when absent), so the
    post-call ``session_max_turns`` tripwire applies to this backend as to Claude."""
    try:
        return int((((raw.get("stats") or {}).get("tools") or {}).get("totalCalls")) or 0)
    except (TypeError, ValueError, AttributeError):
        return 0


class GeminiRunner(AgentRunner):
    """Runs the **Gemini CLI** (`gemini`) — Google's Gemini models, tiered per stage like Claude
    (pro/flash/flash-lite; see DEFAULT_GEMINI_STAGE_MODELS), unlike Codex's flat single model.

    Every design choice below reflects EMPIRICAL testing against a real `gemini` CLI (v0.49.0,
    2026-08-17), not docs alone — see the Gemini backend plan's "Phase 0" for the full findings:

      * The prompt is piped via **stdin only** (no `-p`) — confirmed to trigger the identical
        non-interactive JSON path, and avoids `-p`'s documented stdin-APPENDS-not-replaces quirk.
      * ``--skip-trust`` is REQUIRED on every call — a fresh, never-interactively-trusted scratch
        dir otherwise makes the CLI exit 55 ("not running in a trusted directory").
      * ``--include-directories <repo_dir>`` grants read access to the target repo (confirmed via
        a real cross-directory read), which stays outside the scratch cwd, same layout as Codex.
      * Guardrails map onto the **Policy Engine** (``--policy <toml>``), NOT ``--sandbox`` — see
        `_GEMINI_POLICY_OFFLINE`'s docstring for why (a hard, unreliable Docker/Podman dependency
        that failed outright in Phase 0 testing, confirmed live, vs. zero-dependency and confirmed
        working). ``--approval-mode yolo`` auto-approves whatever the policy doesn't deny — every
        Argo stage's session needs to Write its artifact, as Claude's path-scoped ``Edit(./**)``
        rule and Codex's non-interactive exec allow.
      * Cost is **estimated** from token usage (like Codex — Gemini reports tokens, not USD), but
        MUST be summed across every entry in ``stats.models``: omitting `-m` was found to trigger
        an extra internal "utility_router" model call that also lands in that dict; Argo always
        pins `-m`, so in practice there is usually exactly one entry, but the code must not assume
        that.
    """

    def __init__(self, config: PipelineConfig, ledger: Ledger, gemini_bin: str = "gemini"):
        super().__init__(config, ledger)
        self.gemini_bin = gemini_bin
        self._resolved_bin: str | None = None

    def _bin(self) -> str:
        if self._resolved_bin is None:
            resolved = shutil.which(self.gemini_bin)
            if not resolved:
                raise RunnerError(
                    f"gemini CLI not found on PATH (looked for {self.gemini_bin!r}); "
                    "install the Gemini CLI or use --runner headless/codex/mock")
            self._resolved_bin = resolved
        return self._resolved_bin

    def _build_gemini_cmd(self, *, model, repo_dir, policy_file: Path, stream=False) -> list[str]:
        cmd = [
            self._bin(),
            # stream-json only while a live viewer is attached (chat); converted back to the json
            # envelope by _gemini_stream_envelope, so parse_envelope is unchanged.
            "--output-format", "stream-json" if stream else "json",
            "--skip-trust",              # see class docstring — required for a fresh scratch dir
            "--approval-mode", "yolo",   # non-interactive auto-approve for whatever isn't denied
            "-m", model,
            "--policy", str(policy_file),
        ]
        if repo_dir is not None:
            cmd += ["--include-directories", str(Path(repo_dir).resolve())]
        return cmd

    def _invoke(self, *, prompt, work_dir, model, repo_dir, allowed, disallowed, policy=None,
               stage, run_id, label, session_budget_usd=None, timeout_s=None) -> dict:
        policy_toml = (_GEMINI_POLICY_NETWORK if (policy is not None and policy.network)
                      else _GEMINI_POLICY_OFFLINE)
        policy_file = Path(work_dir) / ".argo_gemini_policy.toml"
        policy_file.write_text(policy_toml, encoding="utf-8")
        stream = self.on_activity is not None
        cmd = self._build_gemini_cmd(model=model, repo_dir=repo_dir, policy_file=policy_file,
                                     stream=stream)
        timeout = timeout_s or self.config.session_timeout_s
        # Multi-account: point this invocation at a specific Gemini API key so an account-fallback
        # can switch keys (limits are per-key/project). See build_runner / _expand_backend. Unlike
        # Claude/Codex's directory-based env vars, this is a real secret value, not a path.
        env = None
        if self.config.gemini_api_key:
            env = {**os.environ, "GEMINI_API_KEY": self.config.gemini_api_key}
        try:
            proc = self._exec(cmd, prompt=prompt, cwd=work_dir, timeout=timeout, env=env,
                              on_stdout_line=(self._with_activity(None, _gemini_activity)
                                              if stream else None))
        except subprocess.TimeoutExpired as exc:  # pragma: no cover - real-runner path
            raise RunnerError(
                f"gemini session timed out after {timeout}s "
                f"(stage={stage}, run_id={run_id}, label={label})",
                retryable=True, failure_kind="timeout") from exc

        # Exit codes 42 (invalid input) and 53 (turn-limit) are a stable, documented part of the
        # CLI's exit-code contract, independent of the JSON-envelope shape gap Phase 0 closed —
        # handled directly here (not via parse_envelope's generic is_error path) because they need
        # DIFFERENT retryability that the generic path has no way to express: 42 is structurally
        # unfixable by retrying, 53 is retryable with its own new FailureKind.
        if proc.returncode == 42:
            raise RunnerError(
                f"gemini rejected invalid input (stage={stage}, run_id={run_id}, label={label}, "
                f"exit=42)\nstderr tail:\n{(proc.stderr or '')[-1500:]}",
                retryable=False)
        if proc.returncode == 53:
            raise RunnerError(
                f"gemini session hit its turn limit (stage={stage}, run_id={run_id}, "
                f"label={label}, exit=53)\nstderr tail:\n{(proc.stderr or '')[-1500:]}",
                retryable=True, failure_kind="turn_limit_exceeded")

        # A result envelope may arrive WITH a non-zero exit (e.g. the quota-error shape confirmed
        # live: exit 1, a clean {"error": {...}} envelope on stdout) — prefer parsing stdout, and
        # only fall back to a hard error if there is no usable JSON at all (e.g. the FatalSandbox
        # Error startup-crash shape confirmed live: nothing on stdout, everything on stderr).
        out = (proc.stdout or "").strip()
        if out:
            if stream:
                envelope = _gemini_stream_envelope(out)
            else:
                try:
                    envelope = json.loads(out)
                except json.JSONDecodeError:
                    envelope = None
            if isinstance(envelope, dict):
                envelope["_exit_code"] = proc.returncode
                return envelope  # parse_envelope validates shape + classifies is_error

        kind = _classify_failure_text(proc.stderr) or "unknown_retryable"
        raise RunnerError(
            f"gemini produced no parseable JSON envelope (stage={stage}, run_id={run_id}, "
            f"label={label}, exit={proc.returncode}); likely auth/startup/sandbox failure.\n"
            f"stderr tail:\n{(proc.stderr or '')[-1500:]}",
            retryable=True, failure_kind=kind)

    def parse_envelope(self, raw: dict, *, model: str, prompt_sha256: str,
                       work_dir: Path) -> LLMResult:
        error = raw.get("error")
        is_error = error is not None
        if is_error:
            text = (error.get("message") if isinstance(error, dict) else str(error)) or ""
        else:
            text = raw.get("response") or ""
            if _looks_like_gemini_refusal(text):
                # Bridge: force is_error so the base class's generic error path (and run()'s
                # neutral-register retry) treats this the same as Claude's/Codex's moderation
                # flags, even though the CLI itself returned a nominally successful envelope.
                is_error = True
                text = f"{_GEMINI_MODERATION_MARKER}: {text}"

        in_tok = out_tok = 0
        cost = 0.0
        cost_known = True
        served_models: list[str] = []
        for served_name, entry in ((raw.get("stats") or {}).get("models") or {}).items():
            if isinstance(served_name, str) and served_name not in served_models:
                served_models.append(served_name)
            tok = (entry or {}).get("tokens") or {}
            # "prompt" (total context, incl. cached) not "input" (cached-excluded) — a deliberate
            # safe-direction overestimate when caching is active, matching the same rounding
            # rationale already documented for MODEL_PRICING's >200k-token Pro tier gap.
            entry_in = int(tok.get("prompt", tok.get("input", 0)) or 0)
            entry_out = int(tok.get("candidates", 0) or 0)
            in_tok += entry_in
            out_tok += entry_out
            entry_cost = estimate_cost_usd(served_name, entry_in, entry_out)
            if model_cost_source(served_name) == "unknown":
                cost_known = False
            cost += entry_cost

        served_tuple = tuple(served_models)
        served = served_tuple[0] if len(served_tuple) == 1 else None
        # Some CLI versions omit stats.models. In that case the requested ID is the only honest
        # cost basis, but it remains marked as estimated rather than served-model proof.
        if not served_tuple:
            cost = estimate_cost_usd(model, in_tok, out_tok)
            cost_known = model_cost_source(model) != "unknown"

        return LLMResult(
            text=text, model=model, prompt_sha256=prompt_sha256, work_dir=work_dir,
            input_tokens=in_tok, output_tokens=out_tok,
            cost_usd=cost,   # estimated (token-based)
            num_turns=_gemini_tool_calls(raw), session_id=raw.get("session_id"),
            stop_reason=f"exit_{raw.get('_exit_code', 0)}",
            is_error=is_error, api_error_status=None, raw=raw,
            requested_model=model, served_model=served, served_models=served_tuple,
            cost_source="estimated_known_price" if cost_known else "unknown",
        )


# ------------------------------------------------------------------------------- mock
class MockClaudeRunner(ClaudeRunner):
    """Deterministic, zero-token runner. Writes fixture files into the session scratch dir
    (exercising the file-based artifact path) and returns a synthetic JSON envelope whose
    ``result`` carries the index manifest.

    Fixtures live under ``<fixtures_dir>/<scenario>/`` with this layout::

        ingest/scope.json
        recon/{repo_profile.json, audit_*.md, synthesis_notes.md}
        audit/<slug>.findings.json
        validate/verdicts.json          # {finding_id: {...verdict...}, "_default": {...}}
        validate/dedup_clusters.json    # optional: {"clusters": [{primary_id, duplicate_ids, reason}]}

    Failure scenarios are driven by sentinel files (see ``_audit`` / ``_recon``)."""

    # Per-call synthetic cost so the ledger has something to sum; kept at 0.0 so golden
    # REPORT.md output stays deterministic regardless of call count.
    MOCK_COST = 0.0

    def __init__(self, config: PipelineConfig, ledger: Ledger):
        super().__init__(config, ledger)
        self.scenario_dir = Path(config.fixtures_dir) / config.fixtures_scenario

    # -- dispatch ---------------------------------------------------------------------
    def _invoke(self, *, prompt, work_dir, model, repo_dir, allowed, disallowed, policy=None,
                stage, run_id, label, session_budget_usd=None, timeout_s=None) -> dict:
        if stage == "chat":
            self._activity("$ rg -n 'get_order' src/")      # synthetic, like a real tool call
            self._activity("Reading the run's validated findings")
            return self._chat(work_dir, label, prompt)
        if stage == "research":
            return self._research(work_dir, label)
        if stage == "remediate":
            return self._remediate(work_dir, label, prompt, repo_dir)
        if stage == "sca":
            return self._sca(work_dir, label)
        if stage == "runtime":
            return self._runtime(work_dir, label)
        if stage == "live":
            return self._live(work_dir, label, prompt)
        if stage in {"corroborate", "corroborate_docs"}:
            return self._corroborate(work_dir, label, prompt)
        if stage == "verify":
            return self._verify(work_dir, label)
        if stage == "asan_poc":
            return self._asan_poc(work_dir, label)
        if stage == "validate":
            return self._validate(work_dir, label, prompt)
        handler = {
            "ingest": self._ingest,
            "recon": self._recon,
            "audit": self._audit,
        }.get(stage)
        if handler is None:
            raise RunnerError(f"MockClaudeRunner has no handler for stage {stage!r}")
        return handler(work_dir, label)

    # -- helpers ----------------------------------------------------------------------
    def _envelope(self, result_text: str, *, is_error: bool = False) -> dict:
        return {
            "type": "result",
            "subtype": "error" if is_error else "success",
            "is_error": is_error,
            "result": result_text,
            "session_id": "mock-session",
            "total_cost_usd": self.MOCK_COST,
            "usage": {"input_tokens": 0, "output_tokens": 0},
            "num_turns": 1,
        }

    @staticmethod
    def _manifest(artifacts: list[dict], status: str = "complete") -> str:
        return "```json\n" + json.dumps(
            {"artifacts": artifacts, "session_status": status}, indent=2
        ) + "\n```"

    def _copy(self, src: Path, dst: Path) -> None:
        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

    # -- stage handlers ---------------------------------------------------------------
    def _ingest(self, work_dir: Path, label) -> dict:
        self._copy(self.scenario_dir / "ingest" / "scope.json", work_dir / "scope.json")
        return self._envelope(self._manifest(
            [{"type": "scope", "path": "scope.json", "status": "ok"}]))

    def _recon(self, work_dir: Path, label) -> dict:
        recon_dir = self.scenario_dir / "recon"
        arts = []
        for src in sorted(recon_dir.glob("*")):
            if src.name.startswith("_") or not src.is_file():
                continue  # sentinels (e.g. _no_manifest) are control files, not artifacts
            self._copy(src, work_dir / src.name)
            kind = ("repo_profile" if src.name == "repo_profile.json"
                    else "audit_prompt" if src.suffix == ".md" and src.name.startswith("audit_")
                    else "synthesis_notes" if src.name == "synthesis_notes.md"
                    else "other")
            arts.append({"type": kind, "path": src.name, "status": "ok"})
        # Sentinel to test the missing-manifest -> scratch-glob fallback path.
        if (recon_dir / "_no_manifest").exists():
            return self._envelope("Recon complete. (manifest intentionally omitted)")
        return self._envelope(self._manifest(arts))

    def _audit(self, work_dir: Path, label) -> dict:
        slug = work_dir.name  # work/audit/<slug>  (a completeness-critic re-pass is "<slug>__critic")
        src = self.scenario_dir / "audit" / f"{slug}.findings.json"
        out = work_dir / f"SECURITY_FINDINGS__{slug}.json"
        if not src.is_file():
            # Completeness-critic re-pass (or unknown focus): no fixture -> emit an empty, valid
            # findings file so the critic dedup path is exercised and finds nothing new.
            base = slug.replace("__critic", "")
            out.write_text(json.dumps({
                "program_name": "mock", "audit_focus": base,
                "generated_at": "2026-01-01T00:00:00+00:00", "findings": []}, indent=2),
                encoding="utf-8")
            return self._envelope(self._manifest(
                [{"type": "findings", "path": out.name, "status": "ok"}]))
        partial_sentinel = self.scenario_dir / "audit" / f"{slug}._partial"
        if partial_sentinel.exists():
            # Simulate the streaming contract faithfully: checkpoint a prefix of the findings,
            # then die before the focus is complete and before a manifest is emitted.
            doc = json.loads(src.read_text(encoding="utf-8-sig"))
            findings = list(doc.get("findings", []))
            checkpointed = max(1, len(findings) // 2) if findings else 0
            doc["findings"] = findings[:checkpointed]
            out.write_text(json.dumps(doc, indent=2), encoding="utf-8")
            return self._envelope("Session interrupted.", is_error=True)
        self._copy(src, out)
        if (self.scenario_dir / "audit" / f"{slug}._no_manifest").exists():
            return self._envelope("Audit complete; manifest omitted.")
        return self._envelope(self._manifest(
            [{"type": "findings", "path": out.name, "status": "ok"}]))

    def _sca(self, work_dir: Path, label) -> dict:
        """Mock SCA: emit a dependencies findings file from a fixture if present, else empty."""
        out = work_dir / "SECURITY_FINDINGS__dependencies.json"
        src = self.scenario_dir / "sca" / "dependencies.findings.json"
        if src.is_file():
            self._copy(src, out)
        else:
            out.write_text(json.dumps({
                "program_name": "mock", "audit_focus": "dependencies",
                "generated_at": "2026-01-01T00:00:00+00:00", "findings": []}, indent=2),
                encoding="utf-8")
        return self._envelope(self._manifest(
            [{"type": "findings", "path": out.name, "status": "ok"}]))

    def _runtime(self, work_dir: Path, label) -> dict:
        """Mock R2 runtime sessions: 'propose' emits a probe plan, 'interpret' emits verdicts."""
        if "interpret" in (label or ""):
            out = work_dir / "runtime_verdicts.json"
            out.write_text(json.dumps({"verdicts": [
                {"finding_id": "MOCK-1", "runtime_verdict": "runtime_confirmed",
                 "evidence": "200 to anonymous caller", "rationale": "endpoint requires no auth"}]}),
                encoding="utf-8")
            return self._envelope(self._manifest(
                [{"type": "runtime_verdicts", "path": out.name, "status": "ok"}]))
        out = work_dir / "runtime_probe_plan.json"
        out.write_text(json.dumps([
            {"finding_id": "MOCK-1", "note": "mock probe",
             "requests": [{"method": "GET", "path": "/status", "expect": {"status": [200]}}]}]),
            encoding="utf-8")
        return self._envelope(self._manifest(
            [{"type": "probe_plan", "path": out.name, "status": "ok"}]))

    def _live(self, work_dir: Path, label, prompt: str) -> dict:
        """Mock L2 live sessions: 'propose' emits an in-scope absolute-URL probe plan (host parsed
        from the prompt's IN-SCOPE HOSTS list so it passes the scope-lock); 'interpret' emits verdicts."""
        if "interpret" in (label or ""):
            out = work_dir / "live_verdicts.json"
            out.write_text(json.dumps({"verdicts": [
                {"finding_id": "MOCK-1", "live_verdict": "live_confirmed",
                 "evidence": "200 to anonymous caller", "rationale": "endpoint requires no auth"}]}),
                encoding="utf-8")
            return self._envelope(self._manifest(
                [{"type": "live_verdicts", "path": out.name, "status": "ok"}]))
        raw = "example.com"
        if "IN-SCOPE HOSTS" in prompt:
            for line in prompt.split("IN-SCOPE HOSTS", 1)[1].splitlines():
                s = line.strip()
                if s.startswith("- "):
                    raw = s[2:].strip()
                    break
        scheme = "https"
        if "://" in raw:
            scheme, raw = raw.split("://", 1)
        host = raw.split("/", 1)[0]
        out = work_dir / "live_probe_plan.json"
        out.write_text(json.dumps([
            {"finding_id": "MOCK-1", "note": "mock live probe",
             "requests": [{"method": "GET", "url": f"{scheme}://{host}/status",
                           "expect": {"status": [200]}}]}]), encoding="utf-8")
        return self._envelope(self._manifest(
            [{"type": "probe_plan", "path": out.name, "status": "ok"}]))

    def _research(self, work_dir: Path, label) -> dict:
        """Mock Stage-1 web research: emit a research_brief.md + threat_intel.json (no real web)."""
        (work_dir / "threat_intel.json").write_text(json.dumps({
            "software": "(mock) target software",
            "stack": ["unknown"],
            "known_cves": [],
            "advisories": [],
            "risk_areas": ["input handling", "authn/authz"],
            "suspected_vuln_classes": ["injection", "access-control"],
            "references": [],
            "approach_notes": "Mock research: focus on untrusted-input sinks and authz boundaries.",
        }, indent=2), encoding="utf-8")
        (work_dir / "research_brief.md").write_text(
            "# Research brief (mock)\n\nNo real web access in mock mode. Prioritize untrusted-input "
            "handling and authorization boundaries.\n", encoding="utf-8")
        return self._envelope(self._manifest([
            {"type": "research_brief", "path": "research_brief.md", "status": "ok"},
            {"type": "threat_intel", "path": "threat_intel.json", "status": "ok"},
        ]))

    def _corroborate(self, work_dir: Path, label, prompt: str) -> dict:
        """Mock corroboration: emit a verdict per finding. A fixture
        ``<scenario>/corroborate/<finding_id>.json`` (if present) drives the verdict so tests can
        exercise design_accepted / fixed_upstream; otherwise default to ``corroborated``. Handles both
        the legacy per-finding session and the batched ``corroborations.json`` session."""
        def _corr_for(fid: str) -> dict:
            src = self.scenario_dir / "corroborate" / f"{fid}.json"
            if src.is_file():
                return json.loads(src.read_text(encoding="utf-8-sig"))
            return {"finding_id": fid, "verdict": "corroborated",
                    "rationale": "(mock) no contradicting docs or newer fixing commit found.",
                    "evidence_urls": [], "fix_commit": None, "doc_url": None, "adjusted_severity": None}

        if work_dir.name.startswith("batch-"):
            ids: list[str] = []
            for m in re.findall(r'"finding_id"\s*:\s*"([^"]+)"', prompt):
                if re.match(r"^[A-Za-z0-9][\w.#-]*$", m) and m not in ids:
                    ids.append(m)
            out = work_dir / "corroborations.json"
            out.write_text(json.dumps({"corroborations": [_corr_for(f) for f in ids]}, indent=2),
                           encoding="utf-8")
            return self._envelope(self._manifest(
                [{"type": "corroborations", "path": out.name, "status": "ok"}]))

        fid = label or "MOCK-1"
        out = work_dir / f"corroboration_{fid}.json"
        out.write_text(json.dumps(_corr_for(fid), indent=2), encoding="utf-8")
        return self._envelope(self._manifest(
            [{"type": "corroboration", "path": out.name, "status": "ok"}]))

    def _verify(self, work_dir: Path, label) -> dict:
        """Mock deep-verify: always a single-finding session (never batched). A fixture
        ``<scenario>/verify/<finding_id>.json`` (if present) drives the verdict so tests can
        exercise corrected/split/merged/refuted/inconclusive; otherwise default to
        ``reconfirmed`` with a canned re-derivation transcript.

        Sentinel ``<scenario>/verify/<finding_id>._fail_once``: fails ONLY the first attempt
        (``work_dir.name == finding_id``, i.e. no ``-retryN`` suffix) so tests can exercise
        deep_verify's retry-on-infra-failure path; retry attempts use a suffixed work_dir name
        and succeed normally."""
        fid = label or "MOCK-1"
        if work_dir.name == fid and (self.scenario_dir / "verify" / f"{fid}._fail_once").exists():
            return self._envelope("Session interrupted.", is_error=True)
        src = self.scenario_dir / "verify" / f"{fid}.json"
        if src.is_file():
            data = json.loads(src.read_text(encoding="utf-8-sig"))
        else:
            data = {"finding_id": fid, "verdict": "reconfirmed",
                    "rationale": "(mock) re-derivation matched the finding as written.",
                    "independent_derivation": "(mock) opened the cited file(s) and re-traced the "
                                             "flow; no discrepancy found.",
                    "related_finding_ids": []}
        out = work_dir / f"deep_verify_{fid}.json"
        out.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return self._envelope(self._manifest(
            [{"type": "deep_verify_verdict", "path": out.name, "status": "ok"}]))

    def _asan_poc(self, work_dir: Path, label) -> dict:
        """Mock ASan harness-authoring session: write harness.c (+ NOTES.md) for this finding. A
        fixture ``<scenario>/asan_poc/<finding_id>.c`` (if present) drives the harness source, so a
        Docker-gated test can exercise the REAL compile+run+parse cycle deterministically (e.g. a
        known one-liner heap-buffer-overflow); otherwise a trivial, safe (non-crashing) default
        keeps the plain mock path itself lightweight and Docker-independent."""
        fid = label or "MOCK-1"
        src = self.scenario_dir / "asan_poc" / f"{fid}.c"
        code = src.read_text(encoding="utf-8") if src.is_file() else (
            "#include <stdio.h>\n"
            "int main(void) { printf(\"mock asan_poc: no fixture, trivial safe harness\\n\"); "
            "return 0; }\n"
        )
        (work_dir / "harness.c").write_text(code, encoding="utf-8")
        (work_dir / "NOTES.md").write_text(
            "(mock) harness authored from a test fixture or the trivial safe default.\n",
            encoding="utf-8")
        return self._envelope(self._manifest([
            {"type": "harness_source", "path": "harness.c", "status": "ok"},
            {"type": "notes", "path": "NOTES.md", "status": "ok"},
        ]))

    def _remediate(self, work_dir: Path, label, prompt: str, repo_dir) -> dict:
        """Emit a `FIX.json` full-file rewrite (the primary remediation format): read the finding's
        primary file (READ-ONLY) and append a harmless remediation marker comment, so Argo's
        mechanical diff yields an applyable patch that keeps the target compiling — exercising the
        verify stage end-to-end at zero token cost."""
        target = ""
        if "Primary location:" in prompt:
            seg = prompt.split("Primary location:", 1)[1].strip()
            target = seg.splitlines()[0].split(":", 1)[0].strip()
        src = Path(repo_dir) / target if (repo_dir and target) else None
        if src and src.is_file():
            content = src.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
            if content and not content.endswith("\n"):
                content += "\n"
            comment = "# argo: remediation marker (mock fix)\n" if target.endswith(".py") \
                else "// argo: remediation marker (mock fix)\n"
            files = [{"path": target, "new_content": content + comment}]
        else:
            # no resolvable target — a new file (always applies, nothing to break)
            files = [{"path": "ARGO_FIX_NOTE.md",
                      "new_content": "Argo proposed-fix placeholder (mock).\n"}]
        (work_dir / "FIX.json").write_text(
            json.dumps({"summary": "mock remediation", "files": files}), encoding="utf-8")
        return self._envelope(
            "Mock remediation: wrote FIX.json (full-file rewrite; Argo computes the diff).\n\n"
            "Generated files: FIX.json")

    def _chat(self, work_dir: Path, label, prompt: str) -> dict:
        # Deterministic canned reply that echoes the user's question (for round-trip tests).
        user = ""
        if "=== USER MESSAGE ===" in prompt:
            seg = prompt.split("=== USER MESSAGE ===", 1)[1].strip()
            user = seg.splitlines()[0] if seg else ""
        reply = f"Mock analyst: regarding “{user[:90]}” — here is a concrete, evidence-based answer."
        u = user.lower()  # decide test-gen from the USER message, not the system prompt
        if "test" in u and ("generate" in u or "suite" in u or "cwe" in u):
            (work_dir / "test_generated_sample.py").write_text(
                "# generated by the chat analyst (mock)\n"
                "def test_placeholder():\n    assert True\n", encoding="utf-8")
            reply += "\n\nGenerated files: test_generated_sample.py"
        return self._envelope(reply)

    def _validate(self, work_dir: Path, label, prompt: str = "") -> dict:
        if work_dir.name == "semantic-dedup":
            # Optional fixture: validate/dedup_clusters.json, copied VERBATIM as the produced
            # artifact (like _audit's fixture copy) — a test can drop deliberately malformed JSON
            # in it to exercise the real code's fail-open parse-error path. Absent -> no-op
            # (findings unchanged), so existing scenarios never need one just because they happen
            # to cross the threshold.
            fixture = self.scenario_dir / "validate" / "dedup_clusters.json"
            out = work_dir / "dedup_clusters.json"
            if fixture.is_file():
                self._copy(fixture, out)
            else:
                out.write_text(json.dumps({"clusters": []}, indent=2), encoding="utf-8")
            return self._envelope(self._manifest(
                [{"type": "dedup_clusters", "path": out.name, "status": "ok"}]))

        verdicts = json.loads(
            (self.scenario_dir / "validate" / "verdicts.json").read_text(encoding="utf-8"))

        def _verdict_for(fid: str) -> dict:
            v = verdicts.get(fid, verdicts.get("_default"))
            if v is None:
                raise RunnerError(f"mock verdict fixture missing for {fid!r} and no _default")
            v = dict(v)
            v.setdefault("finding_id", fid)
            return v

        if work_dir.name.startswith("batch-"):   # batched validate: emit verdicts.json for all ids
            ids: list[str] = []
            for m in re.findall(r'"finding_id"\s*:\s*"([^"]+)"', prompt):
                if re.match(r"^[A-Za-z0-9][\w.#-]*$", m) and m not in ids:  # skip "..."/"<finding_id>"
                    ids.append(m)
            rows = [_verdict_for(fid) for fid in ids]
            out = work_dir / "verdicts.json"
            out.write_text(json.dumps({"verdicts": rows}, indent=2), encoding="utf-8")
            return self._envelope(self._manifest(
                [{"type": "verdicts", "path": out.name, "status": "ok"}]))

        finding_id = work_dir.name  # legacy per-finding path: work/validate/<finding_id>
        verdict = _verdict_for(finding_id)
        out = work_dir / f"verdict_{finding_id}.json"
        out.write_text(json.dumps(verdict, indent=2), encoding="utf-8")
        return self._envelope(self._manifest(
            [{"type": "verdict", "path": out.name, "status": "ok"}]))


#: Error-message hints that mark a session failure as RETRYABLE on another backend (vs a real
#: deterministic failure that should propagate). Matched case-insensitively against the RunnerError.
#: "quota" already matches Gemini's real observed 429 wording ("you exceeded your current quota",
#: confirmed live 2026-08-17); resource_exhausted/"resource has been exhausted" are documented
#: alternate Gemini API phrasings that just didn't happen to be the one that specific call produced.
_RETRYABLE_HINTS = ("session limit", "rate limit", "rate_limit", "api_error_status=429", " 429",
                    "overloaded", "quota", "too many requests", "insufficient_quota",
                    "resource_exhausted", "resource has been exhausted")


def _is_retryable(exc: Exception) -> bool:
    if isinstance(exc, GuardrailError):
        return False
    # Credential resolution happens before a model session exists. Its vendor diagnostics must
    # never enter the generic rate-limit text classifier and silently switch paying identities.
    if getattr(exc, "failure_kind", None) == "credential_bootstrap":
        return False
    if bool(getattr(exc, "retryable", False)):
        return True
    s = str(exc).lower()
    return any(h in s for h in _RETRYABLE_HINTS)


#: Codex's own moderation classifier's error text (confirmed live — see the
#: codex-moderation-cybersecurity-flag campaign notes): "ERROR: This content was flagged for
#: possible cybersecurity risk. If this seems wrong, try rephrasing your request. To get
#: authorized for security work, join the Trusted Access for Cyber program:
#: https://chatgpt.com/cyber". Matched on the stable substring (not the whole sentence) since
#: surrounding wording could shift; this phrase is the load-bearing part.
_MODERATION_FLAG_SIGNATURE = "flagged for possible cybersecurity risk"

#: Claude's OWN moderation-style refusal signature — confirmed live 2026-08-12 on a real
#: asan_poc harness-authoring session against nanomq's SCRAM bug (legitimate, authorized security
#: research, same as every other case in this file): "API Error: Opus 4.8's safeguards flagged
#: this message. Our intentionally broad safeguards allow us to deliver more capabilities faster,
#: but can sometimes flag legitimate cybersecurity work. Apply to the Cyber Verification Program
#: to reduce these interruptions." Matched on a substring that omits the model-version prefix
#: ("Opus 4.8" will change across releases) — this is the SAME category of failure as Codex's
#: moderation flag (a safety classifier refusing legitimate, authorized content), just on the
#: other backend, so it is classified identically and gets the same neutral-register recovery.
_CLAUDE_REFUSAL_SIGNATURE = "safeguards flagged this message"

#: Codex's credits-exhaustion signature, confirmed live via a manual `codex exec` smoke test (see
#: argo-run-pacing-limits campaign notes — recurred 3 times independently: libcsp, authentik's
#: verify stage, coturn). The STRUCTURAL fingerprint alone (stop_reason=exit_1, 0 tokens,
#: session_id=null) is NOT enough to tell this apart from an immediate moderation flag, which
#: produces the identical shape when it fires before any tool call ran — only the actual error
#: text differs, which is why this is a text match, not a code-path match.
_CREDITS_EXHAUSTED_SIGNATURE = "out of credits"


def _classify_failure_text(text: str | None) -> FailureKind | None:
    """Best-effort classification of a raw backend error/stderr string into a :data:`FailureKind`.

    Returns ``None`` (not ``"unknown_retryable"``) when nothing distinctive matched, so a caller
    can tell "checked, and nothing specific matched" from "never checked" and apply its own
    default rather than this function silently picking one.
    """
    s = (text or "").lower()
    if (_MODERATION_FLAG_SIGNATURE in s or _CLAUDE_REFUSAL_SIGNATURE in s
            or _GEMINI_MODERATION_MARKER in s):
        return "moderation_flagged"
    if _CREDITS_EXHAUSTED_SIGNATURE in s:
        return "credits_exhausted"
    if any(h in s for h in _RETRYABLE_HINTS):
        return "rate_limited"
    return None


#: A session-limit error's detail text often carries a human-readable reset time (e.g. "You've hit
#: your session limit · resets 12:50am (Europe/Rome)"). Extracting it means a human (or a future
#: resume script) can `grep` a run log for exactly when it is safe to retry, instead of having to
#: hunt down and re-read the raw API error text. Best-effort: no match -> None, never raises.
_SESSION_RESET_RE = re.compile(r"resets?\s+([^·|\n\"]{3,40})", re.IGNORECASE)


def _extract_session_reset_hint(text: str | None) -> str | None:
    if not text:
        return None
    m = _SESSION_RESET_RE.search(text)
    return m.group(1).strip().rstrip(".,;") if m else None


_TIME_HINT_RE = re.compile(
    r"^\s*(?P<hour>\d{1,2})(?::(?P<minute>\d{2}))?\s*(?P<ampm>am|pm)?"
    r"(?:\s*\((?P<tz>[^)]+)\))?\s*$",
    re.IGNORECASE,
)


def parse_retry_after(value: str | None, *, now: datetime | None = None) -> datetime | None:
    """Best-effort conversion of a reset hint into a future aware datetime.

    Supports ISO timestamps and Claude's common human hints such as ``5pm`` or
    ``12:50am (Europe/Rome)``. If a time-only hint has already passed today, tomorrow is used.
    """
    if not value:
        return None
    text = value.strip()
    now = now or datetime.now(timezone.utc).astimezone()
    try:
        iso = text[:-1] + "+00:00" if text.endswith("Z") else text
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=now.tzinfo)
        return dt
    except ValueError:
        pass

    m = _TIME_HINT_RE.match(text)
    if not m:
        return None
    tzinfo = now.tzinfo
    tz_name = (m.group("tz") or "").strip()
    if tz_name:
        try:
            tzinfo = ZoneInfo(tz_name)
        except (ZoneInfoNotFoundError, ValueError):
            # ZoneInfo raises plain ValueError (not ZoneInfoNotFoundError) for a malformed key
            # (path-traversal-shaped, embedded NUL, ...) — this is a best-effort parse of
            # free-text error output, never worth crashing the fallback chain over.
            tzinfo = now.tzinfo
    hour = int(m.group("hour"))
    minute = int(m.group("minute") or 0)
    ampm = (m.group("ampm") or "").lower()
    if ampm:
        if hour < 1 or hour > 12:
            return None
        hour = hour % 12
        if ampm == "pm":
            hour += 12
    if hour > 23 or minute > 59:
        return None
    base = now.astimezone(tzinfo)
    dt = base.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if dt <= base:
        dt += timedelta(days=1)
    return dt


#: When a retryable error carries NO parseable reset hint (Codex's exit_1/0-token crash signature
#: never includes one; only Claude's "session limit ... resets HH:MM" messages do), disable the
#: backend for this bounded cooldown instead of for the rest of the run. Empirically (this
#: campaign's own operational history) a hint-less Codex failure is more often a transient sandbox
#: flake than genuine credit exhaustion -- permanently benching it on the first hiccup cascades
#: everything onto the fallback backend, exhausting ITS real quota instead. If it genuinely IS
#: exhausted, the wasted retries are near-free (0 tokens, sub-second exit_1). This is now the
#: FALLBACK duration for a failure whose kind isn't one of the specifically-tuned entries in
#: `_COOLDOWN_BY_FAILURE_KIND` below.
_NO_HINT_RETRY_COOLDOWN = timedelta(minutes=5)

#: Per-FailureKind cooldown before a disabled backend is reconsidered, when the error carried no
#: parseable reset hint of its own. Deliberately NOT one flat duration for every retryable failure:
#: - `credits_exhausted`: won't resolve itself no matter how long you wait short of a human topping
#:   the account up. Retrying every 5 minutes against a genuinely empty account wastes nothing
#:   (near-zero tokens, sub-second exit) but also accomplishes nothing -- a longer cooldown lets the
#:   run spend that time productively on a DIFFERENT backend instead of re-checking a dead one.
#:   Still bounded, not permanent: a false-positive text match, or a mid-run top-up, shouldn't
#:   permanently bench an otherwise-working backend for the rest of a long run.
#: - `moderation_flagged`: reflects the "short-lived account/session-level cooldown" hypothesis
#:   from this campaign's operational history (immediate back-to-back retries of the identical
#:   prompt flagged on every attempt even when a spaced-out one-off call with the SAME prompt
#:   succeeded). Duration is a reasoned starting point, not a measured constant -- validate before
#:   relying on it for anything time-critical.
#: Any FailureKind not listed here (including a plain `None`) falls back to `_NO_HINT_RETRY_COOLDOWN`.
_COOLDOWN_BY_FAILURE_KIND: dict[str, timedelta] = {
    "credits_exhausted": timedelta(minutes=30),
    "moderation_flagged": timedelta(minutes=10),
    # the account/profile cannot serve this model at all: benched for the rest of the run
    "model_unavailable": timedelta(days=7),
}

#: Before advancing to the NEXT backend in the chain after a moderation-flagged failure, sleep this
#: long IF (and only if) the next backend is the same underlying provider (`config.runner`) as the
#: one that just failed -- e.g. a `runner_fallbacks=["codex","codex"]` chain retrying on a second
#: Codex account/instance. A genuinely different backend (codex -> headless) doesn't share the
#: classifier that flagged, so there is nothing to wait out and the fallback still fires
#: immediately. This is the direct fix for the observed failure mode: firing the next attempt with
#: zero delay, even on a nominally "different" chain entry, does not escape the cooldown when it's
#: really the same classifier being hit again. Untested exact duration -- a reasoned starting point
#: pending real validation, not a measured constant.
_MODERATION_RETRY_DELAY = timedelta(seconds=90)

#: Delay before AgentRunner.run()'s own same-backend, same-call retry with a caller-supplied
#: neutral-register ``neutral_prompt`` (see run()). Deliberately much shorter than
#: `_MODERATION_RETRY_DELAY`: that 90s figure exists because identical back-to-back retries of
#: the SAME prompt kept flagging on every attempt -- a neutrally-worded prompt is a materially
#: different input to the classifier, so the same "let the classifier cool down" justification
#: doesn't apply at full strength. A short pause is still cheap insurance against anything
#: session/account-level rather than purely content-based. Untested exact duration -- a reasoned
#: starting point, not a measured constant, same as the other timing constants in this module.
_NEUTRAL_RETRY_DELAY_S = 5.0


class FallbackRunner(AgentRunner):
    """Chains backends for resilience: on a RETRYABLE limit (session/rate-limit/429) the SAME call is
    retried on the next backend (e.g. Claude -> Codex -> local). The model is recomputed per backend
    (each child has its own config), and a backend that hits its limit is disabled (circuit breaker)
    so we don't re-hit the wall on every subsequent call -- until its reset hint (if the error
    carried one) or a bounded cooldown (`_NO_HINT_RETRY_COOLDOWN`, if it didn't). A non-retryable
    error propagates immediately."""

    def __init__(self, config: PipelineConfig, ledger: Ledger, runners: list[AgentRunner]):
        self._runners = runners                       # primary first; set BEFORE super().__init__
        self._disabled: dict[int, datetime | None] = {}
        self._fb_lock = threading.Lock()
        super().__init__(config, ledger)

    @property                                         # propagate the orchestrator's cancel_event
    def cancel_event(self):
        return self._runners[0].cancel_event if self._runners else None

    @cancel_event.setter
    def cancel_event(self, ev):
        for r in getattr(self, "_runners", []):
            r.cancel_event = ev

    @property                                         # and the chat UI's live-activity sink
    def on_activity(self):
        return self._runners[0].on_activity if self._runners else None

    @on_activity.setter
    def on_activity(self, sink):
        for r in getattr(self, "_runners", []):
            r.on_activity = sink

    def run(self, **kwargs) -> LLMResult:
        last_exc: Exception | None = None
        stage = kwargs.get("stage")
        attempts = 0
        for i, r in enumerate(self._runners):
            with self._fb_lock:
                disabled_until = self._disabled.get(i)
                if i in self._disabled:
                    if disabled_until is None:
                        continue
                    if datetime.now(timezone.utc) <= disabled_until.astimezone(timezone.utc):
                        continue
                    del self._disabled[i]
            kw = dict(kwargs)
            if stage is not None:                     # each backend picks its own model for the stage
                kw["model"] = r.config.model_for(stage)
            if attempts:
                _set_aside_work_dir(kw.get("work_dir"), attempts)
            attempts += 1
            try:
                return r.run(**kw)
            except RunnerError as exc:
                last_exc = exc
                if not _is_retryable(exc):
                    raise
                failure_kind = getattr(exc, "failure_kind", None)
                cooldown = _COOLDOWN_BY_FAILURE_KIND.get(failure_kind, _NO_HINT_RETRY_COOLDOWN)
                retry_at = parse_retry_after(getattr(exc, "retry_after", None))
                bounded = retry_at is None    # no reset hint in the error -> bounded cooldown, not forever
                if bounded:
                    retry_at = datetime.now(timezone.utc) + cooldown
                with self._fb_lock:
                    self._disabled[i] = retry_at
                if i + 1 < len(self._runners):
                    next_r = self._runners[i + 1]
                    reset = (f" for {cooldown} (no reset hint)" if bounded
                             else f" until {retry_at.isoformat()}")
                    # A moderation flag and the next chain entry is the SAME backend provider (e.g.
                    # a runner_fallbacks=["codex","codex"] chain): firing immediately does not
                    # escape a short-lived classifier cooldown (observed: back-to-back retries all
                    # flagged even when a spaced-out one-off call succeeded). A genuinely different
                    # backend shares no such cooldown, so it still fires immediately. Sleep OUTSIDE
                    # the lock -- other threads sharing this FallbackRunner must keep making
                    # progress on their own calls while this one waits.
                    if failure_kind == "moderation_flagged" and next_r.config.runner == r.config.runner:
                        delay_s = _MODERATION_RETRY_DELAY.total_seconds()
                        print(f"[runner] backend #{i} ({r.config.runner}) was moderation-flagged; "
                              f"waiting {delay_s:.0f}s before retrying the same backend type on "
                              f"#{i + 1}{reset}", file=sys.stderr)
                        time.sleep(delay_s)
                    else:
                        print(f"[runner] backend #{i} ({r.config.runner}) hit a retryable limit "
                              f"({failure_kind or 'unspecified'}); falling back to #{i + 1} "
                              f"({next_r.config.runner}){reset}", file=sys.stderr)
        raise last_exc if last_exc else RunnerError("all fallback backends exhausted")

    def _invoke(self, **kwargs):                      # never used — run() delegates whole calls
        raise NotImplementedError("FallbackRunner delegates whole run() calls to child runners")


def _set_aside_work_dir(work_dir, attempt: int) -> None:
    """Before a fallback backend reuses a session's scratch dir, move the failed attempt's files
    to a sibling ``<dir>.failed-<n>``: stages glob the scratch dir, so a stale partial artifact
    would otherwise be collected alongside (or instead of) the next backend's output. Kept on
    disk for diagnosis. Best-effort: if the rename fails, the dir is left as it was."""
    if work_dir is None:
        return
    wd = Path(work_dir)
    try:
        if not wd.is_dir() or not any(wd.iterdir()):
            return
        target = wd.with_name(f"{wd.name}.failed-{attempt}")
        n = attempt
        while target.exists():
            n += 1
            target = wd.with_name(f"{wd.name}.failed-{n}")
        wd.rename(target)
        wd.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass


def _build_one(config: PipelineConfig, ledger: Ledger, name: str) -> AgentRunner:
    cfg = config if config.runner == name else config.with_overrides(runner=name)
    if name == "mock":
        return MockClaudeRunner(cfg, ledger)
    if name == "headless":
        return HeadlessClaudeRunner(cfg, ledger)
    if name == "codex":
        return CodexRunner(cfg, ledger)
    if name == "gemini":
        return GeminiRunner(cfg, ledger)
    if name == "mistral-api":
        from .mistral_api import MistralApiRunner     # lazy: keeps httpx off the import path
        return MistralApiRunner(cfg, ledger)
    if name == "mistral-vibe":
        from .mistral_vibe import MistralVibeRunner
        return MistralVibeRunner(cfg, ledger)
    raise ValueError(f"unknown runner {name!r} (expected 'headless', 'codex', 'gemini', 'mistral-api', 'mistral-vibe', or 'mock')")


def _label_runner(runner: AgentRunner, backend: str, account: str, index: int) -> AgentRunner:
    """Attach an indexed, non-secret account label to one expanded fallback runner."""
    component = "api-key" if account == "<api-key>" else _safe_account_component(account)
    runner.account_label = f"{backend}:{component}[{index + 1}]"
    return runner


def _dedupe_preserving_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _expand_codex_model_chain(config: PipelineConfig, ledger: Ledger, name: str) -> list[AgentRunner]:
    """Codex de-escalation chain: one runner per (model, credential-slot), models strongest first
    (outer loop) so the strong model is exhausted across every account before a tier is dropped;
    runner_fallbacks backends follow afterwards (see build_runner). Each runner carries a flat
    codex_model, so FallbackRunner.run()'s per-entry model_for() picks the tier for that entry.
    Credential slots mirror the non-chain codex branches of _expand_backend. Invalid (account,
    model) pairs (e.g. a daybreak account that does not serve a strong model) are NOT pruned here:
    they surface at call time as a non-terminal model_unavailable that simply advances the chain."""
    models = _dedupe_preserving_order([m.strip() for m in config.codex_model_chain if m and m.strip()])
    if config.codex_accounts:
        slots = [(d, dict(codex_home=d, codex_api_key=None, codex_api_keys=[]))
                 for d in config.codex_accounts]
    elif config.codex_api_keys:
        slots = [("<api-key>", dict(codex_home=None, codex_api_key=k))
                 for k in config.codex_api_keys]
    else:
        slots = [(config.codex_home, dict(codex_api_key=None, codex_api_keys=[]))]
    runners: list[AgentRunner] = []
    index = 0
    for model in models:
        for account, overrides in slots:
            runner = CodexRunner(config.with_overrides(
                runner=name, codex_model=model, codex_stage_models={}, **overrides), ledger)
            component = "api-key" if account == "<api-key>" else _safe_account_component(account)
            runner.account_label = f"{name}:{component}@{model}[{index + 1}]"
            runners.append(runner)
            index += 1
    return runners


def _expand_backend(config: PipelineConfig, ledger: Ledger, name: str) -> list[AgentRunner]:
    """One backend name -> one or more runners. Multi-account backends expand to one runner per
    credential dir (limits are per-account): Claude via CLAUDE_CONFIG_DIR, Codex via CODEX_HOME,
    Gemini via a GEMINI_API_KEY value (a real secret, not a directory path — see PipelineConfig).
    claude_api_keys/codex_api_keys are a SEPARATE, key-based chaining mechanism (mirrors
    gemini_accounts) -- directory-based *_accounts wins if both are configured for the same
    backend (avoids a Cartesian-product chain nobody asked for; consistent with the single-value
    codex_home-wins-over-codex_api_key precedence in CodexRunner._codex_home_env_value)."""
    if name == "headless" and config.claude_accounts:
        return [_label_runner(HeadlessClaudeRunner(config.with_overrides(
                    runner=name, claude_config_dir=d, claude_api_key=None, claude_api_keys=[]), ledger),
                    name, d, i) for i, d in enumerate(config.claude_accounts)]
    if name == "headless" and config.claude_api_keys:
        return [_label_runner(HeadlessClaudeRunner(config.with_overrides(
                    runner=name, claude_config_dir=None, claude_api_key=k), ledger),
                    name, "<api-key>", i) for i, k in enumerate(config.claude_api_keys)]
    if name == "codex" and config.codex_model_chain:
        return _expand_codex_model_chain(config, ledger, name)
    if name == "codex" and config.codex_accounts:
        return [_label_runner(CodexRunner(config.with_overrides(
                    runner=name, codex_home=d, codex_api_key=None, codex_api_keys=[]), ledger),
                    name, d, i) for i, d in enumerate(config.codex_accounts)]
    if name == "codex" and config.codex_home:
        return [CodexRunner(config.with_overrides(
                    runner=name, codex_api_key=None, codex_api_keys=[]), ledger)]
    if name == "codex" and config.codex_api_keys:
        return [_label_runner(CodexRunner(config.with_overrides(
                    runner=name, codex_home=None, codex_api_key=k), ledger),
                    name, "<api-key>", i) for i, k in enumerate(config.codex_api_keys)]
    if name == "gemini" and config.gemini_accounts:
        return [_label_runner(GeminiRunner(config.with_overrides(
                    runner=name, gemini_api_key=k), ledger),
                    name, "<api-key>", i) for i, k in enumerate(config.gemini_accounts)]
    return [_build_one(config, ledger, name)]


def build_runner(config: PipelineConfig, ledger: Ledger) -> AgentRunner:
    chain = _expand_backend(config, ledger, config.runner)
    for n in config.runner_fallbacks:
        chain += _expand_backend(config, ledger, n)
    return chain[0] if len(chain) == 1 else FallbackRunner(config, ledger, chain)
