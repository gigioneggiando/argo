"""ClaudeRunner abstraction + two implementations.

The runner is the single chokepoint for every LLM invocation, so it is where tool guardrails
and cost logging are enforced — a buggy stage cannot bypass them.

  * :class:`HeadlessClaudeRunner` shells out to ``claude -p`` (Claude Code headless). The repo
    is mounted READ-ONLY via ``--add-dir`` (a no-internet sandbox); the session cwd is a
    separate WRITABLE scratch dir so stray writes never land in the repo; network/mutation
    tools are hard-blocked via ``--disallowedTools``.
  * :class:`MockClaudeRunner` writes fixture files into the scratch dir and returns a
    synthetic manifest — full-glue testing with zero token spend.

Swap implementations behind the :class:`ClaudeRunner` interface (BUILD_SPEC: "Make the runner
an interface so it can be swapped").
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .config import ARTIFACT_TOOLS, PipelineConfig, estimate_cost_usd
from .guardrails import assert_no_network_tools, enforce_session_tools, session_policy
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


class RunnerError(RuntimeError):
    def __init__(self, message: str, *, retry_after: str | None = None,
                 retryable: bool = False, failure_kind: FailureKind | None = None):
        super().__init__(message)
        self.retry_after = retry_after
        self.retryable = retryable
        self.failure_kind = failure_kind


class RunnerCancelled(RuntimeError):
    """The session's process was killed because the run was cancelled mid-stage. Deliberately NOT
    a :class:`RunnerError`, so stage-level ``except RunnerError`` partial-recovery does not swallow
    it — it propagates to the orchestrator, which marks the run cancelled."""


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
    )


class AgentRunner(ABC):
    """Backend-neutral base: derives the session policy, applies guardrails, logs every call, then
    delegates to ``_invoke`` (per-backend launch) and ``parse_envelope`` (per-backend result).
    Subclasses: :class:`HeadlessClaudeRunner` (Claude Code), :class:`CodexRunner` (Codex CLI /
    OpenAI / OSS), :class:`MockClaudeRunner` (fixtures)."""

    def __init__(self, config: PipelineConfig, ledger: Ledger):
        self.config = config
        self.ledger = ledger
        # Set by the orchestrator for the duration of a run; when it fires, an in-flight CLI
        # subprocess is killed (mid-stage cancellation). None => not cancellable (e.g. CLI runs).
        self.cancel_event = None

    # ---------------------------------------------------------------- cancellable subprocess
    def _exec(self, cmd: list[str], *, prompt: str, cwd, timeout: float,
              env: dict | None = None) -> subprocess.CompletedProcess:
        """Run a backend CLI as a **cancellable** subprocess: if ``self.cancel_event`` fires (the
        user hit Cancel mid-stage) or the timeout elapses, kill the whole process **tree** and raise.

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

        def _pump():
            try:
                box["out"], box["err"] = proc.communicate(input=prompt)
            except Exception as exc:               # pragma: no cover - defensive
                box["exc"] = exc

        th = threading.Thread(target=_pump, daemon=True)
        th.start()
        ev = self.cancel_event
        deadline = time.monotonic() + timeout
        while th.is_alive():
            th.join(0.2)
            if ev is not None and ev.is_set():
                self._kill_tree(proc); th.join(5)
                raise RunnerCancelled("session cancelled mid-stage")
            if time.monotonic() > deadline:
                self._kill_tree(proc); th.join(5)
                raise subprocess.TimeoutExpired(cmd, timeout)
        if "exc" in box:                           # pragma: no cover - defensive
            raise box["exc"]
        return subprocess.CompletedProcess(cmd, proc.returncode, box.get("out", ""),
                                           box.get("err", ""))

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

        work_dir.mkdir(parents=True, exist_ok=True)
        prompt_sha = sha256_text(prompt)

        started = time.monotonic()
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
            failure_kind = _classify_failure_text(classify_text)
            if failure_kind is None and result.api_error_status and "429" in str(result.api_error_status):
                failure_kind = "rate_limited"

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
        )
        self._append_jsonl(run_dir, {
            "stage": stage,
            "label": label,
            "model": model,
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
        })

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
                retryable=True,
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
                   session_budget_usd=None) -> list[str]:
        cmd = [
            self._bin(),
            "-p",
            "--output-format", "json",      # metadata only (session id, cost, stop reason)
            "--model", model,
            # bypassPermissions avoids interactive prompts that would hang a headless run;
            # --disallowedTools still HARD-BLOCKS network/mutation tools, and --add-dir gives
            # a no-internet sandbox, so the blast radius is the scratch dir only.
            "--permission-mode", "bypassPermissions",
        ]
        # Native mid-session cost kill (v2.1.178 has --max-budget-usd; it has NO --max-turns).
        if session_budget_usd is not None:
            cmd += ["--max-budget-usd", f"{session_budget_usd:.4f}"]
        if repo_dir is not None:
            cmd += ["--add-dir", str(Path(repo_dir).resolve())]
        if allowed:
            cmd += ["--allowedTools", *allowed]
        if disallowed:
            cmd += ["--disallowedTools", *disallowed]
        return cmd

    def _invoke(self, *, prompt, work_dir, model, repo_dir, allowed, disallowed, policy=None,
                stage, run_id, label, session_budget_usd=None, timeout_s=None) -> dict:
        cmd = self._build_cmd(model=model, repo_dir=repo_dir, allowed=allowed,
                              disallowed=disallowed, session_budget_usd=session_budget_usd)
        timeout = timeout_s or self.config.session_timeout_s
        # Multi-account: point this invocation at a specific Claude credential store so an
        # account-fallback can switch accounts (limits are per-account). See build_runner.
        env = None
        if self.config.claude_config_dir:
            # Normalize to a native absolute path (expanduser handles ~; a bash-style /c/.. path
            # the launched CLI cannot resolve is made absolute). Pass via CLAUDE_CONFIG_DIR.
            cfg_dir = os.path.abspath(os.path.expanduser(str(self.config.claude_config_dir)))
            env = {**os.environ, "CLAUDE_CONFIG_DIR": cfg_dir}
        try:
            proc = self._exec(cmd, prompt=prompt, cwd=work_dir, timeout=timeout, env=env)
        except subprocess.TimeoutExpired as exc:  # pragma: no cover - real-runner path
            raise RunnerError(
                f"claude session timed out after {timeout}s "
                f"(stage={stage}, run_id={run_id}, label={label}); the scratch dir may hold "
                "partial artifacts but no metadata envelope was returned"
            ) from exc

        # A result envelope may arrive WITH a non-zero exit (e.g. is_error / budget-exceeded);
        # prefer parsing stdout, and only fall back to a hard error if there is no usable JSON.
        out = (proc.stdout or "").strip()
        if out:
            try:
                envelope = json.loads(out)
            except json.JSONDecodeError:
                envelope = None
            if isinstance(envelope, dict):
                return envelope  # base run() validates shape + classifies is_error/api errors

        raise RunnerError(
            f"claude produced no parseable JSON envelope (stage={stage}, run_id={run_id}, "
            f"label={label}, exit={proc.returncode}). This usually means an auth/startup "
            f"failure.\nstderr tail:\n{(proc.stderr or '')[-1500:]}\n"
            f"stdout tail:\n{out[-500:]}")


# -------------------------------------------------------------------------------- codex
#: TOML config path that re-enables network egress inside the workspace-write sandbox. Used ONLY
#: for the research stage; isolated as a constant so a Codex-version key change is a one-line fix.
_CODEX_NETWORK_CFG = "sandbox_workspace_write.network_access=true"


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

    def _bin(self) -> str:
        if self._resolved_bin is None:
            resolved = shutil.which(self.codex_bin)
            if not resolved:
                raise RunnerError(f"codex CLI not found on PATH (looked for {self.codex_bin!r}); "
                                  "install the Codex CLI or use --runner headless/mock")
            self._resolved_bin = resolved
        return self._resolved_bin

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
        if policy is not None and policy.network:   # ONLY the research stage gets network egress
            cmd += ["-c", _CODEX_NETWORK_CFG]
        cmd.append("-")                         # read the prompt (instructions) from stdin
        return cmd

    def _invoke(self, *, prompt, work_dir, model, repo_dir, allowed, disallowed, policy=None,
                stage, run_id, label, session_budget_usd=None, timeout_s=None) -> dict:
        last_msg = Path(work_dir) / ".codex_last_message.txt"
        cmd = self._build_codex_cmd(model=model, policy=policy, last_msg_file=last_msg)
        timeout = timeout_s or self.config.session_timeout_s
        # Multi-account: point this invocation at a specific Codex config home (CODEX_HOME) so an
        # account-fallback can switch Codex accounts (limits are per-account). See build_runner.
        env = None
        if self.config.codex_home:
            env = {**os.environ,
                   "CODEX_HOME": os.path.abspath(os.path.expanduser(str(self.config.codex_home)))}
        try:
            proc = self._exec(cmd, prompt=prompt, cwd=work_dir, timeout=timeout, env=env)
        except subprocess.TimeoutExpired as exc:  # pragma: no cover - real-runner path
            # A genuine hang-then-kill is not a deterministic failure -- the same call could well
            # succeed on a retry (this backend again, after a cooldown, or a fallback). Previously
            # NOT marked retryable, so a single hang killed the whole run with no fallback attempt.
            raise RunnerError(
                f"codex session timed out after {timeout}s (stage={stage}, "
                f"run_id={run_id}, label={label})",
                retryable=True, failure_kind="timeout") from exc
        text = last_msg.read_text(encoding="utf-8", errors="replace") if last_msg.exists() else ""
        if proc.returncode != 0 and not text and not (proc.stdout or "").strip():
            # "No output at all" is the exact shape of BOTH an immediate moderation flag (fires
            # before any tool call ran) and credits exhaustion (every call after the account runs
            # dry exits instantly, 0 tokens) -- the two are structurally identical here and only
            # distinguishable by the actual stderr text. Classify it either way. Previously this
            # path was NOT marked retryable at all, so Argo never even tried a configured fallback
            # backend on exactly the failure shape fallback exists for -- fixed: always retryable,
            # a wasted retry here costs ~0 tokens and sub-second wall clock either way.
            kind = _classify_failure_text(proc.stderr) or "unknown_retryable"
            raise RunnerError(
                f"codex produced no output (stage={stage}, run_id={run_id}, label={label}, "
                f"exit={proc.returncode}); likely auth/startup failure.\nstderr tail:\n"
                f"{(proc.stderr or '')[-1500:]}",
                retryable=True, failure_kind=kind)
        return {"_backend": "codex", "returncode": proc.returncode, "text": text,
                "stdout": proc.stdout or "", "stderr": (proc.stderr or "")[-2000:]}

    def parse_envelope(self, raw: dict, *, model: str, prompt_sha256: str,
                       work_dir: Path) -> LLMResult:
        rc = int(raw.get("returncode", 0) or 0)
        text = raw.get("text") or ""
        in_tok, out_tok = _scan_codex_tokens(raw.get("stdout", ""))
        return LLMResult(
            text=text, model=model, prompt_sha256=prompt_sha256, work_dir=work_dir,
            input_tokens=in_tok, output_tokens=out_tok,
            cost_usd=estimate_cost_usd(model, in_tok, out_tok),   # estimated (token-based)
            num_turns=0, session_id=None, stop_reason=f"exit_{rc}",
            is_error=(rc != 0),   # non-zero -> recoverable (the stage globs scratch for partials)
            api_error_status=None, raw=raw,
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
        Argo stage's session needs to Write its artifact, mirroring Claude's bypassPermissions /
        Codex's non-interactive exec.
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

    def _build_gemini_cmd(self, *, model, repo_dir, policy_file: Path) -> list[str]:
        cmd = [
            self._bin(),
            "--output-format", "json",
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
        cmd = self._build_gemini_cmd(model=model, repo_dir=repo_dir, policy_file=policy_file)
        timeout = timeout_s or self.config.session_timeout_s
        # Multi-account: point this invocation at a specific Gemini API key so an account-fallback
        # can switch keys (limits are per-key/project). See build_runner / _expand_backend. Unlike
        # Claude/Codex's directory-based env vars, this is a real secret value, not a path.
        env = None
        if self.config.gemini_api_key:
            env = {**os.environ, "GEMINI_API_KEY": self.config.gemini_api_key}
        try:
            proc = self._exec(cmd, prompt=prompt, cwd=work_dir, timeout=timeout, env=env)
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
        for entry in ((raw.get("stats") or {}).get("models") or {}).values():
            tok = (entry or {}).get("tokens") or {}
            # "prompt" (total context, incl. cached) not "input" (cached-excluded) — a deliberate
            # safe-direction overestimate when caching is active, matching the same rounding
            # rationale already documented for MODEL_PRICING's >200k-token Pro tier gap.
            in_tok += int(tok.get("prompt", tok.get("input", 0)) or 0)
            out_tok += int(tok.get("candidates", 0) or 0)

        return LLMResult(
            text=text, model=model, prompt_sha256=prompt_sha256, work_dir=work_dir,
            input_tokens=in_tok, output_tokens=out_tok,
            cost_usd=estimate_cost_usd(model, in_tok, out_tok),   # estimated (token-based)
            num_turns=0, session_id=raw.get("session_id"),
            stop_reason=f"exit_{raw.get('_exit_code', 0)}",
            is_error=is_error, api_error_status=None, raw=raw,
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
        if stage == "corroborate":
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
        self._copy(src, out)
        # Sentinel: simulate a session that died mid-write (no manifest, partial-ish file).
        if (self.scenario_dir / "audit" / f"{slug}._partial").exists():
            return self._envelope("Session interrupted.", is_error=True)
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
        """Mock Stage-0 web research: emit a research_brief.md + threat_intel.json (no real web)."""
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

    def run(self, **kwargs) -> LLMResult:
        last_exc: Exception | None = None
        stage = kwargs.get("stage")
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
    raise ValueError(f"unknown runner {name!r} (expected 'headless', 'codex', 'gemini', or 'mock')")


def _expand_backend(config: PipelineConfig, ledger: Ledger, name: str) -> list[AgentRunner]:
    """One backend name -> one or more runners. Multi-account backends expand to one runner per
    credential dir (limits are per-account): Claude via CLAUDE_CONFIG_DIR, Codex via CODEX_HOME,
    Gemini via a GEMINI_API_KEY value (a real secret, not a directory path — see PipelineConfig)."""
    if name == "headless" and config.claude_accounts:
        return [HeadlessClaudeRunner(config.with_overrides(runner=name, claude_config_dir=d), ledger)
                for d in config.claude_accounts]
    if name == "codex" and config.codex_accounts:
        return [CodexRunner(config.with_overrides(runner=name, codex_home=d), ledger)
                for d in config.codex_accounts]
    if name == "gemini" and config.gemini_accounts:
        return [GeminiRunner(config.with_overrides(runner=name, gemini_api_key=k), ledger)
                for k in config.gemini_accounts]
    return [_build_one(config, ledger, name)]


def build_runner(config: PipelineConfig, ledger: Ledger) -> AgentRunner:
    chain = _expand_backend(config, ledger, config.runner)
    for n in config.runner_fallbacks:
        chain += _expand_backend(config, ledger, n)
    return chain[0] if len(chain) == 1 else FallbackRunner(config, ledger, chain)
