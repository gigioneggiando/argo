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
import shutil
import signal
import subprocess
import sys
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

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


class RunnerError(RuntimeError):
    pass


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

        # Per-backend parse into the common LLMResult (Claude-strict by default; Codex overrides).
        result = self.parse_envelope(raw, model=model, prompt_sha256=prompt_sha,
                                     work_dir=work_dir)

        # --- cost logging (ledger + per-run JSONL) — ALWAYS, even on error -------------
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
        })

        # --- surface hard API errors LOUDLY (auth / rate-limit / overloaded) -----------
        # These carry api_error_status and cannot produce usable artifacts -> abort clearly.
        if result.is_error and result.api_error_status:
            raise RunnerError(
                f"claude session API error (stage={stage}, run_id={run_id}, label={label}): "
                f"api_error_status={result.api_error_status!r}, stop_reason="
                f"{result.stop_reason!r}, detail={result.text[:300]!r}")

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

        # Recoverable error (no api_error_status, e.g. budget/turn limit reached mid-write):
        # return it so the stage can glob the scratch dir for partial artifacts.
        if result.is_error:
            print(f"[runner] WARNING recoverable is_error session "
                  f"(stage={stage}, run_id={run_id}, label={label}, "
                  f"stop_reason={result.stop_reason!r}) — attempting partial recovery",
                  file=sys.stderr)
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
            raise RunnerError(f"codex session timed out after {timeout}s (stage={stage}, "
                              f"run_id={run_id}, label={label})") from exc
        text = last_msg.read_text(encoding="utf-8", errors="replace") if last_msg.exists() else ""
        if proc.returncode != 0 and not text and not (proc.stdout or "").strip():
            raise RunnerError(  # clear startup/auth failure — fail loudly, don't log a silent call
                f"codex produced no output (stage={stage}, run_id={run_id}, label={label}, "
                f"exit={proc.returncode}); likely auth/startup failure.\nstderr tail:\n"
                f"{(proc.stderr or '')[-1500:]}")
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
        handler = {
            "ingest": self._ingest,
            "recon": self._recon,
            "audit": self._audit,
            "validate": self._validate,
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
        """Mock corroboration: emit a per-finding verdict. A fixture
        ``<scenario>/corroborate/<finding_id>.json`` (if present) drives the verdict so tests can
        exercise design_accepted / fixed_upstream; otherwise default to ``corroborated``."""
        fid = label or "MOCK-1"
        out = work_dir / f"corroboration_{fid}.json"
        src = self.scenario_dir / "corroborate" / f"{fid}.json"
        if src.is_file():
            self._copy(src, out)
        else:
            out.write_text(json.dumps({
                "finding_id": fid, "verdict": "corroborated",
                "rationale": "(mock) no contradicting docs or newer fixing commit found.",
                "evidence_urls": [], "fix_commit": None, "doc_url": None,
                "adjusted_severity": None}, indent=2), encoding="utf-8")
        return self._envelope(self._manifest(
            [{"type": "corroboration", "path": out.name, "status": "ok"}]))

    def _remediate(self, work_dir: Path, label, prompt: str, repo_dir) -> dict:
        """Emit a real, applyable unified diff: read the finding's primary file (READ-ONLY) and
        append a harmless remediation marker comment, producing a valid `fix.diff`. Keeps the
        target compiling so the verify stage can be exercised end-to-end at zero token cost."""
        import difflib

        target = ""
        if "Primary location:" in prompt:
            seg = prompt.split("Primary location:", 1)[1].strip()
            target = seg.splitlines()[0].split(":", 1)[0].strip()
        src = Path(repo_dir) / target if (repo_dir and target) else None
        if src and src.is_file():
            old = src.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
            if old and not old[-1].endswith("\n"):
                old[-1] += "\n"
            comment = "# argo: remediation marker (mock fix)\n" if target.endswith(".py") \
                else "// argo: remediation marker (mock fix)\n"
            new = old + [comment]
            diff = "".join(difflib.unified_diff(
                old, new, fromfile=f"a/{target}", tofile=f"b/{target}"))
        else:
            # no resolvable target — emit a new-file diff (always applies, nothing to break)
            diff = ("--- /dev/null\n+++ b/ARGO_FIX_NOTE.md\n@@ -0,0 +1,1 @@\n"
                    "+Argo proposed-fix placeholder (mock).\n")
        (work_dir / "fix.diff").write_text(diff, encoding="utf-8")
        return self._envelope(
            "Mock remediation: wrote fix.diff (root-cause patch as a unified diff).\n\n"
            "Generated files: fix.diff")

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

    def _validate(self, work_dir: Path, label) -> dict:
        finding_id = work_dir.name  # work/validate/<finding_id>
        verdicts = json.loads(
            (self.scenario_dir / "validate" / "verdicts.json").read_text(encoding="utf-8"))
        verdict = verdicts.get(finding_id, verdicts.get("_default"))
        if verdict is None:
            raise RunnerError(f"mock verdict fixture missing for {finding_id!r} and no _default")
        verdict = dict(verdict)
        verdict.setdefault("finding_id", finding_id)
        out = work_dir / f"verdict_{finding_id}.json"
        out.write_text(json.dumps(verdict, indent=2), encoding="utf-8")
        return self._envelope(self._manifest(
            [{"type": "verdict", "path": out.name, "status": "ok"}]))


#: Error-message hints that mark a session failure as RETRYABLE on another backend (vs a real
#: deterministic failure that should propagate). Matched case-insensitively against the RunnerError.
_RETRYABLE_HINTS = ("session limit", "rate limit", "rate_limit", "api_error_status=429", " 429",
                    "overloaded", "quota", "too many requests", "insufficient_quota")


def _is_retryable(exc: Exception) -> bool:
    s = str(exc).lower()
    return any(h in s for h in _RETRYABLE_HINTS)


class FallbackRunner(AgentRunner):
    """Chains backends for resilience: on a RETRYABLE limit (session/rate-limit/429) the SAME call is
    retried on the next backend (e.g. Claude -> Codex -> local). The model is recomputed per backend
    (each child has its own config), and a backend that hits its limit is disabled for the rest of
    the run (circuit breaker) so we don't re-hit the wall on every subsequent call. A non-retryable
    error propagates immediately."""

    def __init__(self, config: PipelineConfig, ledger: Ledger, runners: list[AgentRunner]):
        self._runners = runners                       # primary first; set BEFORE super().__init__
        self._disabled: set[int] = set()
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
                if i in self._disabled:
                    continue
            kw = dict(kwargs)
            if stage is not None:                     # each backend picks its own model for the stage
                kw["model"] = r.config.model_for(stage)
            try:
                return r.run(**kw)
            except RunnerError as exc:
                last_exc = exc
                if not _is_retryable(exc):
                    raise
                with self._fb_lock:
                    self._disabled.add(i)
                if i + 1 < len(self._runners):
                    print(f"[runner] backend #{i} ({r.config.runner}) hit a retryable limit; "
                          f"falling back to #{i + 1} ({self._runners[i + 1].config.runner})",
                          file=sys.stderr)
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
    raise ValueError(f"unknown runner {name!r} (expected 'headless', 'codex', or 'mock')")


def _expand_backend(config: PipelineConfig, ledger: Ledger, name: str) -> list[AgentRunner]:
    """One backend name -> one or more runners. Multi-account backends expand to one runner per
    credential dir (limits are per-account): Claude via CLAUDE_CONFIG_DIR, Codex via CODEX_HOME."""
    if name == "headless" and config.claude_accounts:
        return [HeadlessClaudeRunner(config.with_overrides(claude_config_dir=d), ledger)
                for d in config.claude_accounts]
    if name == "codex" and config.codex_accounts:
        return [CodexRunner(config.with_overrides(codex_home=d), ledger)
                for d in config.codex_accounts]
    return [_build_one(config, ledger, name)]


def build_runner(config: PipelineConfig, ledger: Ledger) -> AgentRunner:
    chain = _expand_backend(config, ledger, config.runner)
    for n in config.runner_fallbacks:
        chain += _expand_backend(config, ledger, n)
    return chain[0] if len(chain) == 1 else FallbackRunner(config, ledger, chain)
