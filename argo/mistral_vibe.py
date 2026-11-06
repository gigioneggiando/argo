"""``runner = mistral-vibe``: the Mistral **Vibe** coding-agent CLI (``vibe -p``), headless.

Verified against mistral-vibe 3.1.0 on Windows (2026-11-06). Each session gets an Argo-managed,
isolated ``VIBE_HOME`` (never the user's own config, sessions or project trust) whose
``config.toml`` pins the safety envelope:

  * tools: only ``read_file`` and (when the stage grants ``Write``) ``write_file``; every shell
    (``bash``/``powershell``/``git_bash``), web, task, skill and edit tool disabled, and the shells
    additionally set to ``permission = "never"`` (observed: Vibe still *offers* ``file_system.bash``
    to the model, but a ``never`` tool call is refused, not run);
  * ``outside_workdir = "deny"`` with the session scratch dir as ``--workdir``, so writes land only
    in scratch; the audited repo is readable through one encoded path grant
    (``vibe-path:directory_recursive:<repo>``) on ``read_file`` only -- never ``--add-dir``, which
    would make the repo writable too;
  * MCP, subagents, connectors, background processes, project context (``AGENTS.md``), telemetry
    and update checks off.

Vibe 3.1 has no ``grep`` tool (search goes through the shell, which stays off), so this backend
reads code with ``read_file`` only: correct, but slower on large repos than ``mistral-api``.
The networked OSINT stages are refused (no web tools). The key (``ARGO_MISTRAL_VIBE_API_KEY``,
else ``ARGO_MISTRAL_API_KEY``, else ``MISTRAL_API_KEY``) reaches Vibe only as the child's
``MISTRAL_API_KEY``; a browser/subscription login is not used, because the isolated home has none.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from .config import PipelineConfig
from .ledger import Ledger
from .runner import AgentRunner, LLMResult, RunnerError, _redact_secrets

#: Vibe exit codes (``vibe -p``): 0 finished, 1 invocation/config error, 2 runtime/model error,
#: 3 stopped by a limit (turns, tokens, price, time) or interrupted.
_EXIT_CONFIG, _EXIT_RUNTIME, _EXIT_LIMIT = 1, 2, 3
_AUTH_RE = re.compile(r"\b401\b|\b403\b|unauthori[sz]ed|invalid api key|api key", re.I)
_DISABLED = ["bash", "bash_*", "powershell", "powershell_*", "git_bash", "git_bash_*",
             "web_fetch", "web_search", "task", "skill", "edit", "todo", "ask_user_question"]


def _toml_literal(value: str) -> str:
    """TOML literal string (no escapes: Windows backslashes stay literal)."""
    if "'" in value or "\n" in value:
        raise RunnerError(f"path not representable in the Vibe config: {value!r}",
                          retryable=False, failure_kind="credential_bootstrap")
    return f"'{value}'"


def vibe_config_toml(repo_dir: Path | None, allow_write: bool) -> str:
    """The isolated session config (no secrets). ``repo_dir`` is granted read-only."""
    enabled = ["read_file"] + (["write_file"] if allow_write else [])
    lines = [
        "# Managed by Argo (runner=mistral-vibe). Regenerated every session; no secrets here.",
        'outside_workdir = "deny"',
        "enable_mcp = false", "enable_subagents = false", "enable_connectors = false",
        "enable_background_processes = false", "include_project_context = false",
        "enable_telemetry = false", "enable_update_checks = false", "enable_auto_update = false",
        "bypass_tool_permissions = false",
        "enabled_tools = [" + ", ".join(f'"{t}"' for t in enabled) + "]",
        "disabled_tools = [" + ", ".join(f'"{t}"' for t in
                                          _DISABLED + ([] if allow_write else ["write_file"])) + "]",
        "", "[tools.read_file]", 'permission = "always"',
    ]
    if repo_dir is not None:
        grant = "vibe-path:directory_recursive:" + os.path.realpath(repo_dir)
        lines.append(f"allowlist = [{_toml_literal(grant)}]")
    lines += ["", "[tools.write_file]",
              f'permission = "{"always" if allow_write else "never"}"', 'outside_workdir = "deny"']
    for shell in ("bash", "powershell", "git_bash"):
        lines += ["", f"[tools.{shell}]", 'permission = "never"']
    return "\n".join(lines) + "\n"


def _final_text(messages) -> str:
    """Last assistant message text from ``--output json`` (a list of session items)."""
    if not isinstance(messages, list):
        return ""
    for item in reversed(messages):
        if isinstance(item, dict) and item.get("type") == "message" \
                and item.get("role") == "assistant":
            content = item.get("content")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                return "".join(c.get("text", "") for c in content
                               if isinstance(c, dict) and c.get("type") == "text")
    return ""


class MistralVibeRunner(AgentRunner):
    """Headless ``vibe -p`` under an isolated, Argo-written config (see module docstring)."""

    def __init__(self, config: PipelineConfig, ledger: Ledger, vibe_bin: str = "vibe"):
        super().__init__(config, ledger)
        self.vibe_bin = vibe_bin
        self._resolved_bin: str | None = None

    def _bin(self) -> str:
        if self._resolved_bin is None:
            found = shutil.which(self.vibe_bin)
            if not found:
                raise RunnerError(
                    f"vibe CLI not found on PATH (looked for {self.vibe_bin!r}); install it with "
                    "`uv tool install mistral-vibe` or use --runner mistral-api",
                    retryable=False, failure_kind="credential_bootstrap")
            self._resolved_bin = found
        return self._resolved_bin

    def _api_key(self) -> str:
        key = (self.config.mistral_vibe_api_key or os.environ.get("ARGO_MISTRAL_VIBE_API_KEY")
               or self.config.mistral_api_key or os.environ.get("ARGO_MISTRAL_API_KEY")
               or os.environ.get("MISTRAL_API_KEY") or "").strip()
        if not key:
            raise RunnerError(
                "runner=mistral-vibe needs a Mistral key: set ARGO_MISTRAL_VIBE_API_KEY (or "
                "ARGO_MISTRAL_API_KEY / MISTRAL_API_KEY); Argo runs Vibe with an isolated home, "
                "so a browser login is not used", retryable=False,
                failure_kind="credential_bootstrap")
        return key

    def build_cmd(self, *, model: str | None, work_dir: Path, export_dir: Path, allow_write: bool,
                  timeout_s: int) -> list[str]:
        cmd = [self._bin(), "-p", "--output", "json", "--output-dir", str(export_dir),
               "--workdir", str(work_dir), "--time-limit", str(max(30, int(timeout_s) - 15)),
               "--enabled-tools", "read_file"]
        if allow_write:
            cmd += ["--enabled-tools", "write_file"]
        if self.config.session_max_turns:
            cmd += ["--max-turns", str(int(self.config.session_max_turns))]
        if model:
            cmd += ["--model", model]
        return cmd

    def _invoke(self, *, prompt, work_dir, model, repo_dir, allowed, disallowed, policy=None,
                stage, run_id, label, session_budget_usd=None, timeout_s=None) -> dict:
        if policy is not None and policy.network:
            raise RunnerError(
                f"runner=mistral-vibe has no web tools enabled, so stage {stage!r} cannot run on "
                f"it: pass --no-{stage} or route it elsewhere (--stage-runner {stage}=headless|"
                "codex|gemini)", retryable=False, failure_kind="unsupported_stage_tool")
        key = self._api_key()
        work_dir = Path(work_dir)
        work_dir.mkdir(parents=True, exist_ok=True)
        allow_write = "Write" in (allowed or [])
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", label or stage)
        # Home + export live NEXT TO the scratch dir: outside the workdir, so the model can neither
        # read its own config/transcript nor rewrite the policy.
        side = work_dir.parent / ".argo_sessions" / f"{work_dir.name}.vibe.{safe}"
        home, export_dir = side / "home", side / "export"
        if export_dir.exists():
            shutil.rmtree(export_dir, ignore_errors=True)
        home.mkdir(parents=True, exist_ok=True)
        (home / "config.toml").write_text(
            vibe_config_toml(Path(repo_dir) if repo_dir else None, allow_write), encoding="utf-8")
        timeout = int(timeout_s or self.config.session_timeout_s)
        cmd = self.build_cmd(model=model, work_dir=work_dir, export_dir=export_dir,
                             allow_write=allow_write, timeout_s=timeout)
        env = {**os.environ, "VIBE_HOME": str(home), "MISTRAL_API_KEY": key}
        try:
            proc = self._exec(cmd, prompt=prompt, cwd=work_dir, timeout=timeout, env=env)
        except subprocess.TimeoutExpired as exc:   # pragma: no cover - real-runner path
            raise RunnerError(f"vibe session timed out after {timeout}s (stage={stage}, "
                              f"label={label})", retryable=True, failure_kind="timeout") from exc
        stdout = _redact_secrets(proc.stdout, key)
        stderr = _redact_secrets(proc.stderr, key)
        export = {}
        try:
            export = json.loads((export_dir / "export.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        rc = proc.returncode
        err_text = f"{stderr}\n{json.dumps(export.get('error'))}"
        if rc != 0 and _AUTH_RE.search(err_text):
            raise RunnerError(f"Mistral rejected the Vibe key (stage={stage}, label={label}); "
                              "check ARGO_MISTRAL_VIBE_API_KEY -- not retrying",
                              retryable=False, failure_kind="auth_failed")
        if rc == _EXIT_CONFIG:
            raise RunnerError(f"vibe rejected its invocation/config (stage={stage}, "
                              f"label={label}): {stderr[-800:]}", retryable=False,
                              failure_kind="invalid_request")
        try:
            messages = json.loads(stdout) if stdout.strip() else []
        except ValueError:
            messages = []
        cfg = export.get("config") or {}
        alias = model or cfg.get("active_model") or ""
        served = ((cfg.get("models") or {}).get(alias) or {}).get("name") if alias else None
        return {"_backend": "mistral-vibe", "returncode": rc, "text": _final_text(messages),
                "outcome": export.get("outcome"), "stop_reason": export.get("stop_reason"),
                "usage": export.get("usage") or {}, "cost_usd": export.get("cost_usd"),
                "steps": export.get("steps"), "served_model": served,
                "vibe_version": export.get("vibe_version"), "warnings": export.get("warnings"),
                "stderr": stderr[-2000:], "export_dir": str(export_dir)}

    def parse_envelope(self, raw: dict, *, model: str, prompt_sha256: str,
                       work_dir: Path) -> LLMResult:
        rc = int(raw.get("returncode", 0) or 0)
        usage = raw.get("usage") or {}
        cost = raw.get("cost_usd")
        served = raw.get("served_model")
        outcome = raw.get("outcome") or f"exit_{rc}"
        return LLMResult(
            text=raw.get("text") or "", model=model, prompt_sha256=prompt_sha256,
            work_dir=work_dir, input_tokens=int(usage.get("input_tokens") or 0),
            output_tokens=int(usage.get("output_tokens") or 0),
            cost_usd=float(cost) if isinstance(cost, (int, float)) else 0.0,
            num_turns=int(raw.get("steps") or 0), session_id=None, stop_reason=outcome,
            # 2 = runtime/model error, 3 = a limit stopped it: both recoverable (the stage can
            # salvage scratch artifacts; FallbackRunner can retry elsewhere).
            is_error=rc != 0, api_error_status=None, raw=raw, requested_model=model,
            # Vibe aliases (mistral-medium-3.5) map to API names (mistral-vibe-cli-latest):
            # recorded in served_models, never reported as a substitution.
            served_model=None, served_models=(served,) if served else (),
            cost_source="provider_estimated" if isinstance(cost, (int, float)) else "unknown")
