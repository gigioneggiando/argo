"""``runner = mistral-vibe``: the Mistral **Vibe** coding-agent CLI (``vibe -p``), headless.

Verified against mistral-vibe 3.1.0 on Windows (2026-11-06). Each session gets an Argo-managed,
isolated ``VIBE_HOME`` (never the user's own config, sessions or project trust) whose
``config.toml`` pins the safety envelope:

  * tools: only ``read_file`` and (when the stage grants ``Write``) Argo's local stdio MCP
    ``argo_write_file``; Vibe's native writer, every shell (``bash``/``powershell``/``git_bash``),
    web, task, skill and edit tool disabled, and the shells additionally set to
    ``permission = "never"`` (observed: Vibe still *offers* ``file_system.bash`` to the model, but
    a ``never`` tool call is refused, not run);
  * ``outside_workdir = "deny"`` with the session scratch dir as ``--workdir``, so writes land only
    in scratch; the audited repo is readable through one encoded path grant
    (``vibe-path:directory_recursive:<repo>``) on ``read_file`` only -- never ``--add-dir``, which
    would make the repo writable too;
  * remote MCP servers, subagents, connectors, background processes, project context (``AGENTS.md``),
    telemetry and update checks off. The only MCP server is the Argo-owned local JSON writer;
    it has no network tools and is scoped to this session's scratch directory.

Vibe 3.1 has no ``grep`` tool (search goes through the shell, which stays off), so this backend
reads code with ``read_file`` only: correct, but slower on large repos than ``mistral-api``.
The networked OSINT stages are refused (no web tools). Explicit ``key`` auth preserves the
legacy key chain; ``stored`` delegates credential resolution to Vibe's native OS keyring,
without reading credentials in Argo or importing the user's home/profile.
"""
from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .config import PipelineConfig
from .ledger import Ledger
from .runner import AgentRunner, LLMResult, RunnerError, _classify_failure_text, _redact_secrets

#: Vibe exit codes (``vibe -p``): 0 finished, 1 invocation/config error, 2 runtime/model error,
#: 3 stopped by a limit (turns, tokens, price, time) or interrupted.
_EXIT_CONFIG, _EXIT_RUNTIME, _EXIT_LIMIT = 1, 2, 3
_AUTH_RE = re.compile(r"\b401\b|unauthori[sz]ed|invalid api key|expired (?:access )?token|"
                      r"token (?:has )?expired|authentication failed", re.I)
_DISABLED = ["bash", "bash_*", "powershell", "powershell_*", "git_bash", "git_bash_*",
             "web_fetch", "web_search", "task", "skill", "edit", "todo", "ask_user_question"]


def _toml_literal(value: str) -> str:
    """TOML literal string (no escapes: Windows backslashes stay literal)."""
    if "'" in value or "\n" in value:
        raise RunnerError(f"path not representable in the Vibe config: {value!r}",
                          retryable=False, failure_kind="credential_bootstrap")
    return f"'{value}'"


def vibe_config_toml(repo_dir: Path | None, allow_write: bool,
                     work_dir: Path | None = None) -> str:
    """The isolated session config (no secrets). ``repo_dir`` is granted read-only."""
    use_argo_writer = allow_write and work_dir is not None
    enabled = ["read_file"] + (["argo_write_file"] if use_argo_writer else [])
    lines = [
        "# Managed by Argo (runner=mistral-vibe). Regenerated every session; no secrets here.",
        'outside_workdir = "deny"',
        f"enable_mcp = {'true' if use_argo_writer else 'false'}",
        "enable_subagents = false", "enable_connectors = false",
        "enable_background_processes = false", "include_project_context = false",
        "enable_telemetry = false", "enable_update_checks = false", "enable_auto_update = false",
        "bypass_tool_permissions = false",
        "enabled_tools = [" + ", ".join(f'"{t}"' for t in enabled) + "]",
        "disabled_tools = [" + ", ".join(f'"{t}"' for t in
                                          _DISABLED + ["write_file"]) + "]",
        "", "[tools.read_file]", 'permission = "always"',
    ]
    if repo_dir is not None:
        grant = "vibe-path:directory_recursive:" + os.path.realpath(repo_dir)
        lines.append(f"allowlist = [{_toml_literal(grant)}]")
    lines += ["", "[tools.write_file]", 'permission = "never"',
              'outside_workdir = "deny"', "", '[tools."argo_write_file"]',
              f'permission = "{"always" if use_argo_writer else "never"}"']
    for shell in ("bash", "powershell", "git_bash"):
        lines += ["", f"[tools.{shell}]", 'permission = "never"']
    if use_argo_writer:
        module_root = Path(__file__).resolve().parent.parent
        command = [sys.executable, "-m", "argo.mistral_vibe_tools"]
        lines += [
            "", "[[mcp_servers]]", 'name = "argo"', 'transport = "stdio"',
            f"command = {json.dumps(command[0])}",
            "args = " + json.dumps([*command[1:], "--work-dir", str(Path(work_dir).resolve())]),
            f"cwd = {json.dumps(str(Path(work_dir).resolve()))}",
            "env = { PYTHONPATH = " + json.dumps(str(module_root)) + " }",
        ]
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
                               if isinstance(c, dict) and c.get("type") == "text"
                               and isinstance(c.get("text"), str))
    return ""


def _valid_count(value) -> bool:
    return type(value) is int and value >= 0


def _valid_cost(value) -> bool:
    return value is None or (type(value) in (int, float) and math.isfinite(value) and value >= 0)


def _valid_usage(value) -> bool:
    return (isinstance(value, dict)
            and all(_valid_count(value.get(k)) for k in ("input_tokens", "output_tokens"))
            and all(v is None or _valid_count(v) for v in value.values()))


def _valid_messages(value) -> bool:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        return False
    for item in value:
        if item.get("type") != "message":
            continue
        content = item.get("content")
        if isinstance(content, str):
            continue
        if not isinstance(content, list) or not all(isinstance(c, dict) for c in content):
            return False
        if any(c.get("type") == "text" and not isinstance(c.get("text"), str) for c in content):
            return False
    return True


def _valid_export(value) -> bool:
    if not isinstance(value, dict):
        return False
    cfg = value.get("config")
    return (value.get("outcome") == "finished" and value.get("error") is None
            and type(value.get("exit_code")) is int and value["exit_code"] == 0
            and _valid_usage(value.get("usage")) and _valid_cost(value.get("cost_usd"))
            and (value.get("steps") is None or _valid_count(value["steps"]))
            and isinstance(cfg, dict) and isinstance(cfg.get("models", {}), dict)
            and all(isinstance(model, dict) for model in cfg.get("models", {}).values()))


def _vibe_failure(text: str) -> str:
    """Only an Argo-owned label leaves the diagnostic boundary.

    A 403 is not evidence of expired login, nor is a 429 evidence of exhausted billing.
    Never classify assistant/tool text: it may quote source files or user instructions.
    """
    if re.search(r"missing.*api.?key|no.*credentials|keyring.*(?:unavailable|inaccessible|failed)|"
                 r"no recommended backend|no keyring backend", text, re.I):
        return "credential_bootstrap"
    if re.search(r"(?:organization|workspace|admin(?:istrator)?).{0,30}policy|policy conflict", text, re.I):
        return "invalid_request"
    if _AUTH_RE.search(text):
        return "auth_failed"
    if re.search(r"out of credits|insufficient_quota|(?:budget|credits?|allowance|balance)"
                 r".{0,50}(?:exhausted|depleted|exceeded)|payment required", text, re.I):
        return "credits_exhausted"
    if re.search(r"model_not_found|model.{0,50}(?:unavailable|not (?:found|supported))", text, re.I):
        return "model_unavailable"
    return _classify_failure_text(" " + text) or "unknown_retryable"


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
                "ARGO_MISTRAL_API_KEY / MISTRAL_API_KEY); key mode never falls back to stored "
                "credentials", retryable=False,
                failure_kind="credential_bootstrap")
        return key

    def build_cmd(self, *, model: str | None, work_dir: Path, export_dir: Path, allow_write: bool,
                  timeout_s: int) -> list[str]:
        cmd = [self._bin(), "-p", "--output", "json", "--output-dir", str(export_dir),
               "--workdir", str(work_dir), "--time-limit", str(max(30, int(timeout_s) - 15)),
               "--enabled-tools", "read_file"]
        if allow_write:
            cmd += ["--enabled-tools", "argo_write_file"]
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
        auth_mode = getattr(self.config, "mistral_vibe_auth", "key")
        if os.environ.get("VIBE_CLI_OIDC_ENABLED", "").lower() in {"1", "true"}:
            raise RunnerError("Vibe OIDC override is incompatible with Argo key/stored auth; "
                              "disable it in the launching environment", retryable=False,
                              failure_kind="credential_bootstrap")
        key = self._api_key() if auth_mode == "key" else None
        work_dir = Path(work_dir)
        work_dir.mkdir(parents=True, exist_ok=True)
        allow_write = "Write" in (allowed or [])
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", label or stage)
        # Home + export live NEXT TO the scratch dir: outside the workdir, so the model can neither
        # read its own config/transcript nor rewrite the policy.
        sessions = work_dir.parent / ".argo_sessions"
        sessions.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Vibe caches can contain read-only blobs (Windows) and prior attempts are private
        # evidence. Never delete/reuse them during a retry, or import stale dotenv/agent state.
        side = Path(tempfile.mkdtemp(prefix=f"{work_dir.name}.vibe.{safe}.", dir=sessions))
        home, export_dir = side / "home", side / "export"
        home.mkdir(mode=0o700)
        (home / "config.toml").write_text(
            vibe_config_toml(Path(repo_dir) if repo_dir else None, allow_write, work_dir),
            encoding="utf-8")
        timeout = int(timeout_s or self.config.session_timeout_s)
        cmd = self.build_cmd(model=model, work_dir=work_dir, export_dir=export_dir,
                             allow_write=allow_write, timeout_s=timeout)
        # Keep OS/PATH/certificates/proxies/keyring transport, not inherited Vibe policy or
        # authentication overrides. Never mutate the parent environment.
        key_vars = {"MISTRAL_API_KEY", "ARGO_MISTRAL_API_KEY", "ARGO_MISTRAL_VIBE_API_KEY"}
        env = {k: v for k, v in os.environ.items()
               if not k.upper().startswith("VIBE_") and k.upper() not in key_vars}
        env["VIBE_HOME"] = str(home)
        if key is not None:
            env["MISTRAL_API_KEY"] = key
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
        if rc == 0 and not _valid_export(export):
            raise RunnerError("vibe returned an invalid or missing success export",
                              retryable=False, failure_kind="invalid_request")
        if not isinstance(export, dict):
            export = {}
        err_text = f"{stderr}\n{json.dumps(export.get('error'))}"
        failure_kind = _vibe_failure(err_text) if rc != 0 else None
        if failure_kind in {"auth_failed", "credential_bootstrap"}:
            instruction = ("complete `vibe --setup` browser login manually under the server OS "
                           "account; a file-only credential is not imported" if auth_mode == "stored"
                           else "check the configured Vibe key")
            raise RunnerError(f"Vibe authentication unavailable; {instruction}",
                              retryable=False, failure_kind=failure_kind)
        if rc == _EXIT_CONFIG:
            raise RunnerError("vibe rejected its invocation/config; inspect private session output",
                              retryable=False, failure_kind=(failure_kind if failure_kind !=
                              "unknown_retryable" else "invalid_request"))
        try:
            messages = json.loads(stdout) if stdout.strip() else []
        except ValueError:
            messages = None
        if rc == 0 and not _valid_messages(messages):
            raise RunnerError("vibe returned malformed success messages",
                              retryable=False, failure_kind="invalid_request")
        config_value = export.get("config")
        cfg = config_value if isinstance(config_value, dict) else {}
        alias = model or cfg.get("active_model") or ""
        alias = alias if isinstance(alias, str) else ""
        models_value = cfg.get("models")
        models = models_value if isinstance(models_value, dict) else {}
        served_model = models.get(alias)
        served = served_model.get("name") if isinstance(served_model, dict) else None
        served = served if isinstance(served, str) and re.fullmatch(r"[A-Za-z0-9_.:/-]{1,160}", served) else None
        version = export.get("vibe_version")
        version = version if isinstance(version, str) and re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", version) else None
        # Unknown keyring secrets cannot be scrubbed by value in the parent. On failure only
        # fixed labels leave this boundary, never assistant/tool text or vendor diagnostics.
        outcome = export.get("outcome")
        outcome = outcome if isinstance(outcome, str) and outcome in {"finished", "error", "config_error", "turn_limit",
            "token_limit", "price_limit", "time_limit", "interrupted", "tool_denied", "usage_error",
            "infrastructure_failure", "deadline", "terminated", "length", "refusal", "aborted"} else f"exit_{rc}"
        return {"_backend": "mistral-vibe", "returncode": rc,
                "text": _final_text(messages) if rc == 0 else "Vibe session did not finish",
                "outcome": outcome,
                "usage": export.get("usage") if _valid_usage(export.get("usage")) else {},
                "cost_usd": export.get("cost_usd") if _valid_cost(export.get("cost_usd")) else None,
                "steps": export.get("steps") if _valid_count(export.get("steps")) else 0,
                "served_model": served, "vibe_version": version,
                "stderr": "", "failure_kind": failure_kind,
                "mistral_vibe_auth": auth_mode, "auth_source": "unknown"}

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
            failure_kind=raw.get("failure_kind"),
            metadata={"mistral_vibe_auth": raw.get("mistral_vibe_auth", "key"),
                      "auth_source": "unknown", "vibe_version": raw.get("vibe_version")},
            cost_source="provider_estimated" if isinstance(cost, (int, float)) else "unknown")
