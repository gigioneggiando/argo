"""Guardrail enforcement — the constraints that must hold in code, not just in prompts.

Every chokepoint that could violate a non-negotiable rule routes through here:

  * :func:`enforce_session_tools` — strips any network/sub-agent or mutation tool from a
    session's allowlist, guaranteeing no stage can contact a live host or patch the repo.
    Called inside the runner, so even a buggy stage cannot widen the allowlist.
  * :func:`assert_prohibited_present` — fails the run if a rendered prompt does not carry
    the scope's ``prohibited_techniques`` verbatim.
  * :func:`assert_audit_prompt_wellformed` — verifies a model-generated audit prompt
    conforms to the template (carries the RoE + prohibited techniques + finding format).
  * :func:`out_of_scope_match` — code-side scope filter, independent of any LLM verdict.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .config import ALWAYS_DISALLOWED, MUTATION_TOOLS, NETWORK_TOOLS, OSINT_TOOLS

#: The single stage permitted read-only public web OSINT (search + fetch). It never receives the
#: repo and must never reach the program's live in-scope hosts (enforced in the prompt + by scope).
_OSINT_STAGE = "research"


@dataclass(frozen=True)
class SessionPolicy:
    """Backend-neutral description of what a stage's session may do — the single source of truth
    for "no network except research, repo never writable". Each runner translates it into its own
    CLI dialect: the Claude runner into ``--allowedTools``/``--disallowedTools``; the Codex runner
    into sandbox flags (``-s workspace-write`` + an opt-in ``network_access``)."""
    network: bool                 # may reach the network (public OSINT) — ONLY the research stage
    repo_writable: bool = False   # the target repo is ALWAYS read-only, every backend, every stage


def session_policy(stage: str | None) -> SessionPolicy:
    return SessionPolicy(network=(stage == _OSINT_STAGE), repo_writable=False)


class GuardrailError(RuntimeError):
    """Base class for all hard-stop guardrail violations."""


class LiveInteractionForbiddenError(GuardrailError):
    """A session was about to be granted a network/host-reaching tool."""


class PromptGuardrailError(GuardrailError):
    """A prompt rendered without the required prohibited-technique constraints, or a
    generated audit prompt did not conform to the safety template."""


# --------------------------------------------------------------------------- tools
def enforce_session_tools(requested_allowed: list[str], *,
                          stage: str | None = None) -> tuple[list[str], list[str]]:
    """Sanitize a session's tool allowlist.

    Returns ``(allowed, disallowed)`` lists to hand to the CLI. Any requested tool that
    can reach the network/spawn agents or mutate files is dropped from *allowed* and added
    to *disallowed*. This is the structural guarantee behind "never touch live hosts" and
    "repo is read-only": there is simply no code path that can enable such a tool.

    The single exception is ``stage == "research"``: it may keep the **OSINT** tools
    (``WebSearch``/``WebFetch``) for public threat-intel — but still loses the shell,
    sub-agent, and mutation tools. Every other stage stays fully offline.
    """
    permit_osint = stage == _OSINT_STAGE
    forbidden = (NETWORK_TOOLS | MUTATION_TOOLS) - (OSINT_TOOLS if permit_osint else frozenset())
    allowed = [t for t in requested_allowed if t not in forbidden]
    # Belt-and-suspenders: explicitly disallow the forbidden set every time (minus OSINT for research).
    disallowed = sorted(set(ALWAYS_DISALLOWED) - (OSINT_TOOLS if permit_osint else frozenset()))
    return allowed, disallowed


def assert_no_network_tools(allowed: list[str], *, stage: str | None = None) -> None:
    """Hard assertion used right before a session launches. For the ``research`` stage the OSINT
    tools (WebSearch/WebFetch) are permitted; the shell/sub-agent tools never are."""
    permit_osint = stage == _OSINT_STAGE
    forbidden = NETWORK_TOOLS - (OSINT_TOOLS if permit_osint else frozenset())
    leaked = sorted(set(allowed) & forbidden)
    if leaked:
        raise LiveInteractionForbiddenError(
            f"Refusing to launch a session with network/host-reaching tools: {leaked}. "
            "No stage may contact, scan, or exercise a live host."
        )


# ---------------------------------------------------------------- prohibited techniques
def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def assert_prohibited_present(rendered_prompt: str, prohibited_techniques: list[str]) -> None:
    """Fail if any prohibited technique is missing from the rendered prompt text.

    The scope's prohibited techniques must be propagated *verbatim* into every prompt that
    is sent to a model. If the scope lists none, that is itself suspicious for a real
    bug-bounty program, so we require at least one.
    """
    if not prohibited_techniques:
        raise PromptGuardrailError(
            "scope.prohibited_techniques is empty — refusing to render a prompt without "
            "explicit hard limits (e.g. 'no DoS', 'no automated scanning of live hosts'). "
            "Populate prohibited_techniques in scope.json."
        )
    haystack = _normalize(rendered_prompt)
    missing = [p for p in prohibited_techniques if _normalize(p) not in haystack]
    if missing:
        raise PromptGuardrailError(
            "Rendered prompt is missing required prohibited techniques (guardrail): "
            + "; ".join(missing)
        )


def ensure_prohibited_present(prompt_text: str, prohibited_techniques: list[str]) -> str:
    """Deterministically guarantee every scope prohibited technique appears *verbatim* in a
    model-generated audit prompt.

    Recon asks the model to regenerate the audit template carrying the scope's prohibited
    techniques verbatim; models sometimes paraphrase them. Rather than fail the run on a
    paraphrase, we re-insert any missing constraint verbatim under the PROHIBITED TECHNIQUES
    section (creating the section if the model omitted it). We only ever **add** the scope's
    own constraints, never remove or relax anything, so this strengthens the prompt — and
    :func:`assert_prohibited_present` still runs afterwards as the hard gate.
    """
    if not prohibited_techniques:
        return prompt_text
    haystack = _normalize(prompt_text)
    missing = [p for p in prohibited_techniques if _normalize(p) not in haystack]
    if not missing:
        return prompt_text
    block = "\n".join(f"- {m}" for m in missing)
    lines = prompt_text.splitlines()
    for i, line in enumerate(lines):
        if line.lstrip().startswith("#") and "prohibited techniques" in line.lower():
            lines.insert(i + 1, block)
            return "\n".join(lines)
    return prompt_text.rstrip() + "\n\n## PROHIBITED TECHNIQUES\n" + block + "\n"


# Anchors that a template-conforming audit prompt must contain (from
# 01_audit_prompt_template.md.j2). Used to reject malformed model-generated prompts.
_REQUIRED_AUDIT_ANCHORS = (
    "SCOPE & RULES OF ENGAGEMENT",
    "PROHIBITED TECHNIQUES",
    "REQUIRED PER-FINDING FORMAT",
    "Do NOT patch",
)


def assert_audit_prompt_wellformed(prompt_text: str, prohibited_techniques: list[str]) -> None:
    """Validate a model-generated audit prompt before it is used to drive a session."""
    missing_anchors = [a for a in _REQUIRED_AUDIT_ANCHORS if a.lower() not in prompt_text.lower()]
    if missing_anchors:
        raise PromptGuardrailError(
            "Generated audit prompt does not conform to the safety template; missing "
            f"sections: {missing_anchors}"
        )
    assert_prohibited_present(prompt_text, prohibited_techniques)


# ------------------------------------------------------------------ runtime probe safety
class RuntimeProbeError(GuardrailError):
    """A runtime probe plan tried to leave loopback, exceed safety caps, or use an unsafe method.
    The runtime stage builds the OSS target into an egress-blocked, loopback-only container and
    probes ONLY that local instance — it must NEVER reach the program's real in-scope hosts."""


#: Hosts a probe is allowed to target. The app binds inside an ``--network=none`` container (only
#: loopback exists), so a probe can ONLY legitimately address loopback. Anything else is a bug or
#: an attempt to reach a real host — rejected.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})
_READONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _probe_host(path_or_url: str) -> str | None:
    """Return the host a probe targets, or None for a host-relative path (host is injected as
    loopback by the runner). An absolute URL must carry an explicit host."""
    s = (path_or_url or "").strip()
    if s.startswith(("http://", "https://")):
        rest = s.split("://", 1)[1]
        return rest.split("/", 1)[0].split("@")[-1].split(":")[0] or None
    if s.startswith("//"):                         # protocol-relative -> //host/...
        return s[2:].split("/", 1)[0].split(":")[0] or None
    return None                                    # host-relative path: loopback by construction


def _entry_requests(entry: dict) -> list[dict]:
    """All HTTP requests in a plan entry: the optional ``auth`` login step + the probe requests."""
    reqs = list(entry.get("requests", []))
    if isinstance(entry.get("auth"), dict):
        reqs.append(entry["auth"])
    return reqs


def assert_loopback_only(probe_plan: list[dict], scope) -> None:
    """Hard gate: every probe must target loopback, and no probe path/Host may name a scope host.
    Defends the core 'never touch a live host' guardrail at the probe layer."""
    scope_hosts = {_normalize(a.asset) for a in getattr(scope, "in_scope", [])} | \
                  {_normalize(x) for x in getattr(scope, "out_of_scope", [])}
    for entry in probe_plan:
        for req in _entry_requests(entry):
            path = str(req.get("path", ""))
            host = _probe_host(path)
            if host is not None and host.lower() not in _LOOPBACK_HOSTS:
                raise RuntimeProbeError(
                    f"probe targets non-loopback host {host!r} (finding "
                    f"{entry.get('finding_id')!r}); only 127.0.0.1/localhost is allowed")
            hdr_host = ""
            for k, v in (req.get("headers") or {}).items():
                if k.strip().lower() == "host":
                    hdr_host = str(v).strip().lower()
            blob = _normalize(path + " " + hdr_host)
            for sh in scope_hosts:
                # ignore trivial tokens; flag a probe that embeds a real in/out-of-scope host
                if sh and len(sh) > 3 and sh not in {"localhost", "127.0.0.1"} and sh in blob:
                    raise RuntimeProbeError(
                        f"probe references a scope host {sh!r} (finding "
                        f"{entry.get('finding_id')!r}); runtime probes hit only the local instance")


def validate_probe_plan(probe_plan: list[dict], *, max_requests: int, max_payload_bytes: int,
                        allow_state_changing: bool) -> None:
    """Hard caps against DoS / unsafe ops. Methods are limited to read-only unless state-changing is
    explicitly opted in; total request count and per-body size are capped."""
    allowed = set(_READONLY_METHODS) | (set(_STATE_CHANGING_METHODS) if allow_state_changing else set())
    total = 0
    for entry in probe_plan:
        auth = entry.get("auth") if isinstance(entry.get("auth"), dict) else None
        for req in _entry_requests(entry):
            total += 1
            method = str(req.get("method", "GET")).upper()
            # The auth/login step is inherently a (non-destructive) POST — exempt it from the
            # read-only gate, but it is still loopback-checked, counted, and body-capped.
            if req is not auth and method not in allowed:
                raise RuntimeProbeError(
                    f"probe method {method!r} not allowed (finding {entry.get('finding_id')!r}); "
                    f"allowed: {sorted(allowed)}"
                    + ("" if allow_state_changing else " — enable runtime_allow_state_changing for writes"))
            body = req.get("body")
            if body is not None and len(str(body).encode("utf-8", "ignore")) > max_payload_bytes:
                raise RuntimeProbeError(
                    f"probe body exceeds {max_payload_bytes} bytes (finding {entry.get('finding_id')!r})")
    if total > max_requests:
        raise RuntimeProbeError(
            f"probe plan has {total} requests, exceeding the cap of {max_requests} (anti-DoS)")


# --------------------------------------------------------------- LIVE testing (opt-in, gated)
class LiveNotAuthorizedError(GuardrailError):
    """The program's rules of engagement do not authorize live interaction (automation not allowed,
    safe-harbor explicitly absent, or no prohibited-techniques limits declared)."""


class LiveScopeError(GuardrailError):
    """A live probe targets a host that is NOT an in-scope asset (or matches an out-of-scope token).
    Live testing may ONLY touch the program's in-scope assets — never anything else."""


class LiveWriteError(GuardrailError):
    """A live probe violates the L3 state-changing policy: a destructive method (DELETE) on a live host,
    or more state-changing requests than the separate write cap allows."""


#: Methods never permitted against a LIVE host, even when writes are opted in — too destructive for an
#: automated confirmation probe (a finding is confirmed by *observing*, not by deleting real data).
_LIVE_DESTRUCTIVE_METHODS = frozenset({"DELETE"})


def _host_of(url: str) -> str:
    s = (url or "").strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    return s.split("/", 1)[0].split("@")[-1].split("?")[0].rsplit(":", 1)[0].strip("[]").lower()


def _inscope_matchers(scope) -> list[tuple[str, str]]:
    """(kind, value) host matchers from the scope's web/api in-scope assets. 'wild' => *.base."""
    out: list[tuple[str, str]] = []
    for a in getattr(scope, "in_scope", []):
        if getattr(a, "type", None) not in ("web", "api"):
            continue
        raw = a.asset.strip().lower()
        host = _host_of(raw) if "://" in raw else raw.split("/", 1)[0]
        host = host.split("?")[0].rsplit(":", 1)[0].strip()
        if host.startswith("*."):
            out.append(("wild", host[2:]))
        elif host:
            out.append(("exact", host))
    return out


def _host_in_scope(host: str, matchers: list[tuple[str, str]]) -> bool:
    for kind, val in matchers:
        if kind == "exact" and host == val:
            return True
        if kind == "wild" and (host == val or host.endswith("." + val)):
            return True
    return False


def assert_live_authorized(scope) -> None:
    """Hard gate before ANY live interaction: the program's RoE must authorize it."""
    if not getattr(scope, "automation_allowed", False):
        raise LiveNotAuthorizedError(
            "live testing refused: scope.automation_allowed is not true — the program does not permit "
            "automated interaction. Enable it only if the program's rules explicitly allow automation.")
    if getattr(scope, "safe_harbor", None) is False:
        raise LiveNotAuthorizedError("live testing refused: scope.safe_harbor is explicitly false.")
    if not getattr(scope, "prohibited_techniques", None):
        raise LiveNotAuthorizedError(
            "live testing refused: scope.prohibited_techniques is empty — refusing to touch a live host "
            "without explicit hard limits (e.g. 'no DoS', 'no automated scanning').")


def assert_inscope_only(probe_plan: list[dict], scope) -> None:
    """Hard gate: every live probe must use an ABSOLUTE URL whose host is an in-scope asset, and must
    not match any out-of-scope token. The inverse of ``assert_loopback_only`` — here loopback/anything
    that is not an explicit in-scope asset is REJECTED."""
    matchers = _inscope_matchers(scope)
    if not matchers:
        raise LiveScopeError("scope declares no in-scope web/api host — nothing is authorized to probe")
    oos = [_normalize(x) for x in getattr(scope, "out_of_scope", []) if x]
    for entry in probe_plan:
        for req in _entry_requests(entry):
            target = str(req.get("url") or req.get("path") or "")
            if "://" not in target:
                raise LiveScopeError(
                    f"live probe must use an absolute URL to an in-scope host (finding "
                    f"{entry.get('finding_id')!r}); got {target!r}")
            host = _host_of(target)
            if not _host_in_scope(host, matchers):
                raise LiveScopeError(
                    f"live probe targets {host!r}, which is NOT an in-scope asset (finding "
                    f"{entry.get('finding_id')!r}) — refusing to touch it")
            blob = _normalize(target)
            for t in oos:
                if t and len(t) > 3 and t in blob:
                    raise LiveScopeError(
                        f"live probe matches out-of-scope token {t!r} (finding {entry.get('finding_id')!r})")


def assert_live_write_policy(probe_plan: list[dict], *, allow_writes: bool, max_writes: int) -> None:
    """L3 state-changing policy on a LIVE host (extra rails beyond ``validate_probe_plan``):

    * **DELETE is never permitted**, even with writes enabled — destructive operations are out of bounds
      for an automated confirmation probe.
    * State-changing requests (POST/PUT/PATCH) are allowed only when ``allow_writes`` and are capped
      **separately** by ``max_writes`` — so even in write mode you cannot fire a flood of mutations.
    """
    writes = 0
    for entry in probe_plan:
        for req in _entry_requests(entry):
            method = str(req.get("method", "GET")).upper()
            if method in _LIVE_DESTRUCTIVE_METHODS:
                raise LiveWriteError(
                    f"live probe uses {method} (finding {entry.get('finding_id')!r}); destructive methods "
                    f"are never permitted on a live host, even with writes enabled")
            if method in _STATE_CHANGING_METHODS:
                if not allow_writes:
                    raise LiveWriteError(
                        f"live probe uses state-changing method {method!r} but writes are not enabled "
                        f"(finding {entry.get('finding_id')!r}); pass --allow-writes to opt in")
                writes += 1
    if writes > max_writes:
        raise LiveWriteError(
            f"live probe plan has {writes} state-changing request(s), exceeding the write cap of "
            f"{max_writes} (raise --max-writes / live_max_writes if intended)")


# ------------------------------------------------------------------------- scope filter
def out_of_scope_match(affected: list[str], out_of_scope: list[str]) -> str | None:
    """Code-side scope filter, independent of the LLM verdict.

    Returns the matching out-of-scope token if any affected reference falls under an
    explicitly excluded asset/path/feature, else ``None``. Matching is case-insensitive
    substring on normalized path separators — deliberately conservative (prefer dropping a
    borderline finding over reporting against an excluded asset).
    """
    norm_aff = [a.replace("\\", "/").lower() for a in affected]
    for token in out_of_scope:
        t = token.replace("\\", "/").strip().lower()
        if not t:
            continue
        if any(t in a for a in norm_aff):
            return token
    return None
