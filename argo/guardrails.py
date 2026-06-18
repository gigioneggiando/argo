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
