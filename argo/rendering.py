"""Prompt rendering, the runtime artifact-contract epilogue, and manifest extraction.

The five provided assets are never modified. Two of them (``00_…meta_prompt.md`` and
``02_…validation_prompt.md``) carry ``{{UPPER_SNAKE}}`` placeholders that the orchestrator
fills by literal substitution (not Jinja — the injected values are arbitrary JSON/text and
must not be re-parsed). The third (``01_audit_prompt_template.md.j2``) is a real Jinja2
template; in the normal flow the *recon model* renders it, but :func:`render_audit_template`
is provided for tests / fallback.

The artifact-contract epilogue is orchestration glue appended at runtime: it tells the model
to write each deliverable as a separate schema-conforming file into its writable scratch cwd
and to end with a small JSON manifest indexing those files. The asset files stay pristine.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from jinja2 import Environment, StrictUndefined

_PLACEHOLDER_RE = re.compile(r"\{\{[A-Z][A-Z0-9_]*\}\}")

JINJA_ENV = Environment(undefined=StrictUndefined, autoescape=False, keep_trailing_newline=True)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def fill_placeholders(template_text: str, mapping: dict[str, str]) -> str:
    """Literal-substitute ``{{KEY}}`` tokens. Raise if any ``{{UPPER_SNAKE}}`` placeholder
    is left unresolved (no silent blanks reaching a model)."""
    out = template_text
    for key, value in mapping.items():
        out = out.replace("{{" + key + "}}", value)
    leftovers = sorted(set(_PLACEHOLDER_RE.findall(out)))
    if leftovers:
        raise ValueError(f"Unresolved placeholders after fill: {leftovers}")
    return out


def render_audit_template(ctx: dict, prompts_dir: Path) -> str:
    """Render ``01_audit_prompt_template.md.j2`` with StrictUndefined (any missing slot
    raises rather than emitting a blank)."""
    text = (prompts_dir / "01_audit_prompt_template.md.j2").read_text(encoding="utf-8")
    return JINJA_ENV.from_string(text).render(**ctx)


# --------------------------------------------------- design context / impact discipline
#: Idempotency sentinel: the deterministic injector skips a prompt that already carries the block.
_DESIGN_CONTEXT_MARKER = "## DESIGN CONTEXT & IMPACT DISCIPLINE"


def design_context_block(accepted_risks: str | None = None) -> str:
    """Runtime-injected section that (1) enforces impact discipline on EVERY audit/validation
    (report proven impact, not reflexive escalation — the 'IMDS-angle' over-claim), and (2), when
    provided, lists the target's accepted-by-design behaviors so they are not reported as bugs.

    Single source of truth for both #3 (impact discipline) and #1 (design context); injected into
    the audit prompts (via recon) and the validate/corroborate prompts."""
    lines = [
        _DESIGN_CONTEXT_MARKER,
        "",
        "**Impact discipline — report PROVEN impact, not reflexive escalation.**",
        "- Claim only the impact you can support from the code and the target's actual deployment. "
        "Separate PROVEN impact from SPECULATIVE escalation, and label speculation as such.",
        "- Do NOT assert reachability of cloud metadata / IMDS (e.g. `169.254.169.254`), internal "
        "services, or credential theft for an SSRF unless the code or deployment topology actually "
        "shows it is reachable. Absent that evidence, describe it as a *theoretical* escalation, "
        "not confirmed impact, and do not inflate severity on its basis.",
        "- A capability available only to a trusted, authenticated ADMINISTRATOR is usually the "
        "product's intended trust boundary, not a vulnerability, unless it crosses a privilege or "
        "tenancy boundary the design does not intend. Treat \"an admin can do an admin thing\" as by "
        "design.",
        "- Prefer under-claiming to over-claiming: an honest \"needs verification\" beats a confident "
        "wrong impact.",
        "- Severity symmetry (the counterpart to the rule above — do NOT UNDER-claim either). When a "
        "finding DEFEATS a security mechanism the project itself ships or documents — authentication, "
        "a MAC/HMAC, encryption, access control, randomness used for security, or replay protection — "
        "rate it by the security property it breaks. Do NOT downgrade a real cryptographic, "
        "authentication, or memory-safety weakness to \"informational hardening\" merely because "
        "exploitation needs on-path/adjacent access or the trust model is only partial. A weak-but-"
        "shipped defense that fails is a vulnerability, not a nice-to-have.",
        "- BUT first confirm the mechanism is CURRENT and relied upon. A control the project documents or "
        "treats as deprecated, legacy, off-by-default, vestigial, or kept only for backward "
        "compatibility (and that maintainers may intend to remove) is NOT a live security boundary — "
        "defects in it are low-value hardening notes, not vulnerabilities. When unsure whether a "
        "mechanism is load-bearing, say so rather than assuming it is.",
        "- Purpose-is-the-feature. A component whose DOCUMENTED PURPOSE *is* the flagged behavior — a "
        "debug/management memory read/write primitive (peek/poke), a \"run arbitrary command/query\" "
        "feature, an eval/exec surface behind an intended privilege — is working as designed, not a "
        "vulnerability. Report it only as a hardening note, and only if it crosses a privilege/tenancy "
        "boundary the design does not intend; never inflate \"the feature does what it says\" to "
        "Critical/High.",
        "- BUT purpose-is-the-feature only covers the OPERATOR/caller DIRECTLY invoking the feature "
        "through its intended channel (the CLI flag, the authenticated admin call, the API the design "
        "documents). It does NOT cover the same capability being reached SILENTLY through a DATA channel "
        "the design does not imply is executable — e.g. a shareable CONFIG FILE, recipe, template, "
        "plugin manifest, or a DESERIALIZED saved-state file that reconstructs the exec/command/write "
        "feature (config→exec / deserialization→exec). Loading a document/config/recipe/session that "
        "silently runs a command, writes an arbitrary file, or flips the tool into a dangerous mode IS a "
        "trust-boundary crossing and a real finding (rate by impact, note the precondition that the "
        "operator loads an untrusted such file). Do NOT drop it as \"the tool can run commands anyway\" "
        "— \"the operator typed --exec\" and \"a downloaded recipe reconstructed --exec\" are different "
        "actors crossing a boundary the format's users do not expect to be executable. This is the "
        "single most common way this carve-out is over-applied: silently discarding a config/deser→exec "
        "finding because the underlying capability is by-design when invoked directly.",
        "- Trusted-bus / embedded threat models. On a system whose stated model is a trusted bus or no "
        "network-level authentication (common in firmware, industrial, avionics, automotive, and "
        "embedded protocols), the ABSENCE of authentication on management / command / memory-access "
        "functions is typically BY DESIGN — maintainers get these reports constantly and reject them. "
        "Lead with memory-safety and stability defects (out-of-bounds, use-after-free, double-free, "
        "integer/overflow, unbounded copies): they hold regardless of the trust model and are what such "
        "maintainers actually action.",
        "- Niche/opt-in component is NOT a severity dampener once it's reachable. A carve-out that says "
        "\"this component is documented as dev/test-only\" or \"niche/uncommonly deployed\" answers "
        "ONLY the question of whether to report the finding at all (weigh realistic reachability before "
        "flagging) — it does NOT, by itself, justify downgrading severity once wire-reachability and "
        "impact ARE confirmed. \"How commonly is this configuration chosen\" and \"how bad is it once "
        "chosen\" are different axes: rate severity strictly by the confirmed impact (e.g. an arbitrary "
        "file-write / cross-instance message-forgery primitive is High/Critical regardless of how niche "
        "the enabling feature is), and use the niche/opt-in framing only in the exploit-scenario "
        "preconditions, never as a severity multiplier.",
    ]
    if accepted_risks and accepted_risks.strip():
        lines += [
            "",
            "**Accepted-by-design behaviors for THIS target — do NOT report these as vulnerabilities.**",
            "The maintainers consider the following intentional / accepted risk. If a finding matches "
            "one of these, do not raise it as a bug; if you must mention it, mark it explicitly as "
            "accepted-by-design (not a vulnerability):",
            "",
            accepted_risks.strip(),
        ]
    return "\n".join(lines)


def ensure_design_context_present(text: str, accepted_risks: str | None = None) -> str:
    """Idempotently append :func:`design_context_block` to a prompt (only ADDS; never rewrites),
    skipping if the block's marker is already present. Mirrors ``ensure_prohibited_present``."""
    if _DESIGN_CONTEXT_MARKER in text:
        return text
    return text.rstrip() + "\n\n" + design_context_block(accepted_risks) + "\n"


# ----------------------------------------------------------------- artifact contract
def with_artifact_contract(
    prompt: str,
    *,
    artifacts: list[dict],
    extra_rules: list[str] | None = None,
) -> str:
    """Append the runtime output contract to a rendered prompt.

    ``artifacts`` is a list of ``{"type", "filename", "schema", "desc"}`` describing the
    files the model must write into its current working directory.
    """
    lines: list[str] = [
        prompt.rstrip(),
        "",
        "---",
        "",
        "## ORCHESTRATOR OUTPUT CONTRACT (read carefully — enforced by the pipeline)",
        "",
        "Your current working directory is a WRITABLE scratch directory dedicated to this "
        "session. The target repository is mounted READ-ONLY; you may read it but never "
        "write to it. Do NOT contact, scan, or exercise any live host. Do NOT write outside "
        "your working directory.",
        "",
        "Write each deliverable below as a SEPARATE file in your working directory "
        "(not nested, exact filename), each conforming to its stated schema:",
        "",
    ]
    for a in artifacts:
        schema = f" — must conform to `{a['schema']}`" if a.get("schema") else ""
        lines.append(f"- `{a['filename']}` ({a['type']}){schema}: {a.get('desc', '')}")
    for rule in extra_rules or []:
        lines.append(f"- {rule}")
    lines += [
        "",
        "When finished, end your FINAL message with exactly one fenced ```json block — a "
        "small manifest indexing the files you wrote (NOT the artifact contents, which stay "
        "in the files):",
        "",
        "```json",
        "{",
        '  "artifacts": [',
        '    {"type": "<artifact type>", "path": "<relative filename you wrote>", '
        '"status": "ok|partial|skipped"}',
        "  ],",
        '  "session_status": "complete|partial|failed"',
        "}",
        "```",
        "",
        "The manifest is only an index: the pipeline reads and validates the FILES, not this "
        "block. If you could not finish, still write whatever partial files you produced and "
        'mark them "partial".',
    ]
    return "\n".join(lines)


# ----------------------------------------------------------------- manifest extraction
_JSON_BLOCK_RE = re.compile(r"```json\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def extract_manifest(text: str) -> dict | None:
    """Return the parsed manifest from the LAST ```json block in the model's final message,
    or ``None`` if absent/unparseable. The orchestrator falls back to globbing the scratch
    dir when this returns ``None``."""
    if not text:
        return None
    blocks = _JSON_BLOCK_RE.findall(text)
    for block in reversed(blocks):
        try:
            data = json.loads(block)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and "artifacts" in data:
            return data
    return None
