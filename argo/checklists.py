"""Deterministic per-audit-prompt COVERAGE CHECKLIST (Phase 4 — recall + anti-drop uplift).

The archetype-keyed :mod:`argo.knowledge` index is injected once into the *recon* prompt as advisory
reference ("use the relevant classes"). That is necessary but not sufficient: a recon model can still
fail to propagate a lens (e.g. crypto-primitive quality, resource-exhaustion) into the audit prompts it
emits — which is exactly how a real run missed a 32-bit-truncated MAC and a zero-default key while the
audit foci were transport/framing/services.

This module closes that gap: it deterministically APPENDS a mandatory coverage checklist to every
generated audit prompt (mirroring :func:`argo.rendering.ensure_design_context_present`), gated on cheap
signals detected from the repo — so the memory-safety, resource-exhaustion, and crypto-primitive lenses
are ALWAYS present when they apply, regardless of what the recon model chose. It only ADDS; it never
constrains the model's own discovery.
"""

from __future__ import annotations

from pathlib import Path

#: Idempotency sentinel — the injector skips a prompt that already carries the block.
_COVERAGE_MARKER = "## MANDATORY COVERAGE CHECKLIST"

#: File extensions that mean "memory-unsafe / native" — a memory-safety sweep is mandatory.
_NATIVE_EXTS = frozenset({".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".m", ".mm", ".zig", ".s", ".asm"})

#: Path/name fragments that signal cryptographic code — a crypto-primitive sweep is mandatory.
_CRYPTO_HINTS = (
    "hmac", "sha1", "sha256", "sha512", "sha2", "sha3", "md5", "aes", "xtea", "chacha", "poly1305",
    "salsa", "curve25519", "ed25519", "rsa", "ecdsa", "cipher", "crypto", "cmac", "gcm", "kdf",
    "pbkdf", "hkdf", "csprng", "/rand", "rand_r", "nonce", "keystore", "keygen",
)

#: Cap the repo walk so detection stays cheap on large trees.
_SCAN_FILE_CAP = 6000


def _iter_repo_files(repo_dir: Path):
    seen = 0
    for p in repo_dir.rglob("*"):
        if ".git" in p.parts:
            continue
        if p.is_file():
            seen += 1
            if seen > _SCAN_FILE_CAP:
                return
            yield p


def detect_native(repo_dir: Path) -> bool:
    """True if the repo contains memory-unsafe / native source (C/C++/ObjC/Zig/asm)."""
    try:
        for p in _iter_repo_files(Path(repo_dir)):
            if p.suffix.lower() in _NATIVE_EXTS:
                return True
    except OSError:
        pass
    return False


def detect_crypto(repo_dir: Path) -> bool:
    """True if the repo appears to implement/use cryptographic primitives (by path/name heuristic)."""
    try:
        for p in _iter_repo_files(Path(repo_dir)):
            low = p.name.lower()
            parts = "/".join(part.lower() for part in p.parts)
            if any(h in low or h in parts for h in _CRYPTO_HINTS):
                return True
    except OSError:
        pass
    return False


def coverage_checklist_block(*, native: bool, has_crypto: bool) -> str:
    """The mandatory coverage lenses for a focus, gated by the detected signals.

    Always present: a resource-exhaustion / availability lens (R2) and the one-finding-per-root-cause
    reporting discipline (P1). Memory-safety (native) and crypto-primitive (crypto) lenses are added
    only when they apply, so the checklist stays relevant and never dilutes with off-target classes."""
    lines = [
        _COVERAGE_MARKER,
        "",
        "Before you finish, explicitly SWEEP for each lens below that applies to this focus and state "
        "what you checked (even if you found nothing). These are mandatory coverage — additional to, "
        "not a replacement for, your own discovery.",
        "",
        "**Reporting discipline (applies to every finding):**",
        "- ONE finding = ONE root cause. Do NOT bundle two distinct defects (e.g. a timing side channel "
        "AND a coverage gap) into a single finding — split them, so neither gets lost or under-rated.",
        "- State the build configuration it applies to (e.g. default vs a hardening flag enabled).",
        "- Classify each: a real bug regardless of trust model / a defeat of a security mechanism the "
        "project itself ships / an intended-by-design behavior.",
        "",
        "**Variant-family CENSUS — always (the #1 recall miss: reporting one instance and moving on):**",
        "- When a finding is an instance of an ENUMERABLE class, do NOT stop at one example — mechanically "
        "ENUMERATE EVERY sibling in the codebase and report or explicitly clear each. In particular census: "
        "(1) every collection/map/queue/`Vec` mutated by an untrusted-input handler (is each one bounded?); "
        "(2) every OS/desktop sink that untrusted text reaches — logs, clipboard, notifications, filesystem "
        "paths, URL/link opening, terminal escapes (is each escaped/validated?); (3) every panic/abort point "
        "reachable from untrusted input; (4) every outbound fetch of an attacker-influenced URL. Finding the "
        "class but only 1 of N members is the most common coverage gap — list N.",
        "",
        "**Availability & resource exhaustion (CWE-400/770/834/1284) — always:**",
        "- Unbounded allocation, recursion, or per-connection/per-session/per-collection state driven by an "
        "attacker-controlled size/count field; fixed pools/queues with no cap or backpressure; "
        "half-open/handshake state that survives; missing timeouts; amplification. Census EVERY server/peer-"
        "driven collection, not just the obvious one.",
        "",
        "**Secrets & credentials in sinks (CWE-532/522/200) — always:**",
        "- Trace credentials/secrets/tokens (passwords, API keys, auth/SASL, session tokens) to every "
        "logging, telemetry, error-message, cache, and outbound-request sink. Secrets must not be written to "
        "logs or sent to an attacker-influenced destination.",
        "",
        "**Outbound requests / SSRF (CWE-918/601) — if the target fetches URLs or makes outbound requests:**",
        "- For EACH fetch of an attacker-influenced URL (link previews, avatar/icon/metadata URLs, webhooks, "
        "update checks): is the destination validated (loopback / link-local / internal / cloud-metadata "
        "blocked)? are REDIRECTS re-validated per hop? is it zero-click (auto-fetched) vs user-initiated?",
    ]
    if native:
        lines += [
            "",
            "**Memory safety on untrusted input (CWE-787/125/190/191/416/415/476/681) — native code:**",
            "- Trace every attacker-controlled length/offset/count/index from each parse/RX entry point "
            "to its sink (memcpy, array index, pointer arithmetic). Check for out-of-bounds read/write, "
            "signed/unsigned and width-truncation integer bugs, `size_t` underflow on `length - header`, "
            "missing minimum-length guards, and buffer lifecycle (use-after-free / double-free / "
            "double-ownership in any pool or refcount scheme).",
        ]
    else:
        lines += [
            "",
            "**Panic / abort census (CWE-248/617/770/835/407/190) — memory-safe language:**",
            "- The language prevents most memory corruption, so the crown-jewel DoS is a PANIC / abort / hang "
            "reachable from untrusted input. Enumerate EVERY such point: `unwrap`/`expect`/`unreachable!`/"
            "`todo!`/`panic!`/`assert!`, slice/array index `[]`, division/remainder by zero, integer "
            "add/sub/mul that can overflow (panics in debug), `.parse().unwrap()`, time/`Instant`+`Duration` "
            "arithmetic, unbounded recursion, and infinite/busy loops on a closed or empty stream. Also audit "
            "every escape-hatch (`unsafe` block / FFI / reflection) reachable from untrusted input.",
        ]
    if has_crypto:
        lines += [
            "",
            "**Cryptographic primitive quality (CWE-326/327/328/916/330/331/338/294/347/208/321/1188) — "
            "crypto present:**",
            "- MAC/tag LENGTH (truncated tags) and full COVERAGE (does the MAC authenticate the header "
            "and all security-relevant fields, or only the payload?).",
            "- KEY handling: default/zero/hard-coded keys, whether an unset key fails CLOSED, KDF "
            "strength, key scope (per-node vs global shared).",
            "- Comparison of secrets/MACs must be CONSTANT-TIME (no early-exit memcmp).",
            "- RANDOMNESS: are sequence numbers, nonces, IVs, and tokens from a CSPRNG, or predictable "
            "(clock/rand seeds, reuse)?",
            "- FRESHNESS: is there replay protection (counter/nonce/timestamp) for authenticated actions?",
        ]
    return "\n".join(lines)


def ensure_coverage_checklist_present(text: str, *, native: bool, has_crypto: bool) -> str:
    """Idempotently append :func:`coverage_checklist_block` to a prompt (only ADDS; never rewrites),
    skipping if the marker is already present. Mirrors ``ensure_design_context_present``."""
    if _COVERAGE_MARKER in text:
        return text
    return text.rstrip() + "\n\n" + coverage_checklist_block(native=native, has_crypto=has_crypto) + "\n"
