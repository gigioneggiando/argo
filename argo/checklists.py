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

import re
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


#: `free(EXPR)` capturing a plausible lvalue (a var, a struct member `a->b`/`a.b`, an element `a[i]`).
_FREE_CALL_RE = re.compile(r"\bfree\s*\(\s*([A-Za-z_][A-Za-z0-9_.\[\]]*(?:->[A-Za-z_][A-Za-z0-9_.\[\]]*)*)\s*\)")
#: How many lines after a `free()` to look for the tell-tale re-address of the freed lvalue.
_FREE_REUSE_WINDOW = 4


def detect_free_then_reparse(repo_dir: Path) -> bool:
    """True if the native code contains the specific double-free / UAF idiom that a plain
    memory-safety sweep tends to miss: ``free(x)`` followed shortly by ``&x`` (the address of the
    just-freed lvalue passed into a function — typically a re-parse) with NO ``x = NULL`` in between.

    This is exactly the shape of a real Critical that all-but-one audit pass missed: ``free(r->model)``
    then ``json_string(&p, &r->model)`` where ``json_string`` can return false WITHOUT writing
    ``r->model``, leaving it a dangling freed pointer that a later cleanup frees again. Deliberately
    NARROW (requires the ``&x`` re-address, not a plain ``x = ...`` reassign, which is usually safe),
    so it is high-signal and low-noise. Cheap: first match wins; caps the walk."""
    try:
        for p in _iter_repo_files(Path(repo_dir)):
            if p.suffix.lower() not in _NATIVE_EXTS:
                continue
            try:
                lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines):
                m = _FREE_CALL_RE.search(line)
                if not m:
                    continue
                expr = m.group(1)
                addr = re.compile(r"&\s*" + re.escape(expr) + r"\b")
                nulled = re.compile(re.escape(expr) + r"\s*=\s*(?:NULL|nullptr|0)\b")
                for w in lines[i + 1:i + 1 + _FREE_REUSE_WINDOW]:
                    if nulled.search(w):
                        break                       # reset to NULL: this site is safe
                    if addr.search(w):
                        return True                 # freed lvalue re-addressed without nulling
    except OSError:
        pass
    return False


def coverage_checklist_block(*, native: bool, has_crypto: bool, free_reparse: bool = False) -> str:
    """The mandatory coverage lenses for a focus, gated by the detected signals.

    Always present: a resource-exhaustion / availability lens (R2) and the one-finding-per-root-cause
    reporting discipline (P1). Memory-safety (native) and crypto-primitive (crypto) lenses are added
    only when they apply, so the checklist stays relevant and never dilutes with off-target classes.
    ``free_reparse`` (a deterministic pre-scan hit for the free-then-re-address double-free idiom)
    escalates that specific idiom to a high-signal callout within the native lens."""
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
        "",
        "**Substitute-then-parse sinks — census BOTH failure modes (CWE-88/78/74/1284 + CWE-248):**",
        "- Whenever untrusted input is STRING-SUBSTITUTED into a command / argv template / query / path / "
        "format string and the result is THEN parsed, split, or tokenized (e.g. interpolate a value then "
        "`shell_words::split` / `Command`, build a query string then parse it, join a path then normalize), "
        "report BOTH defects, not just the one you notice first: (a) INJECTION — the substituted value "
        "crosses a token/argument/statement boundary it shouldn't (argument injection, command injection, "
        "query/template injection), because substitution happened BEFORE tokenization; AND (b) the "
        "PANIC/error — the post-substitution parse/split fails on a hostile value (unbalanced quote, bad "
        "escape) and is `unwrap()`ed/asserted. Catching only the panic and missing the injection (or vice "
        "versa) at the same sink is a recurring one-finding-per-root-cause miss.",
        "",
        "**Insecure defaults & FAIL-OPEN (CWE-1188/453/636/276/306/862) — config & access-control "
        "defaults — always:**",
        "- Enumerate every security-relevant DEFAULT and fallback the project ships and ask, for each, "
        "whether it fails OPEN. Census in particular: (1) FAIL-OPEN ON LOAD/PARSE FAILURE — when an "
        "authenticator / authorizer / TLS / crypto / policy component is CONFIGURED but fails to load, "
        "returns null, or throws, does the code fall back to a PERMISSIVE default (allow-all / accept-all "
        "/ plaintext / no-verify) instead of failing CLOSED? This fires precisely when the operator "
        "BELIEVES security is enforced, so report it even when the happy path is secure. (2) DEFAULT-OPEN "
        "SURFACE — does the shipped default leave a powerful surface (control/admin API, management/config "
        "endpoint, metrics, pprof/debug) UNAUTHENTICATED or bound to all interfaces, especially under a "
        "non-default auth mode (e.g. an exclude/allow list that silently skips the API, or auth that only "
        "gates the data plane not the control plane)? (3) SURPRISING PERMISSIVE DEFAULT — is anonymous / "
        "allow-all / no-encryption the default, and is that surprising given the project otherwise ships a "
        "security feature? State the exact default value and the config that would harden it.",
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
            "- **free-then-reparse / free-then-reuse without nulling (CWE-415/416)** — a specific idiom a "
            "generic lifecycle sweep misses: for EVERY `free(x)` (or a project free wrapper), check "
            "whether `x` is set to NULL right after. If not, trace whether any later path can `free(x)` "
            "AGAIN or dereference `x`. Watch especially for `free(obj->field); parse_into(&obj->field)` "
            "where the re-parse can FAIL and leave `obj->field` holding the stale freed pointer, so a "
            "later cleanup `free(obj->field)` double-frees. A SIBLING site that DOES null after free is "
            "proof this one is an inconsistency, not design — census every free of a heap field reachable "
            "from untrusted input, and report each unnulled one.",
            "- **output parameter left unwritten on an error/false return (CWE-457/824/416)** — for EVERY "
            "helper `bool f(..., T *out)` that can `return false`/error early, check it writes `*out` on "
            "THAT path too. If it returns false WITHOUT writing `*out`, the caller keeps its previous "
            "value; and if the caller had just `free()`d that variable expecting `f` to overwrite it, the "
            "value is now a dangling freed pointer. (This is precisely how a non-string JSON value fed to "
            "a `json_string(&out)` helper can leave a freed pointer live before a second free.)",
        ]
        if free_reparse:
            lines += [
                "- **>>> HIGH-SIGNAL: a deterministic pre-scan already found at least one `free(x)` "
                "followed by `&x` with no `x = NULL` in between in THIS repo.** That is the exact "
                "free-then-re-address double-free shape above. Locate every such site, confirm whether the "
                "re-address target is written on ALL return paths of the callee, and treat an unnulled one "
                "reachable from untrusted input as a probable Critical until proven otherwise.",
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


def ensure_coverage_checklist_present(text: str, *, native: bool, has_crypto: bool,
                                      free_reparse: bool = False) -> str:
    """Idempotently append :func:`coverage_checklist_block` to a prompt (only ADDS; never rewrites),
    skipping if the marker is already present. Mirrors ``ensure_design_context_present``."""
    if _COVERAGE_MARKER in text:
        return text
    return (text.rstrip() + "\n\n"
            + coverage_checklist_block(native=native, has_crypto=has_crypto, free_reparse=free_reparse)
            + "\n")
