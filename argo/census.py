"""Deterministic cross-file VARIANT CENSUS worksheet (Phase 4 — recall uplift).

The single most common recall miss, confirmed across the libcsp / halloy / ds4 cross-checks, is
reporting ONE instance of an enumerable defect class and moving on. The mandatory coverage checklist
(:mod:`argo.checklists`) already tells the auditor to "census EVERY sibling" — but that instruction is
open-ended, and an open-ended instruction is exactly what a model under-executes.

This module turns that open-ended lens into a CLOSED-ENDED worksheet: it pre-scans the repo for a
handful of cheaply- and reliably-detectable defect families (native free / copy / alloc sinks, and
panic/abort points in memory-safe languages) and injects the CONCRETE extent of each family — how many
sites, across which files — into every audit prompt. The auditor then clears a checklist ("N free()
sites across these 7 files; you reported 1 — account for the other N-1") instead of having to
rediscover the family's spread. This mirrors the ground-truth-into-the-prompt philosophy that is
Argo's biggest quality lever, and the deterministic-pre-scan pattern of
:func:`argo.checklists.detect_free_then_reparse`.

Deliberately narrow and high-precision: only families detectable by a simple lexical scan, only
emitted when a family has >= 2 members (a census is meaningless for a singleton), the file list capped
so a large tree can't bloat the prompt, and it only ever ADDS a worksheet — it never constrains the
model's own discovery.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .checklists import _NATIVE_EXTS, _iter_repo_files

#: Idempotency sentinel — the injector skips a prompt that already carries the worksheet.
_CENSUS_MARKER = "## VARIANT CENSUS WORKSHEET"

#: Memory-safe languages whose crown-jewel DoS is a panic/abort reachable from untrusted input.
_MEMSAFE_EXTS = frozenset({".rs", ".go"})

#: A family needs at least this many sites to be worth a census (a singleton is just the finding).
_MIN_FAMILY = 2

#: How many files to name per family before collapsing the tail into "+K more".
_FILE_LIST_CAP = 12

#: Per-file byte cap so one generated/vendored blob can't dominate the scan cost.
_FILE_BYTE_CAP = 600_000


@dataclass(frozen=True)
class _Family:
    key: str
    title: str
    cwe: str
    exts: frozenset[str]
    pattern: re.Pattern[str]


#: The census families. Each is a simple lexical signature with a low false-positive rate; the point is
#: an ENUMERATION lower bound the auditor must clear, not a proof of a bug at each site.
_FAMILIES: tuple[_Family, ...] = (
    _Family("free", "heap free / ownership sites", "CWE-415/416", _NATIVE_EXTS,
            re.compile(r"\bfree\s*\(")),
    _Family("copy", "unbounded copy / format sinks", "CWE-787/125/134", _NATIVE_EXTS,
            re.compile(r"\b(?:memcpy|memmove|strcpy|strncpy|strcat|stpcpy|sprintf|vsprintf)\s*\(")),
    _Family("alloc", "attacker-sized allocation sites", "CWE-770/190", _NATIVE_EXTS,
            re.compile(r"\b(?:malloc|calloc|realloc|alloca)\s*\(")),
    _Family("panic", "panic / abort points", "CWE-248/617", _MEMSAFE_EXTS,
            re.compile(r"\.unwrap\s*\(|\.expect\s*\(|\bpanic!\s*\(|\bunreachable!\s*\("
                       r"|\btodo!\s*\(|\bunimplemented!\s*\(|\bpanic\s*\(")),
)


@dataclass
class _Tally:
    count: int = 0
    files: dict[str, int] | None = None

    def __post_init__(self) -> None:
        if self.files is None:
            self.files = {}


def scan_families(repo_dir: Path) -> dict[str, _Tally]:
    """Count each census family's sites across the repo, per file. Returns ``{key: _Tally}`` for every
    family that has at least one hit (families with none are omitted). Cheap: one pass, capped walk,
    per-file byte cap, and each file is only pattern-matched against families that apply to its ext."""
    repo_dir = Path(repo_dir)
    by_ext: dict[str, list[_Family]] = {}
    for fam in _FAMILIES:
        for ext in fam.exts:
            by_ext.setdefault(ext, []).append(fam)

    tallies: dict[str, _Tally] = {}
    try:
        for p in _iter_repo_files(repo_dir):
            fams = by_ext.get(p.suffix.lower())
            if not fams:
                continue
            try:
                if p.stat().st_size > _FILE_BYTE_CAP:
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = _relpath(p, repo_dir)
            for fam in fams:
                n = len(fam.pattern.findall(text))
                if not n:
                    continue
                t = tallies.setdefault(fam.key, _Tally())
                t.count += n
                assert t.files is not None
                t.files[rel] = t.files.get(rel, 0) + n
    except OSError:
        pass
    return tallies


def _relpath(p: Path, repo_dir: Path) -> str:
    try:
        return p.relative_to(repo_dir).as_posix()
    except ValueError:
        return p.name


def census_worksheet(repo_dir: Path) -> str:
    """The concrete variant-census worksheet for a repo, or ``""`` when no family has >= 2 sites.

    Self-gating by what is actually in the tree: native families only fire on native files, the
    panic family only on memory-safe files, so a pure-Rust repo yields a panic worksheet and a C repo
    yields free/copy/alloc worksheets without any caller-supplied flags."""
    tallies = scan_families(Path(repo_dir))
    rows: list[str] = []
    for fam in _FAMILIES:                       # deterministic family order
        t = tallies.get(fam.key)
        if t is None or t.count < _MIN_FAMILY:
            continue
        assert t.files is not None
        ordered = sorted(t.files.items(), key=lambda kv: (-kv[1], kv[0]))
        named = ordered[:_FILE_LIST_CAP]
        file_str = ", ".join(f"`{name}`" for name, _ in named)
        if len(ordered) > _FILE_LIST_CAP:
            file_str += f" (+{len(ordered) - _FILE_LIST_CAP} more files)"
        rows.append(
            f"- **{fam.title} ({fam.cwe})** — {t.count} sites across {len(t.files)} files: {file_str}. "
            "Census EVERY one reachable from untrusted input; report or explicitly CLEAR each — do not "
            "stop at the first."
        )
    if not rows:
        return ""
    header = [
        _CENSUS_MARKER,
        "",
        "A deterministic pre-scan enumerated the defect FAMILIES below with their concrete extent in "
        "THIS repo. These are a lower-bound member list, NOT confirmed bugs. When any finding you write "
        "is an instance of one of these families, you MUST account for the WHOLE family — the #1 recall "
        "miss is reporting one member and moving on. State N and how many you cleared.",
        "",
    ]
    return "\n".join(header + rows)


def ensure_variant_census_present(text: str, repo_dir: Path) -> str:
    """Idempotently append :func:`census_worksheet` to a prompt (only ADDS; never rewrites), skipping
    if the marker is already present or the repo yields no censusable family. Mirrors
    :func:`argo.checklists.ensure_coverage_checklist_present`."""
    if _CENSUS_MARKER in text:
        return text
    worksheet = census_worksheet(repo_dir)
    if not worksheet:
        return text
    return text.rstrip() + "\n\n" + worksheet + "\n"
