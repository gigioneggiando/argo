"""Deterministic CITATION GROUNDING (precision uplift, zero LLM calls).

A finding can cite a file, or a project-specific code symbol, that does not exist in the
target under audit — typically a reference carried over from a *different* project. This is
not hypothetical: a ds4 report draft carried a ``gguf_get_tensor`` / ``general.alignment=0``
divide-by-zero that belongs to the SEPARATE ``gguf-tools`` repo (``gguf_get_tensor`` exists
nowhere in the ds4 tree). Nothing in the pipeline verified that the cited code actually
exists in *this* repo before spending a validation session on it.

This module closes that gap cheaply and deterministically:

* **Hallucinated file** — the primary ``affected`` path's basename appears nowhere in the
  repo -> the finding is dropped pre-validation (``ungrounded_citation``). This is the one
  unambiguous "the location does not exist" signal, so it is the only auto-drop here.
* **Hallucinated symbol** — a project-specific identifier the finding presents as code (a
  call ``foo_bar(`` or a backticked ``\\`foo_bar\\```) appears nowhere in the repo. This is
  strong-but-not-certain (it could be a macro, a generated name, or a typo), so we never
  auto-drop on it: we attach a grounding note and downgrade confidence one notch, letting
  the adversarial validator make the final call with the evidence in hand.

Fail-closed on precision, but conservatively: only *project-specific-looking* identifiers
(underscore or interior capital, length >= 6, not a common word) are checked, so ordinary
stdlib/system calls (``read``, ``len``, ``strtod``) are never mistaken for hallucinations.
"""

from __future__ import annotations

import re
from pathlib import Path

from .ranking import split_ref

#: Source-ish files worth scanning for symbol/basename presence. Broad on purpose — a symbol
#: can legitimately be defined in a header, build file, or template.
_SOURCE_EXTS = frozenset({
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".m", ".mm", ".inc", ".zig", ".s", ".asm",
    ".py", ".pyi", ".go", ".rs", ".java", ".kt", ".scala", ".js", ".jsx", ".ts", ".tsx", ".mjs",
    ".rb", ".php", ".cs", ".swift", ".lua", ".pl", ".sh", ".sql", ".proto", ".txt", ".md",
    ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".gradle", ".xml",
})

#: Cap the repo walk so grounding stays cheap on large trees (mirrors checklists._SCAN_FILE_CAP).
_SCAN_FILE_CAP = 8000
_FILE_BYTE_CAP = 2 * 1024 * 1024

#: A cited symbol must be at least this long to be checked (shorter tokens are too generic).
_SYMBOL_MIN_LEN = 6

#: Common identifiers that look call-shaped but are language/library builtins, never treated as
#: project-specific citations even if they pass the shape filter.
_STOPWORDS = frozenset({
    "assert", "printf", "sprintf", "snprintf", "malloc", "calloc", "realloc", "memcpy", "memset",
    "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "return", "static", "struct", "typedef",
    "unsigned", "extern", "sizeof", "public", "private", "protected", "function", "boolean",
    "string", "integer", "object", "buffer", "length", "values", "result", "params", "config",
    "request", "response", "handler", "context", "session", "message", "content", "default",
})

#: call-shaped: `name(`   ->   name
_CALL_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]{%d,})\s*\(" % (_SYMBOL_MIN_LEN - 1))
#: backticked: `name`  /  `name(...)`  /  `name.field`   ->   name (leading identifier only)
_BACKTICK_RE = re.compile(r"`\s*([A-Za-z_][A-Za-z0-9_]{%d,})" % (_SYMBOL_MIN_LEN - 1))


def _is_project_specific(sym: str) -> bool:
    """True for identifiers that look project-specific (a hallucinated one is a strong signal):
    an underscore or an interior capital, long enough, and not a common builtin word."""
    if len(sym) < _SYMBOL_MIN_LEN or sym.lower() in _STOPWORDS:
        return False
    has_underscore = "_" in sym.strip("_")
    has_interior_cap = any(c.isupper() for c in sym[1:])
    return has_underscore or has_interior_cap


def extract_cited_symbols(*texts: str) -> set[str]:
    """Project-specific identifiers a finding presents AS code (call-shaped or backticked)."""
    out: set[str] = set()
    for text in texts:
        if not text:
            continue
        for m in _CALL_RE.finditer(text):
            if _is_project_specific(m.group(1)):
                out.add(m.group(1))
        for m in _BACKTICK_RE.finditer(text):
            if _is_project_specific(m.group(1)):
                out.add(m.group(1))
    return out


def _iter_source_files(repo_dir: Path):
    seen = 0
    for p in repo_dir.rglob("*"):
        if ".git" in p.parts:
            continue
        if p.is_file() and p.suffix.lower() in _SOURCE_EXTS:
            try:
                if p.stat().st_size > _FILE_BYTE_CAP:
                    continue
            except OSError:
                continue
            seen += 1
            if seen > _SCAN_FILE_CAP:
                return
            yield p


class RepoIndex:
    """One cheap repo pass answering 'does this basename / symbol appear anywhere?'. Built once
    per validate run and reused across every finding (O(files), not O(files * findings))."""

    def __init__(self, repo_dir: Path, symbols: set[str]):
        self.repo_dir = Path(repo_dir)
        self._basenames: set[str] = set()
        self._present: set[str] = set()
        self._wanted = {s for s in symbols if s}
        combined = (re.compile(r"\b(?:%s)\b" % "|".join(re.escape(s) for s in sorted(self._wanted)))
                    if self._wanted else None)
        try:
            for p in _iter_source_files(self.repo_dir):
                self._basenames.add(p.name)
                if combined is not None and self._wanted - self._present:
                    text = p.read_text(encoding="utf-8", errors="replace")
                    for hit in combined.findall(text):
                        self._present.add(hit)
        except OSError:
            pass

    def file_grounded(self, ref: str) -> bool:
        """Grounded if the exact path exists, or (tolerating a path-prefix mismatch, e.g. the repo
        copy is rooted at a subdir) any file with the same basename exists in the tree."""
        file, _line = split_ref(ref)
        if not file:
            return True                                   # nothing to ground
        if (self.repo_dir / file).is_file():
            return True
        return Path(file).name in self._basenames

    def symbol_present(self, sym: str) -> bool:
        # A symbol the index was not built to search for is given the benefit of the doubt (never
        # flagged as missing) — only a symbol we actually searched and did not find counts as absent.
        if sym not in self._wanted:
            return True
        return sym in self._present


def ground_finding(index: RepoIndex, finding) -> dict:
    """Return ``{"missing_files": [...], "missing_symbols": [...]}`` for one finding against a
    prebuilt :class:`RepoIndex`. Empty lists mean fully grounded."""
    missing_files = [ref for ref in (finding.affected or []) if not index.file_grounded(ref)]
    symbols = extract_cited_symbols(
        finding.title, finding.why_vulnerable, finding.vulnerable_flow, finding.recommended_fix,
    )
    missing_symbols = sorted(s for s in symbols if not index.symbol_present(s))
    return {"missing_files": missing_files, "missing_symbols": missing_symbols}


def build_index(repo_dir: Path, findings) -> RepoIndex:
    """Build a :class:`RepoIndex` covering every symbol cited by any finding (one repo pass)."""
    symbols: set[str] = set()
    for f in findings:
        symbols |= extract_cited_symbols(
            f.title, f.why_vulnerable, f.vulnerable_flow, f.recommended_fix)
    return RepoIndex(repo_dir, symbols)
