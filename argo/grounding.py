"""Deterministic CITATION GROUNDING (precision uplift, zero LLM calls).

A finding can cite a file, or a project-specific code symbol, that does not exist in the
target under audit — typically a reference carried over from a *different* project. This is
not hypothetical: a ds4 report draft carried a ``gguf_get_tensor`` / ``general.alignment=0``
divide-by-zero that belongs to the SEPARATE ``gguf-tools`` repo (``gguf_get_tensor`` exists
nowhere in the ds4 tree). Nothing in the pipeline verified that the cited code actually
exists in *this* repo before spending a validation session on it.

This module closes that gap cheaply and deterministically:

* **Hallucinated file** — the primary ``affected`` citation is an EXPLICIT file path whose
  basename appears nowhere in the repo -> the finding is dropped pre-validation
  (``ungrounded_citation``). This is the one unambiguous "the location does not exist" signal,
  so it is the only auto-drop here. A symbol-style citation (``auth.Session.Check()``,
  ``crate::x::y``) or an ambiguous path that maps to no unique file is only *unresolved*: it is
  kept (``unresolved_refs``; as the primary citation, confidence -1), never dropped.
* **Hallucinated symbol** — a project-specific identifier the finding presents as code (a
  call ``foo_bar(`` or a backticked ``\\`foo_bar\\```) appears nowhere in the repo. This is
  strong-but-not-certain (it could be a macro, a generated name, or a typo), so we never
  auto-drop on it: we attach a grounding note and downgrade confidence one notch, letting
  the adversarial validator make the final call with the evidence in hand.

The same pass also records two conservative warnings without auto-dropping: numeric citations past
the end of a real file, and list-like findings that may bundle three or more distinct issues. The
latter is informational only and never changes confidence, severity, or verdict.

Fail-closed on precision, but conservatively: only *project-specific-looking* identifiers
(underscore or interior capital, length >= 6, not a common word) are checked, so ordinary
stdlib/system calls (``read``, ``len``, ``strtod``) are never mistaken for hallucinations.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .ranking import split_ref

#: Source-ish files worth scanning for symbol/basename presence. Broad on purpose — a symbol
#: can legitimately be defined in a header, build file, or template.
_SOURCE_EXTS = frozenset({
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".m", ".mm", ".inc", ".zig", ".s", ".asm",
    ".py", ".pyi", ".go", ".rs", ".java", ".kt", ".scala", ".js", ".jsx", ".ts", ".tsx", ".mjs",
    ".rb", ".php", ".cs", ".swift", ".lua", ".pl", ".sh", ".sql", ".proto", ".txt", ".md",
    ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".gradle", ".xml", ".groovy", ".kts",
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


def _iter_all_files(repo_dir: Path):
    """Every regular file under ``repo_dir`` (any extension, any size, no cap), names only.

    This listing decides whether a cited file EXISTS, so it must be complete: an existence check
    bounded by a content-scan cap or an extension list drops real findings (a ``.vue`` template, a
    file past the cap of a large monorepo). ``.git`` and symlinks are skipped."""
    for dirpath, dirnames, filenames in os.walk(repo_dir, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in filenames:
            path = Path(dirpath) / name
            if not path.is_symlink():
                yield path


def _iter_source_files(repo_dir: Path):
    seen = 0
    for p in repo_dir.rglob("*"):
        if ".git" in p.parts:
            continue
        if p.is_symlink():
            continue                                  # never read through a link (may leave the root)
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


#: A dotted qualified name used as a location: ``io.moquette.persistence.SerdesUtils.readProperties()``
#: or ``SerdesUtils.readProperties`` (JVM/.NET/Python style), optionally with call parentheses.
_QUALIFIED_RE = re.compile(r"^\s*((?:[A-Za-z_$][\w$]*\.)+[A-Za-z_$][\w$]*)\s*(?:\([^)]*\))?\s*$")
#: Languages whose files are named after a dotted package/module path.
_QUALIFIED_EXTS = (".java", ".kt", ".kts", ".scala", ".groovy", ".cs", ".py")
#: The line part of a citation tail: ``:26-35``, ``:26``, ``:L30``, ``#L30``, ``:L68-L73``.
_LINE_TAIL_RE = re.compile(r"[:#]\s*L?(\d+)(?:\s*-\s*L?(\d+))?")
#: Extensions that make a citation an EXPLICIT file reference (beyond the scanned source set).
_EXPLICIT_EXTS = _SOURCE_EXTS | frozenset({
    ".vue", ".svelte", ".html", ".htm", ".erb", ".ex", ".exs", ".erl", ".dart", ".r", ".jl",
    ".hs", ".ml", ".fs", ".vb", ".cshtml", ".razor", ".tf", ".hcl", ".bat", ".ps1", ".cmake",
})


def _line_tail(text: str) -> str:
    m = _LINE_TAIL_RE.search(text or "")
    if not m:
        return ""
    return f"{m.group(1)}-{m.group(2)}" if m.group(2) else m.group(1)


def is_explicit_path(ref: str) -> bool:
    """True when a citation names a FILE (``a/b.py:7``, ``Foo.java``, ``src\\x.c``), False when it
    names a SYMBOL (``io.x.Foo.bar()``, ``crate::auth::check``, ``App\\Svc::run``, ``Auth#ok?``).

    Only an explicit file that exists nowhere is evidence of a hallucinated location; a symbol that
    does not map to a file is merely unresolved (many languages do not name files after symbols)."""
    text = (ref or "").strip()
    file = split_ref(text)[0].strip()
    if not file or "::" in file:
        return False
    if text.startswith(file) and text[len(file):].startswith("("):
        return False                                  # ``res.json()``: a call, not ``res.json``
    if "/" in file or "\\" in file:
        return True
    return Path(file).suffix.lower() in _EXPLICIT_EXTS


class RepoIndex:
    """One cheap repo pass answering 'does this basename / symbol appear anywhere?'. Built once
    per validate run and reused across every finding (O(files), not O(files * findings))."""

    def __init__(self, repo_dir: Path, symbols: set[str]):
        self.repo_dir = Path(repo_dir)
        self._root = self.repo_dir.resolve()
        self._basenames: set[str] = set()
        self._present: set[str] = set()
        self._wanted = {s for s in symbols if s}
        self._paths: dict[str, Path] = {}
        self._basename_paths: dict[str, list[Path]] = {}
        self._line_counts: dict[Path, int] = {}
        self._mention_cache: dict[tuple[str, str], bool] = {}
        combined = (re.compile(r"\b(?:%s)\b" % "|".join(re.escape(s) for s in sorted(self._wanted)))
                    if self._wanted else None)
        try:
            # Existence: the complete name listing (cheap; no content read).
            for p in _iter_all_files(self.repo_dir):
                self._basenames.add(p.name)
                try:
                    self._paths[p.relative_to(self.repo_dir).as_posix()] = p
                    self._basename_paths.setdefault(p.name, []).append(p)
                except ValueError:
                    pass
        except OSError:
            pass
        try:
            # Symbol presence: content scan, bounded (source extensions, size and file-count caps).
            for p in _iter_source_files(self.repo_dir):
                if combined is not None and self._wanted - self._present:
                    text = p.read_text(encoding="utf-8", errors="replace")
                    for hit in combined.findall(text):
                        self._present.add(hit)
        except OSError:
            pass

    def _direct_file(self, file: str) -> str | None:
        """The repo-relative POSIX path when ``file`` exists as given INSIDE the repo root."""
        try:
            path = (self.repo_dir / file.replace("\\", "/")).resolve()
            if path.is_relative_to(self._root) and path.is_file():
                return path.relative_to(self._root).as_posix()
        except (OSError, ValueError):
            pass
        return None

    def _rel(self, p: Path) -> str:
        return p.relative_to(self.repo_dir).as_posix()

    def file_grounded(self, ref: str) -> bool:
        """Grounded if the exact path exists, or (tolerating a path-prefix mismatch, e.g. the repo
        copy is rooted at a subdir) any file with the same basename exists in the tree. Ambiguous
        basenames count as grounded here (they exist); :meth:`canonical_file` decides uniqueness."""
        file, _line = split_ref(ref)
        if not file:
            return True                                   # nothing to ground
        if self._direct_file(file):
            return True
        return Path(file.replace("\\", "/")).name in self._basenames

    def resolve_path(self, file: str) -> str | None:
        """An explicit (possibly prefix-truncated) path -> the ONE repo file it names, or None.
        ``api/orders.py`` matches ``src/main/api/orders.py`` only if no other file ends that way."""
        direct = self._direct_file(file)
        if direct:
            return direct
        posix = file.replace("\\", "/")
        while posix.startswith("./"):
            posix = posix[2:]
        if not posix or posix.startswith("../") or posix.startswith("/"):
            return None
        if "/" in posix:
            hits = {rel for rel in self._paths if rel.endswith("/" + posix)}
        else:
            hits = {self._rel(p) for p in self._basename_paths.get(posix, [])}
        return hits.pop() if len(hits) == 1 else None

    def resolve_qualified(self, head: str) -> str | None:
        """Map a dotted qualified name to the ONE repo file that defines it, or None.

        ``io.moquette.persistence.SerdesUtils.readProperties()`` -> the file whose path ends in
        ``io/moquette/persistence/SerdesUtils.java``; ``pkg.login()`` -> ``pkg/__init__.py``; a bare
        ``Outer.Inner.work`` falls back to a UNIQUE ``Inner.<ext>`` then ``Outer.<ext>`` basename.
        Candidates are collected across ALL extensions before uniqueness is decided, so a
        ``Foo.java`` + ``Foo.kt`` pair is ambiguous, never resolved by extension order."""
        m = _QUALIFIED_RE.match(head or "")
        if not m:
            return None
        parts = m.group(1).split(".")
        # 1) package path, most specific first: ``a/b/Class.<ext>`` or an ``a/b/__init__.py`` package.
        #    A single segment is tried only as a lowercase module/package (``pkg.login()`` ->
        #    ``pkg/__init__.py`` / ``pkg.py``); a bare Class is matched as a basename below.
        for i in range(len(parts), 0, -1):
            stem = "/".join(parts[:i])
            if i == 1 and not stem[:1].islower():
                break
            suffixes = [stem + ext for ext in _QUALIFIED_EXTS] + [stem + "/__init__.py"]
            hits = {rel for rel in self._paths for s in suffixes if rel == s or rel.endswith("/" + s)}
            if len(hits) > 1:
                return None                               # ambiguous at the most specific level
            if hits:
                hit = hits.pop()
                return hit if i == len(parts) or self._mentions(hit, parts[i]) else None
        # 2) bare ``Class.member``: Capitalized segments right to left as a UNIQUE basename.
        for idx in range(len(parts) - 1, -1, -1):
            name = parts[idx]
            if not name[:1].isupper():
                continue
            hits = {self._rel(p) for ext in _QUALIFIED_EXTS
                    for p in self._basename_paths.get(name + ext, [])}
            if len(hits) > 1:
                return None
            if hits:
                hit = hits.pop()
                return hit if idx == len(parts) - 1 or self._mentions(hit, parts[idx + 1]) else None
        return None

    def _mentions(self, rel: str, name: str) -> bool:
        """Proof for a name-based match: the candidate file must contain the next cited member
        (``Foo.java`` for ``pkg.Foo.bar()`` must mention ``bar``). Stops ``auth.Session.Check()``
        from resolving to an unrelated ``auth.py``. Indexed files are already size-capped."""
        key = (rel, name)
        if key not in self._mention_cache:
            try:
                if self._paths[rel].stat().st_size > _FILE_BYTE_CAP:
                    raise OSError("too large to read for a name proof")
                text = self._paths[rel].read_text(encoding="utf-8", errors="replace")
                self._mention_cache[key] = re.search(rf"(?<![\w$]){re.escape(name)}(?![\w$])",
                                                     text) is not None
            except (KeyError, OSError):
                self._mention_cache[key] = False
        return self._mention_cache[key]

    def canonical_file(self, ref: str) -> str | None:
        """The ONE repo-relative file a citation points at, or None (unresolved or ambiguous)."""
        if not ref:
            return None
        if is_explicit_path(ref):
            return self.resolve_path(split_ref(ref)[0])
        return self.resolve_qualified(re.split(r"[:#]", ref, maxsplit=1)[0])

    def normalize_ref(self, ref: str) -> str:
        """Rewrite a citation into canonical ``path:lines`` when it names ONE repo file that differs
        from what was written (qualified name, prefix-truncated path); otherwise return it unchanged.
        Downstream readers (excerpts, static context) then open exactly the file grounding used."""
        if not ref:
            return ref
        explicit = is_explicit_path(ref)
        file = split_ref(ref)[0]
        if explicit and self._direct_file(file) == file.replace("\\", "/"):
            return ref                                    # already canonical: keep its description
        resolved = self.canonical_file(ref)
        if not resolved:
            return ref
        if explicit:
            idx = ref.find(file)
            tail = _line_tail(ref[idx + len(file):] if idx >= 0 else ref)
        else:
            head = re.split(r"[:#]", ref, maxsplit=1)[0]
            tail = _line_tail(ref[len(head):])
        return f"{resolved}:{tail}" if tail else resolved

    def symbol_present(self, sym: str) -> bool:
        # A symbol the index was not built to search for is given the benefit of the doubt (never
        # flagged as missing) — only a symbol we actually searched and did not find counts as absent.
        if sym not in self._wanted:
            return True
        return sym in self._present

    def line_in_range(self, ref: str) -> bool:
        """False only when a numeric citation resolves unambiguously and exceeds the file length."""
        file, line = split_ref(ref)
        if not line:
            return True
        path = self._paths.get(Path(file).as_posix())
        if path is None:
            matches = self._basename_paths.get(Path(file).name, [])
            path = matches[0] if len(matches) == 1 else None
        if path is None:
            return True
        try:
            if path.stat().st_size > _FILE_BYTE_CAP:
                return True                               # not read: never flag it out of range
            if path not in self._line_counts:
                self._line_counts[path] = len(path.read_text(
                    encoding="utf-8", errors="replace").splitlines())
            return int(line) <= self._line_counts[path]
        except (OSError, ValueError):
            return True


def composite_signal(finding) -> tuple[bool, str | None]:
    """Conservative, informational-only signal that one finding bundles 3+ distinct things."""
    files = {split_ref(ref)[0].replace("\\", "/").lower()
             for ref in (finding.affected or []) if split_ref(ref)[0]}
    if len(files) >= 3:
        return True, f"affected citations span {len(files)} distinct files/modules"
    for label, text in (("title", finding.title), ("rationale", finding.why_vulnerable)):
        for clause in re.split(r"[.!?]\s+", text or ""):
            if len(clause.split()) > 40:
                continue
            if clause.count(";") >= 2:
                return True, f"{label} contains a list of at least 3 semicolon-separated items"
            if clause.count(",") >= 2 and re.search(r"\b(?:and|or)\b", clause, re.I):
                return True, f"{label} contains a list of at least 3 comma-separated items"
            if len(re.findall(r"\b(?:and|or)\b", clause, re.I)) >= 2:
                return True, f"{label} coordinates at least 3 distinct phrases"
    return False, None


def ground_finding(index: RepoIndex, finding) -> dict:
    """Return deterministic citation and composite signals for one finding against an index."""
    refs = list(finding.affected or [])
    # Only an EXPLICIT file that exists nowhere is "missing" (hallucinated location). A symbol-style
    # citation, or a path that matches several files, is "unresolved": not proof of absence.
    missing_files = [ref for ref in refs if is_explicit_path(ref) and not index.file_grounded(ref)]
    unresolved_refs = [ref for ref in refs
                       if ref and ref not in missing_files and index.canonical_file(ref) is None]
    symbols = extract_cited_symbols(
        finding.title, finding.why_vulnerable, finding.vulnerable_flow, finding.recommended_fix,
    )
    missing_symbols = sorted(s for s in symbols if not index.symbol_present(s))
    out_of_range_lines = [ref for ref in refs
                          if index.file_grounded(ref) and not index.line_in_range(ref)]
    composite_suspect, composite_reason = composite_signal(finding)
    return {"missing_files": missing_files, "missing_symbols": missing_symbols,
            "unresolved_refs": unresolved_refs,
            "out_of_range_lines": out_of_range_lines,
            "composite_suspect": composite_suspect, "composite_reason": composite_reason}


def build_index(repo_dir: Path, findings) -> RepoIndex:
    """Build a :class:`RepoIndex` covering every symbol cited by any finding (one repo pass)."""
    symbols: set[str] = set()
    for f in findings:
        symbols |= extract_cited_symbols(
            f.title, f.why_vulnerable, f.vulnerable_flow, f.recommended_fix)
    return RepoIndex(repo_dir, symbols)
