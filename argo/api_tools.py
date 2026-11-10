"""Model-facing file tools shared by Argo's API-native runners (``mistral-api``, ``deepseek-api``)
and the Vibe artifact writer.

The model only *proposes* tool calls; Argo executes them here, so this module is the whole
security boundary of those backends. Capabilities:

  * ``read_file`` / ``list_dir`` / ``glob`` / ``grep`` -- read-only, confined to the audited repo
    copy and the session scratch dir;
  * ``write_file`` -- scratch dir only, only when the stage grants ``Write``, size-capped, JSON
    validated before commit, atomically replaced through an unpredictable temp file.

There is no shell, process, git, network or subagent tool.

Threat model. Argo creates the roots; the model, the audited source and the artifacts are
untrusted input. Paths are checked lexically first (no Windows UNC/device namespaces, reserved
device names or alternate data streams), then resolved with ``realpath`` (symlinks, junctions) and
confined to the roots. Writes re-verify the directory holding their temp file before committing,
so a link planted in the scratch dir -- or a parent swapped for one between check and use -- does
not redirect them; on failure only the temp file this call created is removed. This is a tool
boundary, not an OS sandbox: a hostile process with the same privileges that rewrites the
filesystem around every syscall is out of scope.

Bounds. Every result is capped (lines, bytes, entries, matches). A read scans at most
``MAX_READ_SCAN_BYTES`` per call and never holds an unbounded physical line in memory. Regex
matching uses the ``regex`` package's matching timeout per search plus a per-call total, both
clipped to the session deadline; oversized patterns and repeat counts are refused before
compiling. These are cooperative limits: they cannot interrupt a syscall blocked in the kernel.
"""
from __future__ import annotations

import fnmatch
import os
import re
import stat
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import regex

from .tool_errors import ToolError, validate_json_content

# --- caps (bounded tool results keep one session's context and cost predictable) ---------------
MAX_READ_LINES = 2000
MAX_READ_BYTES = 256 * 1024             # displayed output per read_file call
MAX_READ_SCAN_BYTES = 8 * 1024 * 1024   # physical bytes one read_file call may scan
MAX_LINE_CHARS = 2000
MAX_LIST_ENTRIES = 500
MAX_GLOB_RESULTS = 300
MAX_GREP_MATCHES = 200
MAX_GREP_FILE_BYTES = 2 * 1024 * 1024
MAX_GREP_FILES = 20000                  # files (and listed entries) one walk may visit
MAX_WRITE_BYTES = 4 * 1024 * 1024
MAX_TOOL_RESULT_CHARS = 60_000
MAX_PATTERN_CHARS = 2048
MAX_REPEAT_COUNT = 1000                 # largest {n,m} bound accepted in a grep pattern
REGEX_MATCH_TIMEOUT_S = 0.05            # one search over one line
GREP_TOTAL_TIMEOUT_S = 2.0              # one grep call
_LINE_HEAD_BYTES = MAX_LINE_CHARS * 4   # utf-8: enough bytes for MAX_LINE_CHARS characters
_SKIP_CHUNK = 64 * 1024
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "target", "dist", "build"}
_WIN_RESERVED = {"con", "prn", "aux", "nul", "conin$", "conout$",
                 *(f"com{i}" for i in range(10)), *(f"lpt{i}" for i in range(10)),
                 *(f"com{c}" for c in "¹²³"), *(f"lpt{c}" for c in "¹²³")}
_TRUNCATED_NOTE = "\n...[tool output truncated]"

# Argument contract per tool: name -> {arg: (type, required)}. bool is never accepted as an int.
_ARG_SPEC: dict[str, dict[str, tuple[type, bool]]] = {
    "read_file": {"path": (str, True), "offset": (int, False), "limit": (int, False)},
    "list_dir": {"path": (str, False)},
    "glob": {"pattern": (str, True), "path": (str, False)},
    "grep": {"pattern": (str, True), "path": (str, False), "glob": (str, False),
             "ignore_case": (bool, False), "max_results": (int, False)},
    "write_file": {"path": (str, True), "content": (str, True)},
}


def bound_tool_result(text: str) -> str:
    """Cap one tool result before it enters the conversation."""
    if len(text) > MAX_TOOL_RESULT_CHARS:
        return text[:MAX_TOOL_RESULT_CHARS] + _TRUNCATED_NOTE
    return text


def _coerce(name: str, key: str, value, kind: type):
    if kind is int:
        if isinstance(value, bool):
            raise ToolError(f"bad arguments for {name}: {key} must be an integer")
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip().isdigit() and len(value.strip()) <= 12:
            return int(value.strip())                 # models sometimes quote small integers
        raise ToolError(f"bad arguments for {name}: {key} must be an integer")
    if not isinstance(value, kind):
        raise ToolError(f"bad arguments for {name}: {key} must be a {kind.__name__}")
    return value


def _validate_args(name: str, args: dict) -> dict:
    spec = _ARG_SPEC[name]
    unexpected = sorted(k for k in args if k not in spec)
    if unexpected:
        shown = ", ".join(repr(k)[:40] for k in unexpected[:5])
        raise ToolError(f"bad arguments for {name}: unexpected {shown}; "
                        f"allowed: {', '.join(spec)}")
    clean = {}
    for key, (kind, required) in spec.items():
        if key not in args or args[key] is None:
            if required:
                raise ToolError(f"bad arguments for {name}: missing required {key!r}")
            continue
        clean[key] = _coerce(name, key, args[key], kind)
    return clean


def _scan_repeat_counts(pattern: str) -> None:
    """Refuse ``{n}``/``{n,m}`` quantifiers above MAX_REPEAT_COUNT before compiling (compile and
    match cost grow with them). Escaped braces are literals and are ignored."""
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "{":
            m = re.match(r"\{\s*(\d*)\s*(?:,\s*(\d*)\s*)?\}", pattern[i:])
            if m:
                for bound in m.groups():
                    if bound and (len(bound) > 6 or int(bound) > MAX_REPEAT_COUNT):
                        raise ToolError(f"pattern repeat count too large (max {MAX_REPEAT_COUNT}); "
                                        "use a simpler pattern")
                i += m.end()
                continue
        i += 1


def compile_pattern(pattern, ignore_case: bool = False):
    if not isinstance(pattern, str) or not pattern:
        raise ToolError("pattern is required")
    if len(pattern) > MAX_PATTERN_CHARS:
        raise ToolError(f"pattern too long ({len(pattern)} > {MAX_PATTERN_CHARS} characters)")
    _scan_repeat_counts(pattern)
    try:
        return regex.compile(pattern, (regex.IGNORECASE if ignore_case else 0) | regex.VERSION0)
    except (regex.error, ValueError, OverflowError) as exc:
        raise ToolError(f"invalid regex: {exc}") from None


# ============================================================================== tool dispatcher
@dataclass
class Toolbox:
    repo_dir: Path | None
    work_dir: Path
    allow_write: bool
    deadline: float | None = None                     # time.monotonic() of the session deadline
    cancel_event: threading.Event | None = None

    def __post_init__(self):
        self.work_real = Path(os.path.realpath(self.work_dir))
        self.repo_real = Path(os.path.realpath(self.repo_dir)) if self.repo_dir else None
        self.roots = [r for r in (self.work_real, self.repo_real) if r is not None]

    # -- liveness ---------------------------------------------------------------------------
    def _live(self) -> None:
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise ToolError("cancelled: the session is stopping")
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise ToolError("session deadline reached: no further tool work")

    def _time_left(self, cap: float) -> float:
        if self.deadline is None:
            return cap
        return min(cap, self.deadline - time.monotonic())

    # -- path policy ------------------------------------------------------------------------
    @staticmethod
    def _inside(path: Path, root: Path) -> bool:
        try:
            return os.path.commonpath([os.path.normcase(str(path)), os.path.normcase(str(root))]) \
                == os.path.normcase(str(root))
        except ValueError:                      # different drives on Windows
            return False

    def _in_roots(self, real: Path) -> bool:
        return any(self._inside(real, root) for root in self.roots)

    @staticmethod
    def _lexical(raw) -> str:
        """Reject paths whose meaning is not a plain local file before anything resolves them."""
        if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
            raise ToolError("path must be a non-empty string")
        s = raw.strip()
        if os.name == "nt":
            if s.startswith(("\\\\", "//", "\\/", "/\\")):
                raise ToolError(f"access denied: {raw[:200]} is a UNC or device path")
            for idx, part in enumerate(re.split(r"[\\/]+", s)):
                if idx == 0 and len(part) == 2 and part[1] == ":" and part[0].isalpha():
                    continue                    # drive letter of an absolute path
                if ":" in part:
                    raise ToolError(f"access denied: {raw[:200]} names an alternate data stream "
                                    "or a drive-relative path")
                stem = part.split(".", 1)[0].rstrip(" ").lower()
                if stem in _WIN_RESERVED:
                    raise ToolError(f"access denied: {raw[:200]} is a reserved device name")
        return s

    def _resolve_read(self, raw) -> Path:
        p = Path(self._lexical(raw))
        candidates = [p] if p.is_absolute() else [self.work_real / p] + (
            [self.repo_real / p] if self.repo_real else [])
        for cand in candidates:
            real = Path(os.path.realpath(cand))
            if self._in_roots(real) and real.exists():
                return real
        for cand in candidates:                 # report the precise reason
            real = Path(os.path.realpath(cand))
            if not self._in_roots(real):
                raise ToolError(f"access denied: {raw} is outside the repository and the "
                                "working directory")
        raise ToolError(f"not found: {raw}")

    def _resolve_write(self, raw) -> Path:
        if not self.allow_write:
            raise ToolError("write_file is not available in this stage")
        p = Path(self._lexical(raw))
        if p.name in ("", ".", "..") or raw.strip().endswith(("/", "\\")):
            raise ToolError("path must name a file")
        target = p if p.is_absolute() else self.work_real / p
        parent_real = Path(os.path.realpath(target.parent))
        if not self._inside(parent_real, self.work_real):
            raise ToolError("access denied: files may only be written inside the working "
                            f"directory {self.work_real}")
        final = parent_real / target.name
        rel = Path(os.path.relpath(final, self.work_real)) if self._inside(final, self.work_real) \
            else None
        if rel is None or any(part.lower() == ".git" for part in rel.parts):
            raise ToolError("access denied: refusing to write a .git path")
        if final.is_symlink():
            raise ToolError("access denied: refusing to write through a symlink")
        if self.repo_real and self._inside(Path(os.path.realpath(final)), self.repo_real):
            raise ToolError("access denied: the repository is read-only")
        return final

    def _open_regular(self, real: Path, shown: str):
        """Open a resolved path for binary reading; refuse non-regular files and a path whose
        target changed between resolution and open."""
        try:
            fh = open(real, "rb")
        except OSError as exc:
            raise ToolError(f"cannot read {shown}: {type(exc).__name__}") from None
        try:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise ToolError(f"{shown} is not a regular file")
            again = Path(os.path.realpath(real))
            cur = os.stat(again)
            if not self._in_roots(again) or (cur.st_dev, cur.st_ino) != (st.st_dev, st.st_ino):
                raise ToolError(f"access denied: {shown} changed while it was being opened")
        except BaseException:
            fh.close()
            raise
        return fh

    def _display(self, p: Path) -> str:
        return str(p)

    # -- walking ----------------------------------------------------------------------------
    def _walk(self, base: Path, state: dict):
        """Yield regular, non-link files under ``base`` that stay inside the roots. Sets
        ``state['truncated']`` when the MAX_GREP_FILES visit cap stops the walk."""
        count = 0
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            self._live()
            keep = []
            for name in sorted(dirnames):
                if name in _SKIP_DIRS:
                    continue
                sub = Path(dirpath) / name
                if sub.is_symlink() or _is_junction(sub) \
                        or not self._in_roots(Path(os.path.realpath(sub))):
                    continue                    # links/junctions may lead outside the roots
                keep.append(name)
            dirnames[:] = keep
            for name in sorted(filenames):
                path = Path(dirpath) / name
                if path.is_symlink():            # may point outside the allowed roots
                    continue
                count += 1
                if count > MAX_GREP_FILES:
                    state["truncated"] = True
                    return
                yield path

    @staticmethod
    def _walk_note(state: dict) -> str:
        return (f"\n... [further files omitted: the walk stopped after {MAX_GREP_FILES} files; "
                "narrow the path]") if state.get("truncated") else ""

    # -- tools ------------------------------------------------------------------------------
    def read_file(self, path: str, offset: int = 1, limit: int = MAX_READ_LINES) -> str:
        self._live()
        f = self._resolve_read(path)
        if f.is_dir():
            raise ToolError(f"{path} is a directory; use list_dir")
        offset = max(1, int(offset or 1))
        limit = max(1, min(int(limit or MAX_READ_LINES), MAX_READ_LINES))
        out, size, scanned, n = [], 0, 0, 0
        with self._open_regular(f, path) as fh:
            while True:
                head = fh.readline(_LINE_HEAD_BYTES)
                if not head:
                    break
                n += 1
                if n >= offset and (n >= offset + limit or size > MAX_READ_BYTES):
                    out.append(f"... [truncated at line {n - 1}; use offset={n} to continue]")
                    break
                scanned += len(head)
                complete = head.endswith(b"\n")
                tail = False
                while not complete and scanned <= MAX_READ_SCAN_BYTES:
                    chunk = fh.readline(_SKIP_CHUNK)    # skip the rest of an over-long line
                    if not chunk:
                        break
                    tail = True
                    scanned += len(chunk)
                    complete = chunk.endswith(b"\n")
                if n >= offset:
                    line = head.decode("utf-8", errors="replace").rstrip("\r\n")
                    if tail or len(line) > MAX_LINE_CHARS:
                        line = line[:MAX_LINE_CHARS] + " ...[line truncated]"
                    out.append(f"{n:6}\t{line}")
                    size += len(line) + 8
                if scanned > MAX_READ_SCAN_BYTES:
                    where = (f"before reaching offset={offset}" if n < offset
                             else f"at line {n}")
                    out.append(f"... [scan limit: stopped after reading {MAX_READ_SCAN_BYTES} "
                               f"bytes {where}; use grep to locate the region]")
                    break
        return "\n".join(out) if out else "(empty file or offset past end)"

    def list_dir(self, path: str = ".") -> str:
        self._live()
        d = self._resolve_read(path or ".")
        if not d.is_dir():
            raise ToolError(f"{path} is not a directory")
        entries, more = [], False
        with os.scandir(d) as it:
            for e in it:
                if len(entries) >= MAX_GREP_FILES:
                    more = True
                    break
                entries.append(e)
        entries.sort(key=lambda e: (not e.is_dir(follow_symlinks=False), e.name))
        lines = [f"{e.name}/" if e.is_dir(follow_symlinks=False) else e.name
                 for e in entries[:MAX_LIST_ENTRIES]]
        if more:
            lines.append("... [more entries omitted]")
        elif len(entries) > MAX_LIST_ENTRIES:
            lines.append(f"... [{len(entries) - MAX_LIST_ENTRIES} more entries]")
        return f"{d}:\n" + ("\n".join(lines) if lines else "(empty)")

    def glob(self, pattern: str, path: str | None = None) -> str:
        self._live()
        if not pattern:
            raise ToolError("pattern is required")
        base = self._resolve_read(path) if path else (self.repo_real or self.work_real)
        if not base.is_dir():
            raise ToolError(f"{path} is not a directory")
        pat = pattern.replace("\\", "/")
        hits, state = [], {}
        for f in self._walk(base, state):
            rel = f.relative_to(base).as_posix()
            if fnmatch.fnmatch(rel, pat) or ("/" not in pat and fnmatch.fnmatch(f.name, pat)) \
                    or (pat.startswith("**/") and fnmatch.fnmatch(rel, pat[3:])):
                hits.append(str(f))
                if len(hits) >= MAX_GLOB_RESULTS:
                    hits.append(f"... [stopped at {MAX_GLOB_RESULTS} results; narrow the pattern]")
                    return "\n".join(hits)
        return ("\n".join(hits) if hits else "(no matches)") + self._walk_note(state)

    def grep(self, pattern: str, path: str | None = None, glob: str | None = None,
             ignore_case: bool = False, max_results: int = MAX_GREP_MATCHES) -> str:
        self._live()
        rx = compile_pattern(pattern, bool(ignore_case))
        base = self._resolve_read(path) if path else (self.repo_real or self.work_real)
        state: dict = {}
        files = [base] if base.is_file() else self._walk(base, state)
        cap = max(1, min(int(max_results or MAX_GREP_MATCHES), MAX_GREP_MATCHES))
        stop_at = time.monotonic() + self._time_left(GREP_TOTAL_TIMEOUT_S)
        out = []
        for f in files:
            self._live()
            if time.monotonic() >= stop_at:
                out.append("... [stopped at the grep time limit; narrow the path or pattern]")
                return "\n".join(out)
            if glob and not (fnmatch.fnmatch(f.name, glob)
                             or fnmatch.fnmatch(f.as_posix(), "*" + glob.lstrip("*"))):
                continue
            try:
                if f.stat().st_size > MAX_GREP_FILE_BYTES:
                    continue
                real = Path(os.path.realpath(f))
                if not self._in_roots(real):
                    continue
                with self._open_regular(real, str(f)) as fh:
                    text = fh.read(MAX_GREP_FILE_BYTES + 1).decode("utf-8", errors="strict")
            except (UnicodeDecodeError, OSError, ToolError):
                continue                        # binary, unreadable, or not a regular file
            lines = text.split("\n")            # same line numbering as read_file
            if lines and lines[-1] == "":
                lines.pop()
            for n, line in enumerate(lines, start=1):
                line = line.rstrip("\r")
                left = stop_at - time.monotonic()
                if left <= 0:
                    out.append("... [stopped at the grep time limit; narrow the path or pattern]")
                    return "\n".join(out)
                try:
                    hit = rx.search(line, timeout=min(REGEX_MATCH_TIMEOUT_S, left))
                except TimeoutError:
                    raise ToolError("pattern exceeded the regex matching time limit "
                                    f"({REGEX_MATCH_TIMEOUT_S}s per line); use a simpler "
                                    "pattern without nested or overlapping repetition") from None
                if hit:
                    out.append(f"{f}:{n}: {line.rstrip()[:300]}")
                    if len(out) >= cap:
                        out.append(f"... [stopped at {cap} matches; narrow the search]")
                        return "\n".join(out)
        return ("\n".join(out) if out else "(no matches)") + self._walk_note(state)

    def write_file(self, path: str, content: str) -> str:
        self._live()
        if not isinstance(content, str):
            raise ToolError("content must be a string")
        data = content.encode("utf-8")
        if len(data) > MAX_WRITE_BYTES:
            raise ToolError(f"content too large ({len(data)} bytes > {MAX_WRITE_BYTES})")
        target = self._resolve_write(path)
        if os.path.lexists(target):
            st = os.lstat(target)
            if not stat.S_ISREG(st.st_mode):
                raise ToolError(f"not written: {path} exists and is not a regular file")
        if target.suffix.lower() == ".json":
            validate_json_content(content)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ToolError(f"not written: cannot create the directory ({type(exc).__name__})") \
                from None
        if not self._inside(Path(os.path.realpath(target.parent)), self.work_real):
            raise ToolError("access denied: the target directory resolves outside the working "
                            "directory")
        try:
            fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".argo-tmp",
                                            dir=target.parent)
        except OSError as exc:
            raise ToolError(f"not written: cannot create a temporary file "
                            f"({type(exc).__name__})") from None
        committed = False
        try:
            if not self._inside(Path(os.path.realpath(tmp_name)).parent, self.work_real):
                os.close(fd)
                raise ToolError("access denied: the target directory changed during the write")
            with os.fdopen(fd, "wb") as tmp:
                tmp.write(data)
            self._live()                            # last check before the commit
            if target.is_symlink():
                raise ToolError("access denied: refusing to write through a symlink")
            os.replace(tmp_name, target)
            committed = True
        except OSError as exc:
            raise ToolError(f"not written: {path}: {type(exc).__name__}") from None
        finally:
            if not committed:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
        return f"wrote {len(data)} bytes to {target}"

    # -- schema + dispatch ------------------------------------------------------------------
    def schemas(self) -> list[dict]:
        def fn(name, desc, props, required):
            return {"type": "function", "function": {
                "name": name, "description": desc,
                "parameters": {"type": "object", "properties": props, "required": required}}}
        s = {"type": "string"}
        i = {"type": "integer"}
        tools = [
            fn("read_file", "Read a text file (repository or working directory). Returns numbered "
               f"lines; at most {MAX_READ_LINES} lines per call, use offset to page.",
               {"path": s, "offset": i, "limit": i}, ["path"]),
            fn("list_dir", "List a directory (repository or working directory).",
               {"path": s}, []),
            fn("glob", "Find files by glob pattern, e.g. '**/*.java' or 'src/**/Auth*.go'. "
               "Defaults to the repository root.", {"pattern": s, "path": s}, ["pattern"]),
            fn("grep", "Search file contents with a Python regular expression. Optional path "
               "(file or directory) and glob filter on file names, e.g. '*.py'.",
               {"pattern": s, "path": s, "glob": s, "ignore_case": {"type": "boolean"},
                "max_results": i}, ["pattern"]),
        ]
        if self.allow_write:
            tools.append(fn("write_file", "Create or overwrite a file in the working directory "
                            "(relative paths resolve there). The repository is read-only.",
                            {"path": s, "content": s}, ["path", "content"]))
        return tools

    def dispatch(self, name: str, args: dict) -> str:
        impl = {"read_file": self.read_file, "list_dir": self.list_dir, "glob": self.glob,
                "grep": self.grep}
        if self.allow_write:
            impl["write_file"] = self.write_file
        if name not in impl:
            shown = name[:60] if isinstance(name, str) else type(name).__name__
            raise ToolError(f"unknown tool {shown!r}; available: {', '.join(sorted(impl))}")
        if not isinstance(args, dict):
            raise ToolError("arguments must be a JSON object")
        clean = _validate_args(name, args)
        try:
            return impl[name](**clean)
        except OSError as exc:
            raise ToolError(f"{name} failed: {type(exc).__name__}") from None


def _is_junction(path: Path) -> bool:
    isjunction = getattr(os.path, "isjunction", None)   # Python >= 3.12
    if isjunction is not None:
        return isjunction(path)
    try:
        return bool(getattr(os.lstat(path), "st_reparse_tag", 0))
    except OSError:
        return False
