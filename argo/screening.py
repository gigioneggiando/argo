"""Fast, deterministic, read-only target screening.

Screening deliberately does not import or execute target code, invoke package managers, run tests,
or contact the network.  It produces a compact fingerprint that the planner can use before any
paid model call.  Cache entries live outside the target tree and are keyed by a content identity.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
_SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "target",
              ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache", "coverage"}
_LANGUAGES = {
    ".c": "C", ".h": "C/C++", ".cc": "C++", ".cpp": "C++", ".cxx": "C++", ".hpp": "C++",
    ".rs": "Rust", ".go": "Go", ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java", ".kt": "Kotlin",
    ".php": "PHP", ".rb": "Ruby", ".cs": "C#", ".swift": "Swift", ".lua": "Lua",
    ".sh": "Shell", ".ps1": "PowerShell", ".sql": "SQL",
}
_INDICATORS = {
    "parser": ("parser", "parse", "deserialize", "deserialize", "lexer", "tokenizer", "ast", "protobuf", "yaml", "json", "xml", "toml"),
    "network": ("http", "https", "socket", "tls", "tcp", "udp", "grpc", "websocket", "request", "server"),
    "auth": ("auth", "permission", "role", "rbac", "acl", "oauth", "jwt", "session", "login", "credential"),
    "crypto": ("crypto", "cipher", "encrypt", "decrypt", "secret", "key", "certificate", "tls"),
    "archive_file": ("archive", "zip", "tar", "gzip", "file", "path", "upload", "download", "extract"),
    "process_shell": ("subprocess", "shell", "exec", "spawn", "command", "process"),
    "memory_unsafe": ("unsafe", "malloc", "free", "memcpy", "pointer", "raw", "ffi", "ctypes"),
    "concurrency": ("thread", "mutex", "lock", "async", "await", "atomic", "channel", "worker"),
}
_MANIFESTS = {"pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "package.json", "package-lock.json",
              "pnpm-lock.yaml", "yarn.lock", "Cargo.toml", "Cargo.lock", "go.mod", "go.sum", "pom.xml",
              "build.gradle", "build.gradle.kts", "composer.json", "Gemfile", "Gemfile.lock", "CMakeLists.txt",
              "Makefile", "meson.build", "BUILD", "WORKSPACE", "flake.lock"}
_BUILD_FILES = {"CMakeLists.txt": "cmake", "Makefile": "make", "meson.build": "meson",
                "BUILD": "bazel", "WORKSPACE": "bazel", "Cargo.toml": "cargo",
                "go.mod": "go", "pom.xml": "maven", "build.gradle": "gradle",
                "pyproject.toml": "python", "package.json": "node"}


def _git_head(root: Path) -> str | None:
    try:
        return subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True,
                              text=True, timeout=3, check=True).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def _files(root: Path):
    for base, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS and
                         (not d.startswith(".") or d in {".github", ".gitlab"}))
        for name in sorted(names):
            p = Path(base) / name
            try:
                if p.is_symlink() or not p.is_file():
                    continue
                yield p
            except OSError:
                continue


def _identity(root: Path, entries: list[tuple[str, int, str]]) -> str:
    h = hashlib.sha256()
    for rel, size, digest in entries:
        h.update(f"{rel}\0{size}\0{digest}\n".encode())
    return h.hexdigest()


def screen_target(target: str | Path, *, cache_dir: str | Path | None = None,
                  rescreen: bool = False) -> dict[str, Any]:
    root = Path(target).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("screening requires a local directory; it never fetches URLs")
    entries: list[tuple[str, int, str]] = []
    for p in _files(root):
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if len(data) > 2_000_000:
            data = data[:2_000_000]
        entries.append((p.relative_to(root).as_posix(), p.stat().st_size, hashlib.sha256(data).hexdigest()))
    identity = _identity(root, entries)
    cache_root = Path(cache_dir) if cache_dir else root.parent / ".argo-screen-cache"
    cache_path = cache_root / f"{identity}.json"
    if cache_path.exists() and not rescreen:
        try:
            return json.loads(cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    lang = Counter()
    surfaces = Counter()
    source_files = 0
    loc = 0
    total_bytes = 0
    evidence: dict[str, list[str]] = {k: [] for k in _INDICATORS}
    manifests: list[str] = []
    tests = fuzzers = sanitizers = ci = 0
    ffi_files = generated_files = vendor_files = giant_files = minified_files = 0
    build_systems: Counter[str] = Counter()
    for rel, size, _digest in entries:
        p = root / rel
        total_bytes += size
        ext = p.suffix.lower()
        if ext in _LANGUAGES:
            source_files += 1
            lang[_LANGUAGES[ext]] += 1
            try:
                raw = p.read_bytes()[:256_000]
                text = raw.decode("utf-8", errors="ignore")
            except OSError:
                text = ""
            loc += text.count("\n") + (1 if text else 0)
            hay = f"{rel}\n{text[:100_000]}".lower()
            for surface, words in _INDICATORS.items():
                if any(word in hay for word in words):
                    surfaces[surface] += 1
                    if len(evidence[surface]) < 8:
                        evidence[surface].append(rel)
        name = p.name
        if name in _MANIFESTS:
            manifests.append(rel)
        low = rel.lower()
        tests += int("test" in low or "/tests/" in low or "_test." in low)
        fuzzers += int("fuzz" in low or "afl" in low or "libfuzzer" in low)
        sanitizers += int("asan" in low or "ubsan" in low or "sanitizer" in low)
        ci += int("/.github/workflows/" in f"/{low}" or "/.gitlab-ci" in f"/{low}")
        build = _BUILD_FILES.get(name)
        if build:
            build_systems[build] += 1
        if any(part in {"vendor", "third_party", "third-party"} for part in Path(rel).parts):
            vendor_files += 1
        if any(word in low for word in ("generated", ".generated.", ".gen.")):
            generated_files += 1
        if size > 500_000:
            giant_files += 1
        if p.suffix.lower() in {".min.js", ".min.css"} or ".min." in p.name.lower():
            minified_files += 1
        # Bounded textual hints for foreign-function/native bindings, without importing code.
        if ext in {".py", ".rs", ".go", ".js", ".ts", ".java", ".cs"}:
            try:
                probe = p.read_bytes()[:64_000].decode("utf-8", errors="ignore").lower()
            except OSError:
                probe = ""
            ffi_files += int(any(x in probe for x in ("ctypes", "cffi", "pyo3", "extern \"c\"",
                                                       "node-gyp", "napi", "jni", "pinvoke")))
    mono = int(any((root / d).is_dir() for d in ("packages", "apps", "services", "crates")) or len(manifests) >= 3)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "fingerprint_id": identity,
        "target": str(root),
        "revision": _git_head(root),
        "files": len(entries), "source_files": source_files, "approx_loc": loc,
        "total_bytes": total_bytes, "directory_depth": max((len(Path(r).parts) for r, _, _ in entries), default=0),
        "monorepo": bool(mono), "languages": dict(lang), "surfaces": dict(surfaces),
        "evidence": {k: v for k, v in evidence.items() if v}, "manifests": manifests[:100],
        "verification": {"tests": tests, "fuzzers": fuzzers, "sanitizers": sanitizers, "ci": ci},
        "native_ratio": round(sum(lang_count for lang, lang_count in lang.items()
                                   if lang in {"C", "C++", "Rust", "Go"}) / max(1, source_files), 4),
        "ffi_files": ffi_files,
        "build_systems": dict(build_systems),
        "context": {"generated_files": generated_files, "vendor_files": vendor_files,
                    "giant_files": giant_files, "minified_files": minified_files,
                    "pressure": "high" if giant_files or generated_files > 20 else
                                "medium" if generated_files or minified_files else "low"},
    }
    cache_root.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload
