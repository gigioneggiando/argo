"""Small, non-secret provenance helpers shared by runs and benchmarks."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path


def cli_versions() -> dict[str, str | None]:
    """Capture installed backend CLI versions once; missing tools are non-fatal."""
    commands = {"claude": ["claude", "--version"], "codex": ["codex", "--version"],
                "gemini": ["gemini", "--version"]}
    out: dict[str, str | None] = {}
    for name, command in commands.items():
        try:
            p = subprocess.run(command, capture_output=True, text=True, timeout=5)
            text = (p.stdout or p.stderr).strip()
            out[name] = text.splitlines()[0][:300] if p.returncode == 0 and text else None
        except (OSError, subprocess.SubprocessError):
            out[name] = None
    return out


def argo_revision() -> str | None:
    try:
        p = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                           timeout=3, check=True)
        return p.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
