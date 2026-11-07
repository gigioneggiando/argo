"""Every runtime dependency in requirements.txt is also declared in pyproject.toml.

Regression: `python-multipart` (needed by the server's zip-upload endpoint) was only in
requirements.txt, so an install from the package metadata could not start `argo serve`
(FastAPI raises at app creation). `httpx` had the same gap before v0.12.1."""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEV_ONLY = {"pytest"}


def _name(spec: str) -> str:
    return re.split(r"[<>=!~;\[\s]", spec.strip(), maxsplit=1)[0].lower().replace("_", "-")


def test_runtime_requirements_are_declared_in_pyproject():
    declared = {_name(d) for d in tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
                ["project"]["dependencies"]}
    required = set()
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            required.add(_name(line))
    missing = sorted(required - declared - DEV_ONLY)
    assert not missing, f"in requirements.txt but not in pyproject [project].dependencies: {missing}"


def test_server_app_builds_with_declared_deps():
    # create_app() is where FastAPI checks for python-multipart; it must not raise.
    from server.app import create_app
    assert create_app() is not None
