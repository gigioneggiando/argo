"""Shared pytest fixtures: a temp run environment driven by the MockClaudeRunner, plus a
helper to derive a mutated fixtures scenario (for failure-path tests)."""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path
from typing import Callable

import pytest

from argo.config import PipelineConfig
from argo.orchestrator import build_context

FIXTURES = Path(__file__).parent / "fixtures"
HAPPY = FIXTURES / "happy"
BRIEF = FIXTURES / "brief.txt"
REPO = FIXTURES / "repo"
FIXED_NOW = "2026-06-16T12:00:00+00:00"
FIXED_RUN_ID = "TEST-RUN-0001"


def _force_rmtree(path: Path) -> None:
    """Restore write+execute on every directory under ``path`` before removing it, then retry
    the actual removal a few times. Two independent reasons this needs to be more than a plain
    shutil.rmtree:
      * On POSIX, deleting an entry requires write permission on its PARENT directory, not the
        entry itself -- _make_readonly's directory hardening (POSIX only, see
        argo/stages/ingest.py) strips exactly that, so nothing inside a hardened directory can be
        unlinked without first restoring the parent's own write bit (a per-file onerror chmod on
        the failing child is not enough).
      * On Windows, a just-imported module's .pyc under a copied fixture tree can occasionally
        still be memory-mapped by the interpreter for a brief moment after import, making an
        immediate delete fail with WinError 5 even though nothing is genuinely still using it a
        moment later -- retrying with a short backoff clears this without masking a real leak
        (a persistent failure across all attempts still raises)."""
    import time

    if not path.exists():
        return
    last_exc: OSError | None = None
    for attempt in range(5):
        try:
            for dirpath, dirnames, _filenames in os.walk(path):
                for name in dirnames:
                    os.chmod(Path(dirpath) / name, stat.S_IRWXU)
            os.chmod(path, stat.S_IRWXU)

            def _onerror(func, p, _exc):
                os.chmod(p, stat.S_IWRITE)
                func(p)

            shutil.rmtree(path, onerror=_onerror)
            return
        except OSError as exc:
            last_exc = exc
            time.sleep(0.2 * (attempt + 1))
    if path.exists():
        raise last_exc


@pytest.fixture
def env(tmp_path):
    """Return a factory that builds a RunContext on the mock runner with an isolated runs dir
    + ledger. ``scenario`` selects a fixtures scenario; ``fixtures_dir`` can be overridden."""
    created = []

    def _make(scenario: str = "happy", *, fixtures_dir: Path | None = None,
              run_id: str = FIXED_RUN_ID, **cfg_overrides) -> "object":
        # Determinism default: pin the completeness-critic OFF so call-count/golden tests are stable
        # (a dedicated test opts back in with audit_critic_passes=1). Same spirit as research-off.
        cfg_overrides.setdefault("audit_critic_passes", 0)
        cfg_overrides.setdefault("sca_enabled", False)   # SCA adds a stage/call; opt in per-test
        cfg_overrides.setdefault("corroborate_enabled", False)  # networked stage/calls; opt in per-test
        cfg_overrides.setdefault("attribution", False)   # keep REPORT.md byte-stable; opt in per-test
        cfg = PipelineConfig(
            runner="mock",
            runs_dir=tmp_path / "runs",
            ledger_path=tmp_path / "ledger.sqlite",
            fixtures_dir=fixtures_dir or FIXTURES,
            fixtures_scenario=scenario,
            **cfg_overrides,
        )
        ctx = build_context(cfg, run_id, now=FIXED_NOW)
        created.append(ctx)
        return ctx

    yield _make
    for ctx in created:
        try:
            ctx.ledger.close()
        except Exception:
            pass
    _force_rmtree(tmp_path / "runs")


@pytest.fixture
def make_scenario(tmp_path) -> Callable[[Callable[[Path], None], str], tuple[Path, str]]:
    """Copy the ``happy`` fixtures into a temp scenario dir, apply ``mutate(scenario_dir)``,
    and return ``(fixtures_dir, scenario_name)`` to pass to ``env``."""
    counter = {"n": 0}

    def _make(mutate: Callable[[Path], None], name: str = "mutated") -> tuple[Path, str]:
        counter["n"] += 1
        fixtures_dir = tmp_path / "fixtures"
        scen = fixtures_dir / f"{name}{counter['n']}"
        scen.mkdir(parents=True, exist_ok=True)
        for sub in ("ingest", "recon", "audit", "validate"):
            shutil.copytree(HAPPY / sub, scen / sub)
        mutate(scen)
        return fixtures_dir, scen.name

    return _make
