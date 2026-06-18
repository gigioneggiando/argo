"""C1 — mid-stage cancellation: the runner runs the CLI as a cancellable subprocess (killed when
the run's cancel_event fires), and the orchestrator treats a mid-stage kill as a cancellation."""

import json
import subprocess
import sys
import threading
import time

import pytest

from argo.config import PipelineConfig
from argo.ledger import Ledger
from argo.orchestrator import PipelineCancelled, run_pipeline
from argo.runner import AgentRunner, RunnerCancelled

from conftest import BRIEF, REPO

_SLEEP = [sys.executable, "-c", "import time; time.sleep(30)"]


class _Bare(AgentRunner):
    def _invoke(self, **kw):  # abstract; unused by these tests
        raise NotImplementedError


def _runner(tmp_path) -> _Bare:
    return _Bare(PipelineConfig(), Ledger(tmp_path / "l.sqlite"))


def test_exec_success(tmp_path):
    r = _runner(tmp_path)
    cp = r._exec([sys.executable, "-c", "print('hi')"], prompt="", cwd=tmp_path, timeout=10)
    assert cp.returncode == 0 and "hi" in cp.stdout
    r.ledger.close()


def test_exec_cancel_kills_subprocess_promptly(tmp_path):
    r = _runner(tmp_path)
    ev = threading.Event()
    r.cancel_event = ev
    threading.Timer(0.3, ev.set).start()         # fire Cancel shortly after launch
    t0 = time.monotonic()
    with pytest.raises(RunnerCancelled):
        r._exec(_SLEEP, prompt="", cwd=tmp_path, timeout=30)
    assert time.monotonic() - t0 < 8             # killed promptly, not after the 30s sleep
    r.ledger.close()


def test_exec_timeout_still_raises(tmp_path):
    r = _runner(tmp_path)                          # no cancel_event -> timeout path
    t0 = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        r._exec(_SLEEP, prompt="", cwd=tmp_path, timeout=0.5)
    assert time.monotonic() - t0 < 8
    r.ledger.close()


def test_pipeline_runner_cancel_marks_cancelled(env):
    """A RunnerCancelled raised mid-stage becomes a cancellation (not a failure), and status.json
    is marked cancelled."""
    ctx = env()

    class _CancelRunner:
        cancel_event = None
        def run(self, **kw):
            raise RunnerCancelled("killed mid-stage")

    ctx.runner = _CancelRunner()
    with pytest.raises(PipelineCancelled):
        run_pipeline(ctx, BRIEF, str(REPO))
    st = json.loads((ctx.run_dir / "status.json").read_text(encoding="utf-8"))
    assert st["state"] == "cancelled"
