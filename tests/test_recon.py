"""recon resilience: a transient cutoff of the synthesis session (machine sleep, network blip, model
stop_sequence) can write ground_truth.json + repo_profile.json but NOT the per-focus audit_*.md prompts,
which used to abort the whole run with "no audit prompts". recon.run now retries the synthesis."""

import shutil
from pathlib import Path
from types import SimpleNamespace

from argo.orchestrator import do_ingest
from argo.stages import recon

from conftest import BRIEF, REPO

RECON_FIXTURE = Path(__file__).parent / "fixtures" / "happy" / "recon"


class _FailFirstReconRunner:
    """Attempt 1 simulates a transient cutoff: writes only ground_truth.json + repo_profile.json (no
    audit_*.md). Attempt 2 writes the full recon fixture (with the audit prompts)."""

    def __init__(self):
        self.calls = 0

    def run(self, *, work_dir, **kw):
        self.calls += 1
        work = Path(work_dir)
        work.mkdir(parents=True, exist_ok=True)   # the real runner creates the scratch dir
        if self.calls == 1:
            names = ["ground_truth.json", "repo_profile.json"]
        else:
            names = [p.name for p in RECON_FIXTURE.glob("*") if p.is_file()]
        for name in names:
            src = RECON_FIXTURE / name
            if src.exists():
                shutil.copy(src, work / name)
        return SimpleNamespace(text="", work_dir=work, cost_usd=0.0, is_error=False)


def test_recon_retries_when_first_attempt_yields_no_audit_prompts(env):
    ctx = env()
    do_ingest(ctx, BRIEF, str(REPO))            # create scope.json via the mock runner
    ctx.runner = _FailFirstReconRunner()         # swap in the fail-first runner

    prompts = recon.run(ctx)

    assert ctx.runner.calls == 2, "recon should retry the synthesis once when it yields no audit prompts"
    assert prompts, "the retry should have produced the audit prompts"
    assert all(p.name.startswith("audit_") for p in prompts)
