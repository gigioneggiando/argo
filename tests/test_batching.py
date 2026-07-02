"""Efficiency: validate/corroborate collapse the per-finding fan-out into batched sessions
(config `validate_batch_size` / `corroborate_batch_size`). Batching must cut session count without
changing which findings survive — the same adversarial verdict per finding, just grouped."""

import json

from argo.orchestrator import run_pipeline

from conftest import BRIEF, REPO


def _sessions(ctx, stage: str) -> int:
    return sum(1 for l in (ctx.run_dir / "llm_log.jsonl").read_text(encoding="utf-8").splitlines()
               if l.strip() and json.loads(l)["stage"] == stage)


def _survivors(ctx) -> list[str]:
    doc = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))
    return sorted(f["id"] for f in doc.get("findings", []))


def test_validate_batches_into_one_session_by_default(env):
    ctx = env()                                          # default validate_batch_size=8
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    assert _sessions(ctx, "validate") == 1               # the fixture's ~4 findings -> ONE session


def test_batch_size_one_is_legacy_per_finding(env):
    ctx = env(validate_batch_size=1)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    assert _sessions(ctx, "validate") >= 3               # one session per validated finding


def test_batching_preserves_survivors(env):
    batched = env(run_id="BATCH-RUN")
    run_pipeline(batched, BRIEF, str(REPO), research_enabled=False)
    per_finding = env(run_id="PERFINDING-RUN", validate_batch_size=1)
    run_pipeline(per_finding, BRIEF, str(REPO), research_enabled=False)
    assert _survivors(batched) == _survivors(per_finding)          # identical result
    assert _sessions(batched, "validate") < _sessions(per_finding, "validate")   # fewer sessions


def test_corroborate_batches_into_one_session(env):
    ctx = env(corroborate_enabled=True)
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)
    assert _sessions(ctx, "corroborate") == 1            # all survivors corroborated in ONE session
