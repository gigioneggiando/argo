"""Refusal-probe: pairing/rate math (zero tokens -- a stubbed runner raises RunnerError instead of
making a real call) + prompt-fixture loading."""

from pathlib import Path

import pytest

from argo.refusal_probe import _score_backend, load_refusal_prompts, run_refusal_probe

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_load_refusal_prompts_real_fixture():
    prompts = load_refusal_prompts(FIXTURES / "refusal_prompts.json")
    assert len(prompts) >= 6
    for p in prompts:
        assert p["id"] and p["prompt"] and p["neutral_variant"]
        assert p["prompt"] != p["neutral_variant"]


def test_load_refusal_prompts_rejects_malformed_entry(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"prompts": [{"id": "x", "prompt": "p"}]}', encoding="utf-8")  # missing neutral_variant
    with pytest.raises(ValueError):
        load_refusal_prompts(bad)


# --------------------------------------------------------------- _score_backend (pairing math)
def test_score_backend_never_flagged():
    calls = [{"label": "p1-t0", "failure_kind": None}, {"label": "p2-t0", "failure_kind": None}]
    s = _score_backend(calls)
    assert s == {"trials": 2, "flagged": 0, "recovered": 0,
                "refusal_flag_rate": 0.0, "refusal_recovery_rate": None}


def test_score_backend_flagged_then_recovered_on_retry():
    calls = [
        {"label": "p1-t0", "failure_kind": "moderation_flagged"},
        {"label": "p1-t0-neutral-retry", "failure_kind": None},
        {"label": "p2-t0", "failure_kind": None},
    ]
    s = _score_backend(calls)
    assert s["trials"] == 2                     # first attempts only -- the retry isn't a trial
    assert s["flagged"] == 1
    assert s["recovered"] == 1
    assert s["refusal_flag_rate"] == 0.5
    assert s["refusal_recovery_rate"] == 1.0


def test_score_backend_flagged_and_retry_also_flagged_does_not_count_as_recovered():
    calls = [
        {"label": "p1-t0", "failure_kind": "moderation_flagged"},
        {"label": "p1-t0-neutral-retry", "failure_kind": "moderation_flagged"},
    ]
    s = _score_backend(calls)
    assert s["flagged"] == 1 and s["recovered"] == 0
    assert s["refusal_recovery_rate"] == 0.0


def test_score_backend_flagged_with_no_retry_row_is_not_recovered():
    """A flagged call whose retry never ran (e.g. the run crashed before the retry) must not be
    silently counted as recovered just because there's no contradicting retry row."""
    calls = [{"label": "p1-t0", "failure_kind": "moderation_flagged"}]
    s = _score_backend(calls)
    assert s["flagged"] == 1 and s["recovered"] == 0


# --------------------------------------------------------------- run_refusal_probe (mock, zero tokens)
def test_run_refusal_probe_end_to_end_mock(tmp_path):
    from argo.config import PipelineConfig
    prompts = load_refusal_prompts(FIXTURES / "refusal_prompts.json")
    cfg = PipelineConfig(runner="mock", runs_dir=tmp_path / "runs", fixtures_dir=FIXTURES,
                         fixtures_scenario="happy", ledger_path=tmp_path / "l.sqlite")
    report = run_refusal_probe(cfg, prompts[:2], backends=["mock"], trials=2, tier="cheap")
    assert report["backends"]["mock"]["trials"] == 4          # 2 prompts x 2 trials
    assert report["backends"]["mock"]["flagged"] == 0          # mock never refuses
    assert report["tier"] == "cheap" and report["trials_per_prompt"] == 2
    assert (Path(cfg.runs_dir) / "refusal_probe_report.json").exists()
