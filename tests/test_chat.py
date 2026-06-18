"""B1 — chat re-validates a user-proposed candidate finding ("why didn't you find X?").

The hard part (validating a single ad-hoc finding) reuses the pipeline's `_validate_one`; these
tests cover the chat plumbing deterministically (the adversarial validator is monkeypatched, and a
stub runner stands in for the model writing CANDIDATE_FINDING.json)."""

import json
from pathlib import Path
from types import SimpleNamespace

import argo.chat as chat
from argo.models import Validation
from argo.orchestrator import run_pipeline

from conftest import BRIEF, REPO


class _StubRunner:
    """Stands in for the chat model: optionally writes a CANDIDATE_FINDING.json into the work dir."""
    def __init__(self, write_candidate: bool = True):
        self.write_candidate = write_candidate

    def run(self, *, work_dir, **kw):
        if self.write_candidate:
            (Path(work_dir) / "CANDIDATE_FINDING.json").write_text(json.dumps({
                "id": "CAND-1", "title": "SQLi in search", "cwe": "CWE-89",
                "severity": "High", "confidence": "Medium",
                "affected": ["src/api/search.py:42"], "vulnerable_flow": "input -> query",
                "why_vulnerable": "string concat", "exploit_scenario": "' OR 1=1",
                "impact": "db read", "recommended_fix": "parameterize"}), encoding="utf-8")
        return SimpleNamespace(text="Here is my analysis.", cost_usd=0.0, is_error=False)


def test_coerce_candidate_backfills():
    d = chat._coerce_candidate({"affected": "x.py:1"})
    for k in ("id", "title", "severity", "confidence", "cwe", "vulnerable_flow",
              "why_vulnerable", "exploit_scenario", "impact", "recommended_fix"):
        assert k in d
    assert d["affected"] == ["x.py:1"]          # a bare string is wrapped into a list


def test_validate_candidate_runs_the_validator(env, monkeypatch):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO))
    monkeypatch.setattr(chat, "_validate_one",
                        lambda c, s, t, f: Validation(verdict="refuted", rationale="sanitized"))
    out = chat._validate_candidate(ctx, ctx.load_scope(), {"affected": "x.py:1", "cwe": "CWE-79"})
    assert out["verdict"] == "refuted" and out["cwe"] == "CWE-79"
    assert out["finding_id"] == "CHAT-CANDIDATE"      # backfilled


def test_ask_revalidates_candidate(env, monkeypatch):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO))
    ctx.runner = _StubRunner(write_candidate=True)
    monkeypatch.setattr(chat, "_validate_one", lambda c, s, t, f: Validation(
        verdict="confirmed", rationale="traced source->sink", validated_severity="High"))
    res = chat.ask(ctx, "why didn't you find the SQLi at search.py:42?")
    assert res["validated_candidate"]["verdict"] == "confirmed"
    assert res["validated_candidate"]["finding_id"] == "CAND-1"
    assert "CONFIRMED" in res["reply"]
    # the raw hypothesis file is not surfaced as a generated artifact; the verdict file is written
    assert "CANDIDATE_FINDING.json" not in res["generated"]
    assert (ctx.run_dir / "generated" / "candidate_CAND-1.json").exists()


def test_ask_without_candidate_is_none(env):
    ctx = env()
    run_pipeline(ctx, BRIEF, str(REPO))
    ctx.runner = _StubRunner(write_candidate=False)
    res = chat.ask(ctx, "explain the top finding")
    assert res["validated_candidate"] is None and res["generated"] == []
