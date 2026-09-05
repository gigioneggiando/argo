"""Audit focus retry — a session that never started is lost work, not a result.

Regression cover for a real coverage loss (Study C run 01b, 2026-09-05): both codex backends
blipped inside the same minute, two of three audit focuses returned `exit_1` with zero tokens and
no partial artifact, and the stage abandoned them. The run finished clean with one third of the
planned audit surface covered — and a target audited on one focus is not comparable with a target
audited on three, so the finding count stops being a property of the target.

The line these tests hold: **session failures are retried, answers are not.** Re-rolling a focus
until the model emits something parseable would be selecting on the output.
"""

import argo.stages.audit as audit_stage
from argo.orchestrator import do_audit, do_ingest, do_recon

from conftest import BRIEF, REPO


def _prepare(env, **cfg):
    ctx = env(**cfg)
    do_ingest(ctx, BRIEF, str(REPO))
    do_recon(ctx)
    return ctx


def _fake_audit_one(script, calls, real):
    """Wrap _audit_one so the first N attempts per slug fail as scripted."""
    def _inner(ctx, scope, prompt_path):
        slug = prompt_path.stem
        calls.append(slug)
        remaining = script.get(slug, 0)
        if remaining > 0:
            script[slug] = remaining - 1
            return slug, None, "session failed, no partial artifact (simulated)", True
        return real(ctx, scope, prompt_path)
    return _inner


def test_a_session_failure_is_retried_once_and_can_succeed(env, monkeypatch):
    ctx = _prepare(env, audit_retry_delay_s=0)
    real = audit_stage._audit_one
    prompts = sorted(p.stem for p in ctx.prompts_out_dir.glob("audit_*.md"))
    victim = prompts[0]
    calls: list[str] = []
    monkeypatch.setattr(audit_stage, "_audit_one",
                        _fake_audit_one({victim: 1}, calls, real))

    do_audit(ctx)

    # the focus was attempted twice and its findings artifact exists after the retry
    assert calls.count(victim) == 2
    produced = {p.stem.replace("audit_", "") for p in ctx.findings_dir.glob("audit_*.json")}
    assert victim.replace("audit_", "") in produced
    # coverage is complete: every planned focus produced an artifact
    assert produced == {s.replace("audit_", "") for s in prompts}


def test_a_malformed_answer_is_never_retried(env, monkeypatch):
    """A findings file that does not parse is a RESULT. Retrying it would select on the output."""
    ctx = _prepare(env, audit_retry_delay_s=0)
    prompts = sorted(p.stem for p in ctx.prompts_out_dir.glob("audit_*.md"))
    victim = prompts[0]
    calls: list[str] = []

    real = audit_stage._audit_one
    monkeypatch.setattr(audit_stage, "_audit_one",
                        lambda c, s, p: (p.stem, None, "findings file is not valid JSON: boom",
                                         False) if p.stem == victim else real(c, s, p))
    monkeypatch.setattr(audit_stage, "_log", lambda m: calls.append(m))

    do_audit(ctx)
    # exactly one attempt on the victim: it appears once in the SKIPPED log, never retried
    assert sum(1 for m in calls if victim in str(m) and "SKIPPED" in str(m)) == 1
    assert not any("retrying once" in str(m) for m in calls)


def test_retry_is_bounded_at_one_extra_attempt(env, monkeypatch):
    ctx = _prepare(env, audit_retry_delay_s=0)
    prompts = sorted(p.stem for p in ctx.prompts_out_dir.glob("audit_*.md"))
    victim = prompts[0]
    calls: list[str] = []
    real = audit_stage._audit_one
    # never succeeds
    monkeypatch.setattr(audit_stage, "_audit_one",
                        _fake_audit_one({victim: 99}, calls, real))

    do_audit(ctx)

    assert calls.count(victim) == 2, "a permanently failing focus must not loop"
    produced = {p.stem for p in ctx.findings_dir.glob("audit_*.json")}
    assert victim not in produced   # and the gap is real, not papered over


def test_retry_can_be_switched_off(env, monkeypatch):
    ctx = _prepare(env, audit_retry_delay_s=0, audit_retry_passes=0)
    prompts = sorted(p.stem for p in ctx.prompts_out_dir.glob("audit_*.md"))
    victim = prompts[0]
    calls: list[str] = []
    real = audit_stage._audit_one
    monkeypatch.setattr(audit_stage, "_audit_one",
                        _fake_audit_one({victim: 1}, calls, real))

    do_audit(ctx)

    assert calls.count(victim) == 1, "audit_retry_passes=0 restores abandon-on-failure"


def test_successful_focuses_are_untouched_by_the_retry_path(env, monkeypatch):
    """The retry must not re-run focuses that already produced an artifact — that would double
    the cost of every run in which any single focus blipped."""
    ctx = _prepare(env, audit_retry_delay_s=0)
    prompts = sorted(p.stem for p in ctx.prompts_out_dir.glob("audit_*.md"))
    victim, others = prompts[0], prompts[1:]
    calls: list[str] = []
    real = audit_stage._audit_one
    monkeypatch.setattr(audit_stage, "_audit_one",
                        _fake_audit_one({victim: 1}, calls, real))

    do_audit(ctx)

    for slug in others:
        assert calls.count(slug) == 1, f"{slug} succeeded and must not be re-run"
