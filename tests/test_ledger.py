"""Ledger.run_cost/run_call_count must combine a run with its second-opinion children
(stages/second_opinion.py's ``f"{run_id}-so{N}"`` blind passes) -- they run in an isolated run_dir
for artifact cleanliness, but their spend is still incurred BY the parent run. Found for real: a
$15 --budget ceiling on a run with second_opinion_passes=1 actually allowed ~$34 real spend because
the budget check (RunContext.assert_budget / AgentRunner._session_budget) queried only the primary
run_id's own cost, silently missing the child pass's spend sitting under a different run_id in the
SAME ledger file."""

from argo.ledger import Ledger


def _log(ledger: Ledger, run_id: str, cost: float) -> None:
    ledger.log_call(run_id=run_id, stage="audit", model="m", prompt_sha256="h", cost_usd=cost)


def test_run_cost_combines_second_opinion_children(tmp_path):
    ledger = Ledger(tmp_path / "l.sqlite")
    _log(ledger, "R", 1.0)
    _log(ledger, "R-so1", 2.0)
    _log(ledger, "R-so2", 3.0)
    assert ledger.run_cost("R") == 6.0
    ledger.close()


def test_run_cost_does_not_leak_into_unrelated_runs(tmp_path):
    ledger = Ledger(tmp_path / "l.sqlite")
    _log(ledger, "R", 1.0)
    _log(ledger, "R-so1", 2.0)
    _log(ledger, "R2", 100.0)          # unrelated run, must not be counted
    _log(ledger, "R2-so1", 100.0)      # unrelated run's own child, must not be counted
    assert ledger.run_cost("R") == 3.0
    assert ledger.run_cost("R2") == 200.0
    ledger.close()


def test_run_call_count_combines_second_opinion_children(tmp_path):
    ledger = Ledger(tmp_path / "l.sqlite")
    _log(ledger, "R", 1.0)
    _log(ledger, "R-so1", 1.0)
    _log(ledger, "R-so1", 1.0)
    assert ledger.run_call_count("R") == 3
    ledger.close()


def test_run_cost_escapes_like_wildcards_in_run_id(tmp_path):
    """A run_id containing a literal '%' or '_' (never produced by new_run_id(), but not otherwise
    forbidden) must not turn into an unintended LIKE wildcard that matches unrelated run_ids."""
    ledger = Ledger(tmp_path / "l.sqlite")
    _log(ledger, "R_1", 1.0)
    _log(ledger, "RX1-so1", 5.0)   # would match "R_1-so%" if '_' were left unescaped -- must NOT
    assert ledger.run_cost("R_1") == 1.0
    ledger.close()


def test_run_cost_with_no_calls_is_zero(tmp_path):
    ledger = Ledger(tmp_path / "l.sqlite")
    assert ledger.run_cost("nonexistent") == 0.0
    assert ledger.run_call_count("nonexistent") == 0
    ledger.close()


def test_migration_adds_duration_and_failure_kind_to_a_preexisting_db(tmp_path):
    """A DB created before duration_ms/failure_kind/label existed must open cleanly and gain the
    new columns (via _MIGRATIONS), not raise or silently keep the old schema."""
    import sqlite3
    p = tmp_path / "old.sqlite"
    conn = sqlite3.connect(str(p))
    conn.execute("""CREATE TABLE llm_calls (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, run_id TEXT NOT NULL,
        stage TEXT NOT NULL, model TEXT NOT NULL, prompt_sha256 TEXT NOT NULL,
        input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0,
        cost_usd REAL NOT NULL DEFAULT 0.0, num_turns INTEGER NOT NULL DEFAULT 0,
        session_id TEXT, stop_reason TEXT)""")
    conn.execute("INSERT INTO llm_calls (ts, run_id, stage, model, prompt_sha256) "
                "VALUES ('t','R','audit','m','h')")
    conn.commit(); conn.close()

    ledger = Ledger(p)
    assert ledger.run_calls("R") == [
        {"stage": "audit", "label": None, "failure_kind": None, "duration_ms": 0, "cost_usd": 0.0}]
    ledger.log_call(run_id="R", stage="audit", model="m", prompt_sha256="h2", duration_ms=42,
                    failure_kind="moderation_flagged", label="x")
    assert ledger.call_durations("R") == [0, 42]
    ledger.close()


def test_call_durations_combines_second_opinion_children(tmp_path):
    ledger = Ledger(tmp_path / "l.sqlite")
    ledger.log_call(run_id="R", stage="audit", model="m", prompt_sha256="h", duration_ms=10)
    ledger.log_call(run_id="R-so1", stage="audit", model="m", prompt_sha256="h", duration_ms=20)
    assert sorted(ledger.call_durations("R")) == [10, 20]
    ledger.close()


def test_run_calls_returns_rows_for_pairing_flag_and_retry(tmp_path):
    ledger = Ledger(tmp_path / "l.sqlite")
    ledger.log_call(run_id="R", stage="audit", model="m", prompt_sha256="h1",
                    label="p1-t0", failure_kind="moderation_flagged")
    ledger.log_call(run_id="R", stage="audit", model="m", prompt_sha256="h2",
                    label="p1-t0-neutral-retry", failure_kind=None)
    calls = ledger.run_calls("R")
    assert len(calls) == 2
    assert calls[0]["label"] == "p1-t0" and calls[0]["failure_kind"] == "moderation_flagged"
    assert calls[1]["label"] == "p1-t0-neutral-retry" and calls[1]["failure_kind"] is None
    ledger.close()
