"""SQLite ledger: per-call cost log + cross-run findings ledger.

Two tables:
  * ``llm_calls``      — every model invocation (prompt hash, model, tokens, cost) for cost
    control on a Max plan and for per-run budget enforcement.
  * ``findings_ledger`` — every surviving finding (program, dedup_key, verdict, date) so we
    can detect cross-program/cross-run resubmission and track hit rate over time.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS llm_calls (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             TEXT NOT NULL,
    run_id         TEXT NOT NULL,
    stage          TEXT NOT NULL,
    model          TEXT NOT NULL,
    prompt_sha256  TEXT NOT NULL,
    input_tokens   INTEGER NOT NULL DEFAULT 0,
    output_tokens  INTEGER NOT NULL DEFAULT 0,
    cost_usd       REAL NOT NULL DEFAULT 0.0,
    num_turns      INTEGER NOT NULL DEFAULT 0,
    session_id     TEXT,
    stop_reason    TEXT
);
CREATE INDEX IF NOT EXISTS idx_llm_calls_run ON llm_calls(run_id);

CREATE TABLE IF NOT EXISTS findings_ledger (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                 TEXT NOT NULL,
    program_name       TEXT NOT NULL,
    run_id             TEXT NOT NULL,
    dedup_key          TEXT NOT NULL,
    title              TEXT,
    verdict            TEXT,
    validated_severity TEXT,
    UNIQUE(program_name, dedup_key, run_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_prog_key ON findings_ledger(program_name, dedup_key);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Ledger:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False + a write lock: the runner logs from parallel audit/validate
        # worker threads, all serialized through this single connection.
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # WAL + a busy timeout: the API opens a second (read) connection for live cost while the
        # run thread writes call costs — WAL lets readers and the writer coexist without locking.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Ledger":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------ llm calls
    def log_call(
        self,
        *,
        run_id: str,
        stage: str,
        model: str,
        prompt_sha256: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cost_usd: float = 0.0,
        num_turns: int = 0,
        session_id: str | None = None,
        stop_reason: str | None = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO llm_calls
                   (ts, run_id, stage, model, prompt_sha256, input_tokens, output_tokens,
                    cost_usd, num_turns, session_id, stop_reason)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (_now(), run_id, stage, model, prompt_sha256, input_tokens, output_tokens,
                 cost_usd, num_turns, session_id, stop_reason),
            )
            self._conn.commit()

    def run_cost(self, run_id: str) -> float:
        with self._lock:
            row = self._conn.execute(
                "SELECT COALESCE(SUM(cost_usd), 0.0) AS c FROM llm_calls WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        return float(row["c"])

    def run_call_count(self, run_id: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM llm_calls WHERE run_id = ?", (run_id,)
            ).fetchone()
        return int(row["n"])

    # ------------------------------------------------------------- cost analytics
    def totals(self) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) n, COALESCE(SUM(cost_usd),0) c, COUNT(DISTINCT run_id) r "
                "FROM llm_calls"
            ).fetchone()
        return {"calls": int(row["n"]), "cost_usd": float(row["c"]), "runs": int(row["r"])}

    def cost_by_model(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT model, COUNT(*) calls, COALESCE(SUM(cost_usd),0) cost, "
                "COALESCE(SUM(input_tokens),0) input_tokens, "
                "COALESCE(SUM(output_tokens),0) output_tokens "
                "FROM llm_calls GROUP BY model ORDER BY cost DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def cost_by_stage(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT stage, COUNT(*) calls, COALESCE(SUM(cost_usd),0) cost "
                "FROM llm_calls GROUP BY stage ORDER BY cost DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def recent_run_costs(self, limit: int = 20) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT run_id, COUNT(*) calls, COALESCE(SUM(cost_usd),0) cost, MAX(ts) ts "
                "FROM llm_calls GROUP BY run_id ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # -------------------------------------------------------------- findings ledger
    def record_finding(
        self,
        *,
        program_name: str,
        run_id: str,
        dedup_key: str,
        title: str | None,
        verdict: str | None,
        validated_severity: str | None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR IGNORE INTO findings_ledger
                   (ts, program_name, run_id, dedup_key, title, verdict, validated_severity)
                   VALUES (?,?,?,?,?,?,?)""",
                (_now(), program_name, run_id, dedup_key, title, verdict, validated_severity),
            )
            self._conn.commit()

    def prior_sightings(self, program_name: str, dedup_key: str, exclude_run_id: str) -> list[dict]:
        """Earlier ledger entries for the same (program, dedup_key) from other runs —
        used to flag likely resubmissions in the report."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT run_id, verdict, validated_severity, ts FROM findings_ledger
                   WHERE program_name = ? AND dedup_key = ? AND run_id != ?
                   ORDER BY ts""",
                (program_name, dedup_key, exclude_run_id),
            ).fetchall()
        return [dict(r) for r in rows]
