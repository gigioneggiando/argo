"""Two processes migrating the same fresh ledger must not crash on the slower ALTER TABLE.

Regression: parallel `argo pipeline` runs started in the same second on 2026-11-05; one died with
`sqlite3.OperationalError: duplicate column name: duration_ms`."""

import sqlite3

import pytest

from argo import ledger as ledger_mod
from argo.ledger import Ledger


class _StaleSchemaConn:
    """Connection proxy whose PRAGMA table_info is empty: the view of a process that read the
    schema before a concurrent process added the migration columns."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, *args):
        if sql.startswith("PRAGMA table_info"):
            return []
        return self._conn.execute(sql, *args)


def test_duplicate_column_from_concurrent_migration_is_ignored(tmp_path):
    lg = Ledger(tmp_path / "l.sqlite")               # columns already added by "process A"
    real = lg._conn
    lg._conn = _StaleSchemaConn(real)
    lg._migrate()                                    # "process B": every ALTER hits a duplicate
    lg._conn = real
    lg.close()


def test_other_operational_errors_still_raise(tmp_path, monkeypatch):
    lg = Ledger(tmp_path / "l.sqlite")
    monkeypatch.setitem(ledger_mod._MIGRATIONS, "no_such_table", [("x", "TEXT")])
    with pytest.raises(sqlite3.OperationalError):
        lg._migrate()
    lg.close()
