"""A2 — triager accept-rate (ledger feedback) + quality report pairing it with benchmark recall."""

import json
import sqlite3

from argo.ledger import Ledger
from argo.quality import quality_report, write_quality


def _seed(led: Ledger) -> None:
    for i, sev in enumerate(["Critical", "High", "High", "Medium"]):
        led.record_finding(program_name="acme", run_id="r1", dedup_key=f"k{i}",
                           title=f"f{i}", verdict="confirmed", validated_severity=sev)


def test_record_feedback_and_accept_rate(tmp_path):
    led = Ledger(tmp_path / "l.sqlite")
    _seed(led)
    # no feedback yet -> all pending, rate is None
    ar0 = led.accept_rate("acme")
    assert ar0["judged"] == 0 and ar0["pending"] == 4 and ar0["accept_rate"] is None
    # accept 3, reject 1
    assert led.record_triager_feedback(program_name="acme", dedup_key="k0", accepted=True) == 1
    led.record_triager_feedback(program_name="acme", dedup_key="k1", accepted=True)
    led.record_triager_feedback(program_name="acme", dedup_key="k2", accepted=True)
    led.record_triager_feedback(program_name="acme", dedup_key="k3", accepted=False,
                                feedback="dup of a known issue")
    ar = led.accept_rate("acme")
    assert (ar["accepted"], ar["rejected"], ar["pending"], ar["judged"]) == (3, 1, 0, 4)
    assert ar["accept_rate"] == 0.75
    assert ar["by_severity"]["High"] == {"accepted": 2, "rejected": 0, "pending": 0}
    led.close()


def test_feedback_scoped_to_run(tmp_path):
    led = Ledger(tmp_path / "l.sqlite")
    led.record_finding(program_name="p", run_id="rA", dedup_key="k", title="t",
                       verdict="confirmed", validated_severity="High")
    led.record_finding(program_name="p", run_id="rB", dedup_key="k", title="t",
                       verdict="confirmed", validated_severity="High")
    # scoping to rA updates only that row
    assert led.record_triager_feedback(program_name="p", dedup_key="k", accepted=True,
                                       run_id="rA") == 1
    ar = led.accept_rate("p")
    assert ar["accepted"] == 1 and ar["pending"] == 1
    led.close()


def test_ledger_migration_adds_columns(tmp_path):
    # simulate an OLD db (findings_ledger without the triager_* columns), then open with Ledger
    dbp = tmp_path / "old.sqlite"
    con = sqlite3.connect(dbp)
    con.execute("""CREATE TABLE findings_ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT,
                   program_name TEXT, run_id TEXT, dedup_key TEXT, title TEXT, verdict TEXT,
                   validated_severity TEXT, UNIQUE(program_name, dedup_key, run_id))""")
    con.execute("INSERT INTO findings_ledger (ts,program_name,run_id,dedup_key,title,verdict,"
                "validated_severity) VALUES ('t','acme','r','k','f','confirmed','High')")
    con.commit(); con.close()
    led = Ledger(dbp)                                   # _migrate adds the triager_* columns
    cols = {r["name"] for r in led._conn.execute("PRAGMA table_info(findings_ledger)")}
    assert {"triager_accepted", "triager_feedback", "triager_ts"} <= cols
    assert led.record_triager_feedback(program_name="acme", dedup_key="k", accepted=True) == 1
    assert led.accept_rate("acme")["accepted"] == 1
    led.close()


def test_cli_feedback_import_and_quality(tmp_path):
    from typer.testing import CliRunner
    from argo.cli import app
    dbp = tmp_path / "l.sqlite"
    led = Ledger(dbp)
    led.record_finding(program_name="acme", run_id="r", dedup_key="k", title="t",
                       verdict="confirmed", validated_severity="High")
    led.close()
    imp = tmp_path / "fb.json"
    imp.write_text(json.dumps([{"program_name": "acme", "dedup_key": "k", "accepted": True}]),
                   encoding="utf-8")
    runner = CliRunner()
    r1 = runner.invoke(app, ["feedback", "--import", str(imp), "--ledger", str(dbp)])
    assert r1.exit_code == 0, r1.output
    assert '"rows_updated": 1' in r1.output
    r2 = runner.invoke(app, ["quality", "--program", "acme", "--ledger", str(dbp),
                             "--runs-dir", str(tmp_path / "runs")])
    assert r2.exit_code == 0, r2.output
    assert '"real_world_accept_rate": 1.0' in r2.output


def test_quality_report_pairs_accept_rate_and_recall(tmp_path):
    led = Ledger(tmp_path / "l.sqlite")
    _seed(led)
    led.record_triager_feedback(program_name="acme", dedup_key="k0", accepted=True)
    led.record_triager_feedback(program_name="acme", dedup_key="k1", accepted=False)
    bench = tmp_path / "benchmark_report.json"
    bench.write_text(json.dumps({"suite": "s", "totals": {"recall": 0.8, "precision": 0.9,
                                                          "f1": 0.85, "cases": 2}}), encoding="utf-8")
    rep = quality_report(led, program_name="acme", benchmark_report_path=bench)
    assert rep["headline"]["real_world_accept_rate"] == 0.5
    assert rep["headline"]["real_world_n"] == 2
    assert rep["headline"]["benchmark_recall"] == 0.8
    # write_quality persists quality.json next to the benchmark
    out = write_quality(led, tmp_path, program_name="acme")
    assert (tmp_path / "quality.json").exists() and out["benchmark"]["recall"] == 0.8
    led.close()
