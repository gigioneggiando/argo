"""Per-run progress telemetry: a small ``status.json`` written into the run dir and updated at
each stage boundary, so a UI/API can show a live timeline + cost instead of a blind spinner.

This is intentionally file-based (like every other artifact): it survives process boundaries and
is readable by anyone watching the run dir, with no in-memory coupling to the producer.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .context import RunContext

ALL_STAGES = ("ingest", "recon", "audit", "validate", "report")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ProgressReporter:
    """Tracks stage state for one run and persists it to ``runs/<id>/status.json``.

    Thread-safe: stages may update from the orchestrator thread while a reader polls the file.
    Cost is read live from the ledger so it advances even mid-stage.
    """

    def __init__(self, ctx: "RunContext", stages: tuple[str, ...] | list[str],
                 initial_status: dict | None = None):
        self.ctx = ctx
        self.stages = list(stages)
        self._lock = threading.Lock()
        self._state = str(initial_status.get("state") or "starting") if initial_status else "starting"
        self._error: Optional[str] = initial_status.get("error") if initial_status else None
        self._retry_after: Optional[str] = initial_status.get("retry_after") if initial_status else None
        self._started_at = (initial_status.get("started_at") if initial_status else None) or _now()
        self._stage_state = {s: {"name": s, "state": "pending"} for s in self.stages}
        if initial_status:
            for st in initial_status.get("stages") or []:
                name = st.get("name") if isinstance(st, dict) else None
                if name in self._stage_state:
                    self._stage_state[name].update(st)
        self._begun = False

    # -- lifecycle ------------------------------------------------------------------
    def begin(self) -> None:
        with self._lock:
            if self._begun:
                return
            self._begun = True
            self._state = "running"
            self._error = None
            self._retry_after = None
            self._write()

    def start_stage(self, stage: str) -> None:
        with self._lock:
            st = self._stage_state.setdefault(stage, {"name": stage, "state": "pending"})
            st["state"] = "running"
            st["started_at"] = _now()
            st.pop("ended_at", None)
            st.pop("error", None)
            st.pop("retry_after", None)
            self._state = "running"
            self._error = None
            self._retry_after = None
            self._write()

    def finish_stage(self, stage: str) -> None:
        with self._lock:
            st = self._stage_state.setdefault(stage, {"name": stage, "state": "pending"})
            st["state"] = "done"
            st["ended_at"] = _now()
            st.pop("error", None)
            st.pop("retry_after", None)
            self._write()

    def fail_stage(self, stage: str, error: str, retry_after: str | None = None) -> None:
        with self._lock:
            st = self._stage_state.setdefault(stage, {"name": stage, "state": "pending"})
            st["state"] = "failed"
            st["ended_at"] = _now()
            st["error"] = error
            if retry_after:
                st["retry_after"] = retry_after
            else:
                st.pop("retry_after", None)
            self._state = "failed"
            self._error = error
            self._retry_after = retry_after
            self._write()

    def complete(self) -> None:
        with self._lock:
            self._state = "completed"
            self._error = None
            self._retry_after = None
            self._write()

    def cancelled(self) -> None:
        with self._lock:
            self._state = "cancelled"
            for st in self._stage_state.values():
                if st["state"] in ("running", "pending"):
                    st["state"] = "skipped"
            self._write()

    def fail(self, error: str) -> None:
        with self._lock:
            self._state = "failed"
            self._error = error
            self._retry_after = None
            self._write()

    # -- snapshot -------------------------------------------------------------------
    def snapshot(self) -> dict:
        """Build the current status dict (cost + artifacts read live from disk/ledger)."""
        current = next((s for s in self.stages if self._stage_state.get(s, {}).get("state")
                        == "running"), None)
        try:
            cost = self.ctx.ledger.run_cost(self.ctx.run_id)
        except Exception:  # pragma: no cover - ledger closed/unavailable
            cost = 0.0
        return {
            "run_id": self.ctx.run_id,
            "state": self._state,
            "current_stage": current,
            "stages": [self._stage_state[s] for s in self.stages],
            "artifacts": self._artifacts(),
            "cost_usd": round(cost, 6),
            "error": self._error,
            "retry_after": self._retry_after,
            "started_at": self._started_at,
            "updated_at": _now(),
        }

    def _artifacts(self) -> dict:
        rd = self.ctx.run_dir
        prompts = list((rd / "prompts").glob("audit_*.md")) if (rd / "prompts").exists() else []
        findings = list((rd / "findings").glob("*.json")) if (rd / "findings").exists() else []
        drafts = list((rd / "submission_drafts").glob("*.md")) \
            if (rd / "submission_drafts").exists() else []
        return {
            "scope": (rd / "scope.json").exists(),
            "repo_profile": (rd / "repo_profile.json").exists(),
            "synthesis_notes": (rd / "synthesis_notes.md").exists(),
            "prompts": len(prompts),
            "findings": len(findings),
            "validated_findings": (rd / "validated_findings.json").exists(),
            "report": (rd / "REPORT.md").exists(),
            "drafts": len(drafts),
        }

    def _write(self) -> None:
        """Persist status.json atomically (temp + replace). Telemetry must NEVER crash the run:
        on Windows ``os.replace`` can transiently fail (WinError 5) when a concurrent reader has
        the file open, so we retry briefly and then drop this frame — the next update catches up.
        Readers (``read_status``) tolerate a missing/partial read."""
        self.ctx.run_dir.mkdir(parents=True, exist_ok=True)
        path = self.ctx.run_dir / "status.json"
        tmp = path.with_suffix(".json.tmp")
        data = json.dumps(self.snapshot(), indent=2)
        for _ in range(5):
            try:
                tmp.write_text(data, encoding="utf-8")
                tmp.replace(path)
                return
            except PermissionError:
                time.sleep(0.02)
            except OSError:
                return


def read_status(run_dir: Path) -> Optional[dict]:
    """Read a run's status.json, or None if absent/unreadable."""
    p = Path(run_dir) / "status.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError):
        return None
