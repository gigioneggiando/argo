"""Persisted UI defaults (Phase 2). These are the form defaults the New Run page loads; the run
request still carries the effective config, so the engine stays simple — this is a small JSON
store, not a second source of truth."""

from __future__ import annotations

import json
import threading
from pathlib import Path

DEFAULTS = {
    "runner": "mock",
    "budget_usd": None,
    "parallel": 3,
    "audit_model": None,
    "calibration": False,
    "models": {},   # per-stage overrides: {ingest, recon, audit, validate, report}
}


class SettingsStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def load(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        return {**DEFAULTS, **(data or {})}

    def save(self, data: dict) -> dict:
        merged = {**DEFAULTS, **(data or {})}
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
        return merged
