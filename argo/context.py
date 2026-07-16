"""RunContext: the per-run object threaded through every stage, plus run-dir path helpers
and the file-collection fallback (manifest first, scratch-dir glob if the manifest is
missing or the session died mid-write)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import PipelineConfig
from .ledger import Ledger
from .models import Scope
from .rendering import extract_manifest
from .runner import ClaudeRunner, LLMResult
from .schemas import validate_scope


class BudgetExceeded(RuntimeError):
    pass


@dataclass
class RunContext:
    run_id: str
    config: PipelineConfig
    runner: ClaudeRunner
    ledger: Ledger
    scope: Optional[Scope] = None
    now: Optional[str] = None  # ISO timestamp; injectable for deterministic report output

    # ---- paths -------------------------------------------------------------------
    @property
    def run_dir(self) -> Path:
        return Path(self.config.runs_dir) / self.run_id

    @property
    def repo_dir(self) -> Path:
        return self.run_dir / "repo"

    @property
    def scope_path(self) -> Path:
        return self.run_dir / "scope.json"

    @property
    def meta_path(self) -> Path:
        return self.run_dir / "meta.json"

    @property
    def prompts_out_dir(self) -> Path:
        return self.run_dir / "prompts"

    @property
    def findings_dir(self) -> Path:
        return self.run_dir / "findings"

    @property
    def variant_logs_dir(self) -> Path:
        """Per-focus VARIANT_HUNT_LOG markdown (coverage forcing-function from the audit stage):
        one row per variant-family member + the invariant-checklist results."""
        return self.run_dir / "variant_logs"

    @property
    def validated_findings_path(self) -> Path:
        return self.run_dir / "validated_findings.json"

    @property
    def repo_profile_path(self) -> Path:
        return self.run_dir / "repo_profile.json"

    @property
    def ground_truth_path(self) -> Path:
        """Recon's structured ground-truth pack (invariants / baseline-correct refs / variant
        families / FP carve-outs per focus). Best-effort: the authoritative copy is baked into
        each audit prompt; this file lets audit/validate/report consume it programmatically."""
        return self.run_dir / "ground_truth.json"

    @property
    def research_brief_path(self) -> Path:
        return self.run_dir / "research_brief.md"

    @property
    def threat_intel_path(self) -> Path:
        return self.run_dir / "threat_intel.json"

    @property
    def drafts_dir(self) -> Path:
        return self.run_dir / "submission_drafts"

    @property
    def assets_dir(self) -> Path:
        return Path(self.config.prompts_dir)

    def work_dir(self, *parts: str) -> Path:
        return self.run_dir.joinpath("work", *parts)

    def timestamp(self) -> str:
        return self.now or datetime.now(timezone.utc).isoformat()

    # ---- scope -------------------------------------------------------------------
    def load_scope(self) -> Scope:
        if self.scope is not None:
            return self.scope
        raw = json.loads(self.scope_path.read_text(encoding="utf-8-sig"))
        validate_scope(raw, self.assets_dir)  # schema is authoritative
        self.scope = Scope.model_validate(raw)
        return self.scope

    # ---- budget ------------------------------------------------------------------
    def assert_budget(self) -> None:
        cap = self.config.budget_usd
        if cap is None:
            return
        spent = self.ledger.run_cost(self.run_id)
        if spent >= cap:
            raise BudgetExceeded(
                f"Per-run budget ${cap:.2f} reached (spent ${spent:.4f}); aborting before "
                "launching another session."
            )


# ----------------------------------------------------------------- artifact collection
def collect_output_files(result: LLMResult, glob_pattern: str) -> list[Path]:
    """Resolve the files a session wrote. Prefer the manifest's index; fall back to globbing
    the scratch dir so partial results survive a missing manifest or a died-mid-write session.
    """
    work_dir = result.work_dir
    found: list[Path] = []
    manifest = extract_manifest(result.text)
    if manifest:
        for art in manifest.get("artifacts", []):
            rel = art.get("path")
            if not rel:
                continue
            p = (work_dir / rel)
            if p.exists():
                found.append(p)
    # Always union with a scratch-dir glob: covers missing/partial manifests and any file the
    # model wrote but forgot to index.
    for p in sorted(work_dir.glob(glob_pattern)):
        if p not in found and p.is_file():
            found.append(p)
    return found
