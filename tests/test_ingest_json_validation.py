"""Ingest keeps its independent JSON gate for artifacts outside Argo's validated tools."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from argo.config import PipelineConfig
from argo.runner import LLMResult
from argo.stages import ingest


class _ExternalArtifactRunner:
    def run(self, **kwargs):
        return LLMResult(text="", model="fixture", prompt_sha256="test",
                         work_dir=kwargs["work_dir"])


def test_ingest_rejects_invalid_scope_from_external_writer(tmp_path):
    brief = tmp_path / "brief.txt"
    brief.write_text("A synthetic brief for the ingest gate.", encoding="utf-8")
    run_dir = tmp_path / "run"
    work = run_dir / "work" / "ingest"
    work.mkdir(parents=True)
    (work / "scope.json").write_text(
        '{"program_name": "test", "program_brief_raw": "literal\nnewline"}',
        encoding="utf-8")
    ctx = SimpleNamespace(
        run_dir=run_dir,
        run_id="test-run",
        config=PipelineConfig(runner="mock", runs_dir=str(tmp_path / "runs"),
                              prompts_dir=str(Path("argo/prompts").resolve())),
        assets_dir=Path("argo/prompts").resolve(),
        runner_for=lambda _stage: _ExternalArtifactRunner(),
        work_dir=lambda *parts: run_dir.joinpath("work", *parts),
        scope=None,
    )

    with pytest.raises(ValueError, match="Invalid control character"):
        ingest.run(ctx, brief_path=brief, repo="synthetic/local-target", repo_is_url=False)

    assert not (run_dir / "scope.json").exists()
