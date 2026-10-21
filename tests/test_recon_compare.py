"""Recon ablation and offline artifact-comparison regressions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from argo.cli import app
from argo.knowledge import format_for_prompt
from argo.orchestrator import run_pipeline
from argo.recon_compare import compare_recon
from conftest import BRIEF, REPO


def _capture_recon_prompt(ctx, sink: list[str]) -> None:
    original = ctx.runner._invoke

    def capture(**kwargs):
        if kwargs["stage"] == "recon":
            sink.append(kwargs["prompt"])
        return original(**kwargs)

    ctx.runner._invoke = capture


def _minimal_run(root: Path, name: str, *, prompt: str = "Inspect src/a.py:7 for CWE-22.\n",
                 commit: str = "a" * 40, model: str = "model-a", backend: str = "mock",
                 inputs: bool = True) -> Path:
    run = root / name
    (run / "prompts").mkdir(parents=True)
    (run / "repo_profile.json").write_text(
        json.dumps({"archetype": "library_sdk", "run_path": str(run)}, indent=2),
        encoding="utf-8")
    (run / "prompts" / "audit_main.md").write_text(
        prompt.replace("<RUN>", str(run)), encoding="utf-8")
    (run / "meta.json").write_text(json.dumps({"repo_commit": commit}), encoding="utf-8")
    if inputs:
        (run / "recon_inputs.json").write_text(json.dumps({
            "schema_version": 1,
            "base_prompt_sha256": "same-base",
            "context_pack_sha256": None,
            "vuln_index_enabled": name.endswith("candidate"),
            "vuln_index_sha256": "index" if name.endswith("candidate") else None,
            "recon_settings": {"runner": "mock", "model": model},
        }), encoding="utf-8")
    (run / "llm_log.jsonl").write_text(json.dumps({
        "stage": "recon", "backend": backend, "model": model, "is_error": False,
        "input_tokens": 1, "output_tokens": 1, "cost_usd": 0.0,
    }) + "\n", encoding="utf-8")
    return run


def _tree_hashes(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


def test_vuln_index_ablation_changes_only_index_input(env):
    enabled = env(run_id="INDEX-ON", vuln_index_enabled=True, target_memory_enabled=False)
    disabled = env(run_id="INDEX-OFF", vuln_index_enabled=False, target_memory_enabled=False)
    enabled_prompts: list[str] = []
    disabled_prompts: list[str] = []
    _capture_recon_prompt(enabled, enabled_prompts)
    _capture_recon_prompt(disabled, disabled_prompts)

    run_pipeline(enabled, BRIEF, str(REPO), dry_run=True, research_enabled=False)
    run_pipeline(disabled, BRIEF, str(REPO), dry_run=True, research_enabled=False)

    marker = format_for_prompt()
    assert marker in enabled_prompts[0]
    assert marker not in disabled_prompts[0]
    on_inputs = json.loads((enabled.run_dir / "recon_inputs.json").read_text(encoding="utf-8"))
    off_inputs = json.loads((disabled.run_dir / "recon_inputs.json").read_text(encoding="utf-8"))
    assert on_inputs["base_prompt_sha256"] == off_inputs["base_prompt_sha256"]
    assert on_inputs["vuln_index_sha256"] is not None
    assert off_inputs["vuln_index_sha256"] is None
    assert json.loads((disabled.run_dir / "config.json").read_text(encoding="utf-8"))[
        "vuln_index_enabled"] is False

    # The fixture repository is not a git checkout, so set equal recorded revisions explicitly.
    for ctx in (enabled, disabled):
        meta = json.loads(ctx.meta_path.read_text(encoding="utf-8"))
        meta["repo_commit"] = "a" * 40
        ctx.meta_path.write_text(json.dumps(meta), encoding="utf-8")
    result = compare_recon(enabled.run_dir, disabled.run_dir)
    assert result["same_repo_commit"] is True
    assert result["same_non_index_inputs"] is True
    assert result["baseline"]["inputs"]["vuln_index_enabled"] is True
    assert result["candidate"]["inputs"]["vuln_index_enabled"] is False


def test_compare_normalizes_run_paths_json_order_and_cwe_case(tmp_path):
    baseline = _minimal_run(tmp_path, "baseline", prompt="Path <RUN>/repo/src/a.py:7 cwe-22\n")
    candidate = _minimal_run(tmp_path, "candidate", prompt="Path <RUN>/repo/src/a.py:7 CWE-22\n")
    # Use identical case for artifact equality, but retain the case-insensitive signal assertion.
    (candidate / "prompts" / "audit_main.md").write_text(
        f"Path {candidate}/repo/src/a.py:7 cwe-22\n", encoding="utf-8")
    profile = {"run_path": str(candidate), "archetype": "library_sdk"}
    (candidate / "repo_profile.json").write_text(json.dumps(profile), encoding="utf-8")

    result = compare_recon(baseline, candidate)
    assert result["changes"] == []
    assert result["baseline"]["signals"]["cwes"] == ["CWE-22"]
    assert result["candidate"]["signals"]["unique_citations"] == 1


def test_compare_warns_on_confounds_and_applies_global_diff_cap(tmp_path):
    baseline = _minimal_run(tmp_path, "baseline", prompt="one\ntwo\nthree\n", commit="a" * 40)
    candidate = _minimal_run(tmp_path, "candidate", prompt="alpha\nbeta\ngamma\n",
                             commit="b" * 40, model="model-b")
    (candidate / "prompts" / "audit_extra.md").write_text("extra\nlines\nhere\n", encoding="utf-8")

    result = compare_recon(baseline, candidate, max_diff_lines=3)
    assert result["same_repo_commit"] is False
    assert result["same_non_index_inputs"] is False
    assert any("source equivalence" in warning for warning in result["warnings"])
    assert any("Non-index recon inputs differ" in warning for warning in result["warnings"])
    assert any("backend/model" in warning for warning in result["warnings"])
    assert sum(len(change["diff"].splitlines()) for change in result["changes"]) <= 3
    assert any(change["diff_truncated"] for change in result["changes"])
    assert {change["change"] for change in result["changes"]} >= {"modified", "added"}


def test_compare_legacy_inputs_and_missing_backend_are_not_claimed_equivalent(tmp_path):
    baseline = _minimal_run(tmp_path, "baseline", inputs=False, backend="")
    candidate = _minimal_run(tmp_path, "candidate")
    result = compare_recon(baseline, candidate)
    assert result["same_non_index_inputs"] is None
    assert any("Legacy run" in warning for warning in result["warnings"])
    assert any("backend/model" in warning for warning in result["warnings"])


@pytest.mark.parametrize("damage", ["profile", "prompts", "oversized"])
def test_compare_rejects_incomplete_or_oversized_runs(tmp_path, damage):
    baseline = _minimal_run(tmp_path, "baseline")
    candidate = _minimal_run(tmp_path, "candidate")
    if damage == "profile":
        (candidate / "repo_profile.json").unlink()
    elif damage == "prompts":
        (candidate / "prompts" / "audit_main.md").unlink()
    else:
        from argo.recon_compare import MAX_FILE_BYTES
        with (candidate / "prompts" / "audit_main.md").open("wb") as handle:
            handle.truncate(MAX_FILE_BYTES + 1)
    with pytest.raises((OSError, ValueError)):
        compare_recon(baseline, candidate)


def test_compare_recon_cli_is_read_only_and_emits_json(tmp_path):
    baseline = _minimal_run(tmp_path, "baseline")
    candidate = _minimal_run(tmp_path, "candidate")
    before = _tree_hashes(tmp_path)
    result = CliRunner().invoke(app, [
        "compare-recon", "--baseline", str(baseline), "--candidate", str(candidate),
        "--max-diff-lines", "10",
    ])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["schema_version"] == 1
    assert _tree_hashes(tmp_path) == before


def test_pipeline_cli_persists_no_vuln_index_for_resume(tmp_path):
    runs = tmp_path / "runs"
    result = CliRunner().invoke(app, [
        "pipeline", "--brief", str(BRIEF), "--repo", str(REPO), "--runner", "mock",
        "--runs-dir", str(runs), "--scenario", "happy", "--run", "CLI-INDEX-OFF",
        "--dry-run", "--no-research", "--no-vuln-index",
    ])
    assert result.exit_code == 0, result.output
    config = json.loads((runs / "CLI-INDEX-OFF" / "config.json").read_text(encoding="utf-8"))
    inputs = json.loads((runs / "CLI-INDEX-OFF" / "recon_inputs.json").read_text(
        encoding="utf-8"))
    assert config["vuln_index_enabled"] is False
    assert inputs["vuln_index_enabled"] is False
