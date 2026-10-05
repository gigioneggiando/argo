"""Private, revision-bound target memory stays useful without silently trusting old facts."""

from __future__ import annotations

import json
from pathlib import Path

from argo.config import PipelineConfig, load_pipeline_config, write_pipeline_config
from argo.orchestrator import run_pipeline
from argo.target_memory import TargetMemoryStore, canonical_target, fresh_facts, prompt_context

from conftest import BRIEF, REPO


def test_remote_identity_normalizes_https_and_ssh_forms():
    https = canonical_target("https://GitHub.com/Example/Widget.git", True)
    ssh = canonical_target("git@github.com:example/widget.git", True)

    assert https == ssh
    assert https.key == "remote:github.com/example/widget"


def test_changed_or_unknown_commit_stales_facts(tmp_path):
    store = TargetMemoryStore(tmp_path / "memory")
    target = canonical_target("https://github.com/example/widget", True)
    store.upsert(target, "a" * 40, [
        ("invariant", "Only owners can read an order.", "recon:ground_truth", ["ground_truth.json"]),
    ])

    same = store.load(target, "a" * 40)
    assert len(fresh_facts(same)) == 1
    assert "Only owners" in prompt_context(fresh_facts(same))

    changed = store.load(target, "b" * 40)
    assert not fresh_facts(changed)
    assert changed.facts[0].freshness == "stale"
    assert changed.facts[0].invalidated_by == "b" * 40
    # The stale state is durable; a later run cannot accidentally revive it without re-observing it.
    assert TargetMemoryStore(tmp_path / "memory").load(target, "b" * 40).facts[0].freshness == "stale"


def test_target_memory_directory_round_trips_through_saved_config(tmp_path):
    config_path = tmp_path / "config.json"
    write_pipeline_config(
        config_path,
        PipelineConfig(target_memory_enabled=False, target_memory_dir=Path("private-memory")),
    )

    restored = load_pipeline_config(config_path)

    assert restored.target_memory_enabled is False
    assert restored.target_memory_dir == Path("private-memory")


def test_pipeline_emits_private_memory_snapshot_and_captures_recon_facts(env, tmp_path):
    ctx = env(target_memory_dir=tmp_path / "private-memory")
    run_pipeline(ctx, BRIEF, str(REPO), research_enabled=False)

    snapshot = json.loads(ctx.target_memory_path.read_text(encoding="utf-8"))
    assert snapshot["target"]["is_remote"] is False
    assert snapshot["note"].startswith("Private local target memory")
    status = json.loads((ctx.run_dir / "status.json").read_text(encoding="utf-8"))
    assert status["artifacts"]["target_memory"] is True

    files = list((tmp_path / "private-memory").glob("*.json"))
    assert len(files) == 1
    memory = json.loads(files[0].read_text(encoding="utf-8"))
    assert any(fact["kind"] == "entry_point" for fact in memory["facts"])
    # The fixture has no Git revision, so conservative invalidation prevents it from becoming seed.
    assert all(fact["freshness"] == "stale" for fact in memory["facts"])
