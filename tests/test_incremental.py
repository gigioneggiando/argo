"""F4 incremental review treats a diff as invalidation, never as a complete security boundary."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from argo.orchestrator import pipeline_stages
from argo.stages import incremental
from argo.target_memory import TargetMemoryStore, canonical_target


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True).stdout.strip()


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", message, "--quiet")
    return _git(repo, "rev-parse", "HEAD")


def _repo(ctx) -> tuple[Path, str, str]:
    repo = ctx.repo_dir
    repo.mkdir(parents=True)
    _git(repo, "init", "--quiet")
    _git(repo, "config", "user.email", "argo-test@example.invalid")
    _git(repo, "config", "user.name", "Argo test")
    src = repo / "src"
    src.mkdir()
    (src / "service.py").write_text("def transfer(order):\n    return order\n", encoding="utf-8")
    (src / "handler.py").write_text("from service import transfer\n", encoding="utf-8")
    (src / "legacy.py").write_text("def legacy_authorize():\n    return True\n", encoding="utf-8")
    base = _commit(repo, "base")
    (src / "service.py").write_text(
        "def transfer(order):\n    return order.owner_id\n\nclass Ledger:\n    pass\n",
        encoding="utf-8",
    )
    (src / "legacy.py").unlink()
    head = _commit(repo, "change transfer")
    return repo, base, head


def test_incremental_review_emits_changed_neighborhood_and_stales_prior_facts(env, tmp_path):
    ctx = env(incremental_base="placeholder", target_memory_dir=tmp_path / "memory")
    _repo_path, base, head = _repo(ctx)
    ctx.config = ctx.config.with_overrides(incremental_base=base)
    ctx.meta_path.write_text(json.dumps({
        "repo_source": "https://github.com/example/widget.git", "repo_is_url": True,
        "repo_commit": head,
    }), encoding="utf-8")
    identity = canonical_target("https://github.com/example/widget.git", True)
    TargetMemoryStore(ctx.target_memory_dir).upsert(identity, base, [
        ("invariant", "src/service.py: transfer preserves owner isolation.",
         "recon:ground_truth", ["ground_truth.json"]),
        ("entry_point", "src/handler.py: public API entry point.",
         "recon:repo_profile", ["repo_profile.json"]),
        ("invariant", "src/legacy.py: legacy authorization remains enforced.",
         "recon:ground_truth", ["ground_truth.json"]),
    ])
    TargetMemoryStore(ctx.target_memory_dir).upsert(identity, head, [
        ("component", "src/handler.py belongs to the current HEAD component map.",
         "recon:repo_profile", ["repo_profile.json"]),
    ])

    path = incremental.run(ctx)
    review = json.loads(path.read_text(encoding="utf-8"))

    assert review["mode"] == "context_preserving_incremental_review"
    assert review["base_commit"] == base and review["head_commit"] == head
    assert review["changed_files"] == [
        {"status": "D", "path": "src/legacy.py"},
        {"status": "M", "path": "src/service.py"},
    ]
    assert "transfer" in review["candidate_symbols"]
    assert set(review["review_neighborhood"]) >= {
        "src/service.py", "src/handler.py", "src/legacy.py",
    }
    assert review["memory_facts"]["invalidated"][0]["paths"] == ["src/service.py"]
    assert "owner isolation" in review["memory_facts"]["invalidated"][0]["summary"]
    assert any(row["paths"] == ["src/legacy.py"]
               for row in review["memory_facts"]["invalidated"])
    assert review["memory_facts"]["stale_unproven"][0]["state"] == "stale_unproven"
    assert review["memory_facts"]["retained"][0]["state"] == "retained_same_revision"
    prompt = incremental.prompt_context(ctx)
    assert "full-repository context remains mandatory" in prompt
    assert "unchanged code is safe" in prompt
    assert "transfer preserves owner isolation" in prompt


def test_incremental_stage_is_opt_in_and_precedes_recon(env):
    ctx = env(incremental_base="abc123")
    assert pipeline_stages(ctx, research_enabled=False)[:4] == [
        "ingest", "target_memory", "incremental_review", "recon",
    ]
