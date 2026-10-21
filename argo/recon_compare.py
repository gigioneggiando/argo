"""Offline comparison of recon artifacts; structural counts are not quality scores."""

from __future__ import annotations

import difflib
import hashlib
import json
import re
from pathlib import Path

from .context import atomic_write_json

MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 8_000_000
MAX_PROMPTS = 64


def _read(path: Path) -> str:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"artifact exceeds {MAX_FILE_BYTES} bytes: {path.name}")
    return path.read_text(encoding="utf-8-sig").replace("\r\n", "\n")


def _object(path: Path) -> dict:
    value = json.loads(_read(path))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path.name}")
    return value


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _normalize(text: str, run_dir: Path) -> str:
    # JSON embeds escaped Windows paths, Markdown usually embeds native paths.
    root = str(run_dir.resolve())
    for path, marker in ((str((run_dir / "repo").resolve()), "<REPO>"), (root, "<RUN>")):
        for variant in sorted({path, path.replace("\\", "/"), path.replace("\\", "\\\\")},
                              key=len, reverse=True):
            text = text.replace(variant, marker)
    return text


def record_inputs(ctx, prompt: str, index_block: str) -> None:
    """Record input hashes for future comparisons, without saving the full prompt."""
    base = prompt.replace(index_block, "", 1) if index_block else prompt
    atomic_write_json(ctx.run_dir / "recon_inputs.json", {
        "schema_version": 1,
        "base_prompt_sha256": _sha(_normalize(base, ctx.run_dir)),
        "vuln_index_enabled": ctx.config.vuln_index_enabled,
        "vuln_index_sha256": _sha(index_block) if index_block else None,
        "context_pack_sha256": _sha(_read(ctx.context_pack_path))
        if ctx.context_pack_path.exists() else None,
        "recon_settings": {
            "runner": ctx.config.runner, "model": ctx.config.model_for("recon"),
            "fallbacks": ctx.config.runner_fallbacks,
            "timeout_s": ctx.config.timeout_for("recon"),
            "session_max_turns": ctx.config.session_max_turns,
            "session_max_cost_usd": ctx.config.session_max_cost_usd,
            "budget_usd": ctx.config.budget_usd,
        },
    })


def _snapshot(run_dir: Path) -> dict:
    if not run_dir.is_dir():
        raise ValueError(f"run directory does not exist: {run_dir}")
    profile = _object(run_dir / "repo_profile.json")  # Required: don't compare incomplete recon.
    prompts = sorted(p for p in (run_dir / "prompts").glob("*.md")
                     if re.match(r"audit[-_]", p.name, re.I))
    if not prompts:
        raise ValueError(f"no audit prompts in {run_dir}")
    if len(prompts) > MAX_PROMPTS:
        raise ValueError(f"more than {MAX_PROMPTS} audit prompts")
    paths = [run_dir / "repo_profile.json", *prompts]
    paths += [run_dir / name for name in ("ground_truth.json", "synthesis_notes.md")
              if (run_dir / name).exists()]
    if sum(p.stat().st_size for p in paths) > MAX_TOTAL_BYTES:
        raise ValueError(f"recon artifacts exceed {MAX_TOTAL_BYTES} bytes")
    artifacts = {}
    for path in paths:
        text = _read(path)
        if path.suffix == ".json":
            text = json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n"
        artifacts[path.relative_to(run_dir).as_posix()] = _normalize(text, run_dir)
    prompt_text = "\n".join(artifacts[p.relative_to(run_dir).as_posix()] for p in prompts)
    cwes = sorted({match.upper() for match in re.findall(r"\bCWE-\d+\b", prompt_text, re.I)})
    citations = set(re.findall(r"[\w./\\-]+\.[A-Za-z0-9]+:\d+\b", prompt_text))
    inputs_path = run_dir / "recon_inputs.json"
    meta_path = run_dir / "meta.json"
    calls = []
    log = run_dir / "llm_log.jsonl"
    if log.exists():
        for line in _read(log).splitlines():
            row = json.loads(line)
            if row.get("stage") == "recon":
                calls.append({key: row.get(key) for key in (
                    "backend", "model", "is_error", "input_tokens", "output_tokens", "cost_usd")})
    return {
        "run": run_dir.name,
        "repo_commit": _object(meta_path).get("repo_commit") if meta_path.exists() else None,
        "inputs": _object(inputs_path) if inputs_path.exists() else None,
        "signals": {"archetype": profile.get("archetype"), "prompt_count": len(prompts),
                    "prompt_characters": len(prompt_text), "unique_citations": len(citations),
                    "cwes": cwes},
        "recon_calls": calls,
        "artifacts": artifacts,
    }


def compare_recon(baseline: Path, candidate: Path, *, max_diff_lines: int = 200) -> dict:
    """Compare two existing runs, with a global diff budget and explicit comparability limits."""
    if not 0 <= max_diff_lines <= 5000:
        raise ValueError("max_diff_lines must be between 0 and 5000")
    a, b = _snapshot(Path(baseline)), _snapshot(Path(candidate))
    warnings = ["Structural counts do not measure precision or recall. Repeat matched runs before attributing differences to the index.",
                "Commit equality uses recorded HEAD metadata; it does not prove clean or identical working trees."]
    same_commit = bool(a["repo_commit"] and a["repo_commit"] == b["repo_commit"])
    if not same_commit:
        warnings.append("Matching repository commits are unavailable; source equivalence is unverified.")
    input_match = None
    if a["inputs"] and b["inputs"]:
        input_match = bool(a["inputs"].get("base_prompt_sha256") and
                          b["inputs"].get("base_prompt_sha256")) and all(
            a["inputs"].get(key) == b["inputs"].get(key)
            for key in ("base_prompt_sha256", "context_pack_sha256", "recon_settings"))
        if not input_match:
            warnings.append("Non-index recon inputs differ; this is not an isolated index comparison.")
    else:
        warnings.append("Legacy run lacks recon input hashes; input equivalence is unknown.")
    served = []
    for snapshot in (a, b):
        served.append({(row["backend"], row["model"]) for row in snapshot["recon_calls"]
                       if row["is_error"] is False and row["backend"] and row["model"]})
    if not served[0] or not served[1] or served[0] != served[1]:
        warnings.append("Matching successful recon backend/model records are unavailable; check fallback and partial recovery.")
    changes = []
    remaining = max_diff_lines
    for name in sorted(a["artifacts"].keys() | b["artifacts"].keys()):
        before, after = a["artifacts"].get(name), b["artifacts"].get(name)
        if before == after:
            continue
        lines = list(difflib.unified_diff((before or "").splitlines(), (after or "").splitlines(),
                     fromfile=f"baseline/{name}", tofile=f"candidate/{name}", lineterm=""))
        shown = lines[:remaining]
        remaining -= len(shown)
        changes.append({"artifact": name,
                        "change": "added" if before is None else "removed" if after is None else "modified",
                        "diff": "\n".join(shown), "diff_truncated": len(shown) < len(lines)})
    for snapshot in (a, b):
        del snapshot["artifacts"]
    return {"schema_version": 1, "baseline": a, "candidate": b,
            "same_repo_commit": same_commit, "same_non_index_inputs": input_match,
            "warnings": warnings, "changes": changes}
