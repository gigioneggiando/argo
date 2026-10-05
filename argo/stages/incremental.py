"""Deterministic, context-preserving PR/incremental-review planning.

This is deliberately not a diff scanner.  The diff is an invalidation signal: we identify changed
files, candidate symbols and a bounded textual neighbourhood, mark prior target-memory facts stale
or directly affected, and hand recon a review plan while it still has the *entire* repository
mounted read-only. Nothing in an unchanged file is called safe or skipped by the pipeline.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

from ..context import RunContext, atomic_write_json
from ..target_memory import TargetMemoryStore, canonical_target

_SYMBOL = re.compile(r"^\s*(?:async\s+)?(?:def|class|function|func|fn|type|interface)\s+([A-Za-z_$][\w$]*)",
                     re.MULTILINE)
_TEXT_EXTENSIONS = {".c", ".cc", ".cpp", ".cs", ".go", ".java", ".js", ".jsx", ".mjs",
                    ".php", ".py", ".rb", ".rs", ".scala", ".swift", ".ts", ".tsx"}


def _meta(ctx: RunContext) -> dict:
    try:
        raw = json.loads(ctx.meta_path.read_text(encoding="utf-8-sig"))
        return raw if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        return {}


def _safe_ref(ref: str) -> str:
    value = (ref or "").strip()
    if not value or value.startswith("-") or "\x00" in value:
        raise ValueError("incremental base must be a non-option Git commit or ref")
    return value


def _git(repo: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-c", f"safe.directory={repo.resolve()}", "-c", "protocol.ext.allow=never",
             "-c", "core.hooksPath=NUL" if os.name == "nt" else "core.hooksPath=/dev/null",
             "-C", str(repo), *args],
            check=True, capture_output=True, text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("incremental review requires Git") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "Git command failed").strip().replace("\n", " ")
        raise ValueError(f"incremental review Git operation failed: {detail[:300]}") from exc
    return result.stdout


def _resolve(repo: Path, ref: str) -> str:
    value = _safe_ref(ref)
    try:
        return _git(repo, "rev-parse", "--verify", "--end-of-options", f"{value}^{{commit}}").strip()
    except ValueError:
        # A normal clone keeps remote-tracking refs, while a user naturally writes `main` rather
        # than `origin/main`. This fallback does not broaden the target or contact the network.
        if "/" not in value:
            return _git(repo, "rev-parse", "--verify", "--end-of-options",
                        f"origin/{value}^{{commit}}").strip()
        raise


def _changed_files(repo: Path, base: str, head: str) -> list[dict]:
    raw = _git(repo, "diff", "--name-status", "-z", base, head, "--")
    fields = raw.split("\0")
    rows: list[dict] = []
    index = 0
    while index < len(fields):
        status = fields[index]
        index += 1
        if not status:
            continue
        if status[:1] in {"R", "C"}:
            if index + 1 > len(fields):
                break
            old, new = fields[index:index + 2]
            index += 2
            rows.append({"status": status, "path": new, "old_path": old})
        elif index < len(fields):
            rows.append({"status": status, "path": fields[index]})
            index += 1
    return sorted(rows, key=lambda row: (row["path"], row["status"]))


def _changed_symbols(repo: Path, paths: list[str]) -> list[str]:
    symbols: set[str] = set()
    for rel in paths:
        path = repo / rel
        if path.suffix.lower() not in _TEXT_EXTENSIONS or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")[:1_000_000]
        except OSError:
            continue
        symbols.update(match.group(1) for match in _SYMBOL.finditer(text))
    return sorted(symbols)[:80]


def _related_files(repo: Path, symbols: list[str], changed: set[str], limit: int) -> list[str]:
    """Bounded source neighbourhood from exact symbol references, never a claim of reachability."""
    limit = max(1, min(int(limit), 500))
    related: set[str] = set(changed)
    patterns = [re.compile(rf"\b{re.escape(symbol)}\b") for symbol in symbols if len(symbol) >= 3]
    if not patterns:
        return sorted(related)[:limit]
    for path in sorted(repo.rglob("*")):
        if len(related) >= limit or not path.is_file() or ".git" in path.parts:
            continue
        if path.suffix.lower() not in _TEXT_EXTENSIONS:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")[:1_000_000]
        except OSError:
            continue
        if any(pattern.search(text) for pattern in patterns):
            related.add(path.relative_to(repo).as_posix())
    return sorted(related)[:limit]


def _fact_state(ctx: RunContext, meta: dict, changed: set[str], head: str) -> dict:
    identity = canonical_target(str(meta.get("repo_source") or ""), bool(meta.get("repo_is_url")))
    memory = TargetMemoryStore(ctx.target_memory_dir).load(identity, head)
    impacted, retained, unproven = [], [], []
    for fact in memory.facts:
        haystack = fact.summary.lower()
        hits = [path for path in sorted(changed) if path.lower() in haystack]
        row = {"id": fact.id, "kind": fact.kind, "summary": fact.summary,
               "provenance": fact.provenance}
        if fact.freshness == "fresh":
            retained.append({**row, "state": "retained_same_revision"})
        elif hits:
            impacted.append({**row, "state": "invalidated_by_changed_file", "paths": hits})
        else:
            # Different revision means a fact can inform a human only after it is re-proved; this is
            # intentionally not called retained even where no captured path mentions a changed file.
            unproven.append({**row, "state": "stale_unproven"})
    return {"invalidated": impacted, "retained": retained, "stale_unproven": unproven}


def run(ctx: RunContext) -> Path:
    """Write a bounded review plan for ``incremental_base`` versus the acquired HEAD."""
    base_ref = _safe_ref(ctx.config.incremental_base or "")
    if not (ctx.repo_dir / ".git").exists():
        raise ValueError("incremental review requires a Git repository with base history")
    meta = _meta(ctx)
    base, head = _resolve(ctx.repo_dir, base_ref), _resolve(ctx.repo_dir, "HEAD")
    pinned = str(meta.get("repo_commit") or "").strip()
    if pinned and pinned != head:
        raise ValueError("incremental review refused: acquired HEAD differs from meta.json repo_commit")
    common = _git(ctx.repo_dir, "merge-base", base, head).strip()
    if common != base:
        raise ValueError("incremental base is not an ancestor of the audited HEAD")
    changed_rows = _changed_files(ctx.repo_dir, base, head)
    # Deleted paths and the old side of a rename are still invalidation triggers even though they
    # cannot be scanned in HEAD for symbols.
    changed = {str(row["path"]) for row in changed_rows}
    changed.update(str(row["old_path"]) for row in changed_rows if row.get("old_path"))
    symbols = _changed_symbols(ctx.repo_dir, sorted(changed))
    related = _related_files(ctx.repo_dir, symbols, changed, ctx.config.incremental_max_related_files)
    facts = _fact_state(ctx, meta, changed, head)
    payload = {
        "schema_version": 1,
        "mode": "context_preserving_incremental_review",
        "base_commit": base,
        "head_commit": head,
        "changed_files": changed_rows,
        "candidate_symbols": symbols,
        "review_neighborhood": related,
        "memory_facts": facts,
        "recall_notice": ("The diff is an invalidation signal, not a security boundary. The full "
                          "repository remains available to recon/audit; unchanged code is not asserted safe."),
    }
    atomic_write_json(ctx.incremental_review_path, payload)
    return ctx.incremental_review_path


def prompt_context(ctx: RunContext, *, limit: int = 9000) -> str:
    """Bounded, explicitly non-exhaustive plan injected into recon for a full-context review."""
    try:
        review = json.loads(ctx.incremental_review_path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return ""
    changed = [row.get("path") for row in review.get("changed_files") or [] if isinstance(row, dict)]
    neighbourhood = review.get("review_neighborhood") or []
    facts = review.get("memory_facts") if isinstance(review.get("memory_facts"), dict) else {}
    invalidated = facts.get("invalidated") or []
    stale = facts.get("stale_unproven") or []
    lines = [
        "## INCREMENTAL REVIEW PLAN (full-repository context remains mandatory)",
        f"Compare base {review.get('base_commit', '?')[:12]} to head {review.get('head_commit', '?')[:12]}.",
        "Prioritize this changed neighbourhood, then follow callers/callees and trust boundaries in the full repository.",
        "Do not claim unchanged code is safe or omit a finding solely because its cited line is unchanged.",
        "Changed files: " + (", ".join(changed[:80]) or "none"),
        "Related files (textual symbol neighbourhood, not proven reachability): "
        + (", ".join(str(item) for item in neighbourhood[:120]) or "none"),
        "Prior facts directly invalidated by changed paths (private hypotheses; re-prove):",
    ]
    lines.extend(f"- [{item.get('kind', 'fact')}] {item.get('summary', '')}"
                 for item in invalidated[:30] if isinstance(item, dict))
    lines.append("Other prior facts stale at this revision (not retained; re-check when relevant):")
    lines.extend(f"- [{item.get('kind', 'fact')}] {item.get('summary', '')}"
                 for item in stale[:30] if isinstance(item, dict))
    return "\n".join(lines)[:limit]
