"""Private, revision-bound target memory for repeated Argo audits.

The store deliberately holds short structured conclusions and artifact pointers, never a copy of
the audited source tree.  A fact is eligible to seed a later run only when it was observed at the
same commit.  A different or unknown revision makes it stale; callers must re-establish it.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from .context import atomic_write_json


SCHEMA_VERSION = 1
_KINDS = {
    "component", "entry_point", "identity", "data", "trust_boundary", "invariant",
    "baseline", "design_decision", "false_lead", "finding", "variant", "fix", "question",
}


class TargetIdentity(BaseModel):
    """Stable identity which does not expose local absolute paths in a run artifact."""

    model_config = ConfigDict(extra="forbid")

    key: str
    display_name: str
    is_remote: bool


class MemoryFact(BaseModel):
    """A concise, source-free conclusion with enough provenance to be reviewed or invalidated."""

    model_config = ConfigDict(extra="forbid")

    id: str
    kind: str
    summary: str = Field(min_length=1, max_length=1200)
    provenance: str
    artifacts: list[str] = Field(default_factory=list)
    confidence: str = "medium"
    visibility: str = "private"
    observed_commit: str | None = None
    freshness: str = "fresh"
    invalidated_by: str | None = None
    first_seen_at: str
    last_seen_at: str


class TargetMemory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = SCHEMA_VERSION
    target: TargetIdentity
    facts: list[MemoryFact] = Field(default_factory=list)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_target(repo_source: str, repo_is_url: bool) -> TargetIdentity:
    """Return a stable remote identity or an opaque local identity.

    Remote URLs are normalized across HTTPS and SSH forms.  A local path is hashed rather than
    placed in the store or copied to a run artifact.
    """
    raw = (repo_source or "").strip()
    if repo_is_url:
        if re.match(r"^[^/@:\\s]+@[^:/\s]+:[^\s]+$", raw):
            _user, rest = raw.split("@", 1)
            host, path = rest.split(":", 1)
        else:
            parsed = urlsplit(raw)
            host, path = parsed.hostname or "", parsed.path
        path = path.strip("/")
        if path.lower().endswith(".git"):
            path = path[:-4]
        canonical = "/".join(part for part in (host.lower(), path.lower()) if part)
        if canonical:
            return TargetIdentity(key=f"remote:{canonical}", display_name=canonical,
                                  is_remote=True)

    # Resolve local aliases before hashing, but keep the path itself out of every artifact.
    # Failure to resolve is harmless: the raw input still gives a conservative, opaque identity.
    try:
        local = str(Path(raw).expanduser().resolve())
    except OSError:
        local = raw
    digest = hashlib.sha256(local.encode("utf-8")).hexdigest()[:20]
    name = Path(local).name or "local-target"
    return TargetIdentity(key=f"local:{digest}", display_name=name, is_remote=False)


def _filename(identity: TargetIdentity) -> str:
    digest = hashlib.sha256(identity.key.encode("utf-8")).hexdigest()
    return f"{digest}.json"


class TargetMemoryStore:
    """Atomic JSON store scoped to one local user's configured memory directory."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def path_for(self, identity: TargetIdentity) -> Path:
        return self.root / _filename(identity)

    def load(self, identity: TargetIdentity, commit: str | None) -> TargetMemory:
        path = self.path_for(identity)
        if not path.exists():
            return TargetMemory(target=identity)
        try:
            memory = TargetMemory.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # A corrupt local cache must never stop an audit or cause it to trust stale state.
            return TargetMemory(target=identity)
        if memory.target.key != identity.key:
            return TargetMemory(target=identity)

        changed = False
        for fact in memory.facts:
            current = bool(commit and fact.observed_commit == commit)
            if fact.freshness != ("fresh" if current else "stale"):
                fact.freshness = "fresh" if current else "stale"
                fact.invalidated_by = None if current else (commit or "revision unavailable")
                changed = True
        if changed:
            self.save(memory)
        return memory

    def save(self, memory: TargetMemory) -> None:
        path = self.path_for(memory.target)
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(path, memory.model_dump(mode="json"))

    def upsert(self, identity: TargetIdentity, commit: str | None,
               facts: list[tuple[str, str, str, list[str]]]) -> TargetMemory:
        """Persist deterministic summaries from this run and retain a compact audit trail."""
        memory = self.load(identity, commit)
        now = _utcnow()
        by_id = {fact.id: fact for fact in memory.facts}
        for kind, summary, provenance, artifacts in facts:
            if kind not in _KINDS or not summary.strip():
                continue
            summary = " ".join(summary.split())[:1200]
            payload = {"kind": kind, "summary": summary, "provenance": provenance}
            fact_id = "tm:" + hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()[:16]
            old = by_id.get(fact_id)
            if old is not None:
                old.observed_commit = commit
                old.freshness = "fresh" if commit else "stale"
                old.invalidated_by = None if commit else "revision unavailable"
                old.last_seen_at = now
                old.artifacts = sorted(set(old.artifacts) | set(artifacts))
                continue
            memory.facts.append(MemoryFact(
                id=fact_id, kind=kind, summary=summary, provenance=provenance,
                artifacts=sorted(set(artifacts)), observed_commit=commit,
                freshness="fresh" if commit else "stale",
                invalidated_by=None if commit else "revision unavailable",
                first_seen_at=now, last_seen_at=now,
            ))
        self.save(memory)
        return memory


def fresh_facts(memory: TargetMemory, *, limit: int = 24) -> list[MemoryFact]:
    """Return only same-revision facts; order stays deterministic across runs."""
    return sorted((fact for fact in memory.facts if fact.freshness == "fresh"),
                  key=lambda fact: (fact.kind, fact.id))[:limit]


def prompt_context(facts: list[MemoryFact], *, limit: int = 9000) -> str:
    """Render bounded context explicitly as provisional prior knowledge, never as proof."""
    if not facts:
        return ""
    lines = [
        "## PRIOR TARGET MEMORY (same revision; re-check before relying on it)",
        "These are private summaries from prior Argo artifacts, not authoritative source evidence. "
        "Use them to prioritize inspection; verify each claim against the current repository and "
        "do not treat a prior false lead or design decision as a reason to skip novel evidence.",
    ]
    for fact in facts:
        lines.append(f"- [{fact.kind}] {fact.summary}")
    return "\n".join(lines)[:limit]
