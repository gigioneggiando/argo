"""Bounded, connector-neutral private architecture context for one audit run.

The format deliberately stores concise claims and inventories, not uploaded documents or source
material.  Every factual item needs provenance, and prompt rendering labels the whole pack as
user-supplied context which still needs to be checked against the repository.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


MAX_PACK_BYTES = 128_000
MAX_ITEMS_PER_SECTION = 100
_SECRET = re.compile(
    r"(?i)(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*\S+|"
    r"\b(?:password|passwd|api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token)"
    r"\s*[:=]\s*['\"]?[^\s,'\"]{6,})"
)


class ContextClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    statement: str = Field(min_length=1, max_length=2000)
    provenance: str = Field(min_length=1, max_length=500)
    confidence: Literal["confirmed", "claimed", "unknown"] = "claimed"

    @field_validator("statement", "provenance")
    @classmethod
    def _trim(cls, value: str) -> str:
        return " ".join(value.split())


class RoleContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    trust: str = Field(min_length=1, max_length=500)
    provenance: str = Field(min_length=1, max_length=500)


class ServiceContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    purpose: str = Field(min_length=1, max_length=500)
    trust_boundary: str = Field(min_length=1, max_length=500)
    provenance: str = Field(min_length=1, max_length=500)


class ContextArtifact(BaseModel):
    """A reference only. Argo does not copy or dereference the underlying document."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    kind: Literal["architecture_diagram", "architecture_note", "iam_export", "iac_export", "other"]
    description: str = Field(min_length=1, max_length=500)
    reference: str = Field(min_length=1, max_length=500)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")


class ContextPack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    target: str | None = Field(default=None, max_length=300)
    architecture_notes: list[ContextClaim] = Field(default_factory=list)
    roles: list[RoleContext] = Field(default_factory=list)
    services: list[ServiceContext] = Field(default_factory=list)
    business_invariants: list[ContextClaim] = Field(default_factory=list)
    iam_facts: list[ContextClaim] = Field(default_factory=list)
    artifacts: list[ContextArtifact] = Field(default_factory=list)

    @model_validator(mode="after")
    def _bounded_and_unique(self):
        sections = (
            self.architecture_notes, self.roles, self.services, self.business_invariants,
            self.iam_facts, self.artifacts,
        )
        if any(len(section) > MAX_ITEMS_PER_SECTION for section in sections):
            raise ValueError(f"context-pack sections are capped at {MAX_ITEMS_PER_SECTION} items")
        ids = [item.id for section in (
            self.architecture_notes, self.business_invariants, self.iam_facts, self.artifacts,
        ) for item in section]
        if len(ids) != len(set(ids)):
            raise ValueError("context-pack ids must be unique across claim/artifact sections")
        return self


def load(path: Path) -> ContextPack:
    """Validate a context pack before any model call and reject likely embedded credentials."""
    path = Path(path)
    raw_bytes = path.read_bytes()
    if len(raw_bytes) > MAX_PACK_BYTES:
        raise ValueError(f"context pack exceeds {MAX_PACK_BYTES} bytes")
    raw = json.loads(raw_bytes.decode("utf-8-sig"))
    pack = ContextPack.model_validate(raw)
    normalized = json.dumps(pack.model_dump(mode="json"), ensure_ascii=False)
    assert_no_secrets(normalized)
    return pack


def assert_no_secrets(text: str) -> None:
    if _SECRET.search(text):
        raise ValueError("context appears to contain a credential or private key")


def load_run(path: Path) -> ContextPack | None:
    try:
        return ContextPack.model_validate_json(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None


def prompt_context(pack: ContextPack | None, *, limit: int = 16_000) -> str:
    if pack is None:
        return ""
    payload = json.dumps(pack.model_dump(mode="json", exclude_none=True), indent=2,
                         ensure_ascii=False)
    return (
        "## PRIVATE OPERATOR-PROVIDED CONTEXT PACK (claims, not source evidence)\n"
        "Use this bounded architecture/business context to test reachability and intended trust "
        "boundaries. Preserve its provenance, check every claim against the repository where "
        "possible, and leave conflicts or unprovable deployment assumptions explicit. Do not copy "
        "this private pack into reports, drafts, public corroboration searches, or source citations.\n\n"
        + payload
    )[:limit]
