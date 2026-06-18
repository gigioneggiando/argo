"""JSON-Schema validation against the authoritative ``scope_schema.json`` /
``findings_schema.json`` assets. These schemas are the contract; the pydantic models in
``models.py`` are a convenience layer on top, but schema validation is what gates a stage
boundary.
"""

from __future__ import annotations

import functools
import json
from pathlib import Path

from jsonschema import Draft7Validator

from .config import PipelineConfig

_DEFAULT_PROMPTS_DIR = PipelineConfig().prompts_dir


class SchemaValidationError(ValueError):
    """Raised when a document fails validation against its JSON Schema."""

    def __init__(self, kind: str, errors: list[str]):
        self.kind = kind
        self.errors = errors
        joined = "\n  - ".join(errors)
        super().__init__(f"{kind} failed schema validation:\n  - {joined}")


@functools.lru_cache(maxsize=None)
def _load_schema(prompts_dir: Path, name: str) -> dict:
    return json.loads((prompts_dir / name).read_text(encoding="utf-8"))


def _validate(doc: dict, schema: dict, kind: str) -> dict:
    validator = Draft7Validator(schema)
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    if errors:
        msgs = []
        for e in errors:
            loc = "/".join(str(p) for p in e.path) or "<root>"
            msgs.append(f"{loc}: {e.message}")
        raise SchemaValidationError(kind, msgs)
    return doc


def validate_scope(doc: dict, prompts_dir: Path | None = None) -> dict:
    schema = _load_schema(prompts_dir or _DEFAULT_PROMPTS_DIR, "scope_schema.json")
    return _validate(doc, schema, "scope.json")


def validate_findings(doc: dict, prompts_dir: Path | None = None) -> dict:
    schema = _load_schema(prompts_dir or _DEFAULT_PROMPTS_DIR, "findings_schema.json")
    return _validate(doc, schema, "findings JSON")
