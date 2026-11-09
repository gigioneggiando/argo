"""Shared errors and validation helpers for model-facing artifact tools."""
from __future__ import annotations

import json


class ToolError(Exception):
    """A recoverable tool-call error returned to the model for correction."""


def _safe_excerpt(content: str, position: int, limit: int = 120) -> str:
    """Return a bounded structural excerpt without copying model-provided values."""
    start = max(0, position - limit // 2)
    excerpt = content[start:start + limit].encode("unicode_escape").decode("ascii")[:180]
    # Keep JSON punctuation, quotes, escapes, and whitespace so the syntax problem remains
    # visible. Mask every value character to avoid echoing a brief, secret, or source fragment.
    return "".join(char if char in '{}[]:,"\\ \t\r\n' else "*" for char in excerpt)


def validate_json_content(content: str) -> None:
    """Reject malformed JSON with a deterministic, sanitized correction hint."""
    try:
        json.loads(content)
    except json.JSONDecodeError as exc:
        excerpt = _safe_excerpt(content, exc.pos)
        raise ToolError(
            f"not written: invalid JSON ({exc.msg} at line {exc.lineno}, column "
            f"{exc.colno}). Near: {excerpt!r}. Escape inner double quotes as \\\" and "
            "newlines as \\n, then call write_file again with the full corrected content."
        ) from None
