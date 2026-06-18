"""Severity / confidence ordering shared by the validate (dedup keeper) and report (sort)
stages."""

from __future__ import annotations

import hashlib
import re

SEVERITY_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}
CONFIDENCE_RANK = {"Confirmed": 4, "High": 3, "Medium": 2, "Low": 1}


def severity_rank(s: str | None) -> int:
    return SEVERITY_RANK.get(s or "", 0)


def confidence_rank(c: str | None) -> int:
    return CONFIDENCE_RANK.get(c or "", 0)


def split_ref(ref: str) -> tuple[str, str]:
    """Split an ``affected`` entry into ``(file, line)``; line is "" when absent.

    Handles ``path/to/file.py:42``, ``path:42-50`` (takes 42), and non-line refs
    (``Class.method``)."""
    if ":" in ref:
        head, tail = ref.rsplit(":", 1)
        m = re.match(r"\s*(\d+)", tail)
        if m and head.strip():
            return head.strip(), m.group(1)
    return ref.strip(), ""


def dedup_key(primary_file: str, primary_line: str, cwe: str) -> str:
    """``sha1(normalize(primary_file + primary_line + cwe))`` per BUILD_SPEC."""
    norm = f"{primary_file}|{primary_line}|{cwe}".replace("\\", "/").lower()
    norm = re.sub(r"\s+", "", norm)
    return hashlib.sha1(norm.encode("utf-8")).hexdigest()
