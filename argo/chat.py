"""Phase 3 — interactive chat over a completed run.

A conversational analyst seeded with the run's artifacts (scope, repo profile, synthesis notes,
validated findings) and READ-ONLY access to the repo. It helps the user understand results and
attack false negatives ("why didn't you find X?"), and can generate a test suite that would catch
a finding/CWE — written to ``runs/<id>/generated/`` only, NEVER into the target repo.

Stateless at the CLI level: each turn rebuilds the context + history and runs one ``claude``
session (no fragile --resume). History is persisted to ``runs/<id>/chat.jsonl``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .config import ARTIFACT_TOOLS
from .context import RunContext
from .models import Finding
from .stages.validate import _validate_one

_MAX_ARTIFACT_CHARS = 16_000
_MAX_HISTORY_MSGS = 16

_SYSTEM = """You are a senior application-security analyst continuing an AUTHORIZED, source-only \
bug-bounty review. A full audit run has completed; its context is below and you have READ-ONLY \
access to the repository (Read/Grep/Glob). Help the user understand the results and improve recall.

HARD RULES (non-negotiable):
- Source/static analysis only. NEVER contact, scan, or exercise any live host.
- The repository is READ-ONLY. Never modify it. You may read it to trace data flows.
- Do NOT patch the target. If asked to write tests, create NEW files ONLY in your current working \
directory (never inside the repository), and clearly mark them as generated.
- Be evidence-driven: cite file:line. For a "why didn't you find X", either CONFIRM a genuinely \
missed finding with a traced source->sink flow, or explain honestly why it is not one (dead code, \
sanitized, out of scope, or deliberately deprioritized — the synthesis notes say what was dropped).
- Stay inside the program scope; respect the prohibited techniques in the scope.

RE-VALIDATING A MISSED FINDING (use sparingly, only for a concrete, localized hypothesis):
When the user challenges a specific potential missed vulnerability (e.g. "why didn't you find the \
SQLi at db.py:42", "isn't that endpoint vulnerable to SSRF") and you judge it a genuine, specific \
hypothesis worth re-checking, write a file `CANDIDATE_FINDING.json` in your working directory with \
this shape: {"id","title","cwe","severity","confidence","affected":["file:line"],"vulnerable_flow",\
"why_vulnerable","exploit_scenario","impact","recommended_fix"}. An INDEPENDENT adversarial \
validator will then re-check it against the code and its verdict (confirmed / refuted / \
needs-runtime) will be appended to your answer. Do NOT write it for vague or non-localized \
questions — only for a real, traceable candidate."""

_FOOTER = """Answer concisely and concretely, grounded in the run context and the repository. \
If you generate test files, write them to your working directory and end with a line \
"Generated files: <names>"."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ChatStore:
    """Append-only chat history at ``runs/<id>/chat.jsonl``."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def messages(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return out

    def append(self, role: str, content: str) -> dict:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        rec = {"role": role, "content": content, "ts": _now()}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        return rec


def _read(path: Path, cap: int = _MAX_ARTIFACT_CHARS) -> str:
    if not path.exists():
        return "(not available)"
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text) > cap:
        return text[:cap] + f"\n… (truncated; {len(text)} chars total)"
    return text


def _build_prompt(ctx: RunContext, history: list[dict], message: str) -> str:
    rd = ctx.run_dir
    prior = history[:-1][-_MAX_HISTORY_MSGS:]  # exclude the just-appended user message
    convo = "\n\n".join(f"{m['role'].upper()}: {m['content']}" for m in prior) or "(start of conversation)"
    program = ctx.scope.program_name if ctx.scope else "(unknown)"
    return "\n\n".join([
        _SYSTEM,
        f"=== RUN CONTEXT — program: {program} ===",
        "SCOPE (scope.json):", _read(rd / "scope.json"),
        "REPO PROFILE (repo_profile.json):", _read(rd / "repo_profile.json"),
        "SYNTHESIS NOTES (split rationale + deprioritized surfaces):", _read(rd / "synthesis_notes.md"),
        "VALIDATED FINDINGS (validated_findings.json):", _read(rd / "validated_findings.json"),
        "=== CONVERSATION SO FAR ===", convo,
        "=== USER MESSAGE ===", message,
        _FOOTER,
    ])


_CANDIDATE_FILE = "CANDIDATE_FINDING.json"


def _coerce_candidate(c: dict) -> dict:
    """Backfill the required Finding fields so a partial model-proposed candidate still validates."""
    d = dict(c)
    d.setdefault("id", "CHAT-CANDIDATE")
    d.setdefault("title", "User-proposed candidate")
    d.setdefault("severity", "Medium")
    d.setdefault("confidence", "Low")
    d.setdefault("cwe", "CWE-Unknown")
    if not isinstance(d.get("affected"), list):
        d["affected"] = [d["affected"]] if d.get("affected") else []
    for k in ("vulnerable_flow", "why_vulnerable", "exploit_scenario", "impact", "recommended_fix"):
        d.setdefault(k, "(proposed by the user via chat — to be assessed)")
    return d


def _validate_candidate(ctx: RunContext, scope, candidate: dict) -> dict:
    """Re-validate a single user-proposed candidate finding with the SAME adversarial validator the
    pipeline uses (``_validate_one``) — isolated, read-only, refute-first. Non-mutating: nothing is
    added to validated_findings.json; this is an interactive probe."""
    scope_json_text = (ctx.run_dir / "scope.json").read_text(encoding="utf-8")
    finding = Finding.model_validate(_coerce_candidate(candidate))
    verdict = _validate_one(ctx, scope, scope_json_text, finding)
    return {"finding_id": finding.id, "title": finding.title, "cwe": finding.cwe,
            "verdict": verdict.verdict, "validated_severity": verdict.validated_severity,
            "rationale": verdict.rationale}


def _format_candidate_verdict(v: dict) -> str:
    head = {"confirmed": "✅ Re-validated: **CONFIRMED**",
            "refuted": "❌ Re-validated: **REFUTED**",
            "needs_runtime_verification": "⚠️ Re-validated: **NEEDS RUNTIME CHECK**",
            "out_of_scope": "🚫 Re-validated: **OUT OF SCOPE**"}.get(
                v.get("verdict"), f"Re-validated: {v.get('verdict')}")
    rationale = v.get("rationale") or ""
    return (f"\n\n---\n{head} — candidate `{v.get('finding_id')}` ({v.get('cwe')}). "
            f"This was re-checked independently by the adversarial validator (an interactive probe; "
            f"it is not added to the run's findings).\n\n{rationale}")


def ask(ctx: RunContext, message: str) -> dict:
    """Run one chat turn. Returns ``{reply, generated, cost_usd, validated_candidate}`` and persists
    both messages. If the analyst proposes a ``CANDIDATE_FINDING.json`` (B1 — "why didn't you find
    X?"), it is re-validated with the pipeline's adversarial validator and the verdict appended."""
    scope = ctx.load_scope()
    store = ChatStore(ctx.run_dir / "chat.jsonl")
    store.append("user", message)
    prompt = _build_prompt(ctx, store.messages(), message)

    work = ctx.run_dir / "generated"          # writable; the target repo stays read-only
    work.mkdir(parents=True, exist_ok=True)
    before = {p.name for p in work.glob("*") if p.is_file()}

    result = ctx.runner.run(
        prompt=prompt,
        run_dir=ctx.run_dir,
        work_dir=work,
        model=ctx.config.model_for("chat"),
        stage="chat",
        run_id=ctx.run_id,
        repo_dir=ctx.repo_dir,                # READ-ONLY
        allowed_tools=ARTIFACT_TOOLS,         # read repo + write to the generated/ workspace
        label="chat",
    )
    reply = (result.text or "").strip() or "(no reply)"

    # B1: did the analyst propose a candidate missed finding to re-validate?
    validated_candidate = None
    new_names = {p.name for p in work.glob("*") if p.is_file()} - before
    if _CANDIDATE_FILE in new_names:
        try:
            candidate = json.loads((work / _CANDIDATE_FILE).read_text(encoding="utf-8"))
            validated_candidate = _validate_candidate(ctx, scope, candidate)
            (work / f"candidate_{validated_candidate['finding_id']}.json").write_text(
                json.dumps({"candidate": candidate, "validation": validated_candidate}, indent=2),
                encoding="utf-8")
            reply += _format_candidate_verdict(validated_candidate)
        except Exception as exc:              # a bad candidate must never break the chat turn
            validated_candidate = {"error": str(exc)[:300]}

    store.append("assistant", reply)
    # the raw hypothesis file is internal plumbing, not a user-facing generated artifact
    new_files = sorted(n for n in ({p.name for p in work.glob("*") if p.is_file()} - before)
                       if n != _CANDIDATE_FILE)
    return {"reply": reply, "generated": new_files, "cost_usd": round(result.cost_usd, 6),
            "validated_candidate": validated_candidate}
