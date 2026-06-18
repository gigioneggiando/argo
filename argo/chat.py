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
- Stay inside the program scope; respect the prohibited techniques in the scope."""

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


def ask(ctx: RunContext, message: str) -> dict:
    """Run one chat turn. Returns ``{reply, generated, cost_usd}`` and persists both messages."""
    ctx.load_scope()
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
    store.append("assistant", reply)
    new_files = sorted({p.name for p in work.glob("*") if p.is_file()} - before)
    return {"reply": reply, "generated": new_files, "cost_usd": round(result.cost_usd, 6)}
