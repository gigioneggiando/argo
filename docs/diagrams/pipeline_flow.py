#!/usr/bin/env python3
"""Generate docs/diagrams/pipeline_flow.svg (stdlib only).

The stage list mirrors ``argo.orchestrator.pipeline_stages`` in execution order. To change the
diagram, edit STAGES below and run:  python docs/diagrams/pipeline_flow.py
"""
from __future__ import annotations

from html import escape
from pathlib import Path

W = 680
MAIN_X, MAIN_W = 40, 420             # main column
SIDE_X, SIDE_W = 482, 168            # right-hand side notes
CX = MAIN_X + MAIN_W // 2            # main column centre
GAP = 20                             # vertical gap between stages (arrow length)

STYLE = {  # kind -> (fill, stroke, title colour, subtitle colour)
    "input": ("#F1EFE8", "#5F5E5A", "#2C2C2A", "#5F5E5A"),
    "auto": ("#EEEDFE", "#534AB7", "#26215C", "#534AB7"),
    "osint": ("#E6F7F2", "#2A8C73", "#13503F", "#2A8C73"),
    "live": ("#FCEFCB", "#B07A1E", "#6B4A0F", "#8A5D12"),
    "manual": ("#FAECE7", "#993C1D", "#711B0C", "#993C1D"),
    "note": ("#F7F7F5", "#A8A7A3", "#6F6E69", "#6F6E69"),
}

# (title, subtitle lines, kind, optional?) in execution order -- see pipeline_stages().
STAGES = [
    ("Stage 0 · Ingest", ["brief or folder → scope.json (+ pinned commit)"], "auto", False),
    ("Target memory", ["private, revision-bound facts → recon hints, never evidence"], "auto", False),
    ("Incremental review (opt-in)", ["--incremental-base: diff → changed files, invalidated facts"], "auto", True),
    ("Stage 1 · Research \U0001F310 (opt-out)", ["uses Stage 0 scope · OSINT before recon"], "osint", True),
    ("Stage 2 · Recon + synthesis", ["ground truth → custom prompts"], "auto", False),
    ("Stage 3 · Audit", ["parallel focuses + critic → findings + variant log"], "auto", False),
    ("SCA · Dependencies (opt-out)", ["manifests → known-vulnerable pins"], "auto", True),
    ("Second opinion (opt-in)", ["N blind recon+audit passes → merged in"], "auto", True),
    ("Stage 4 · Validate", ["dedup · citation grounding (missing file → drop; symbol → keep)",
                            "adversarial review · parse-only context, not flow proof"], "auto", False),
    ("Corroborate \U0001F310 (opt-out)", ["docs + repo history → confirm / discard findings"], "osint", True),
    ("Verify (opt-in)", ["re-derive from source → split / merge / correct"], "auto", True),
    ("ASan PoC (opt-in · C/C++)", ["fixed clang + ASan run, egress-blocked → crash trace"], "auto", True),
    ("Freshness check (opt-in)", ["later commits to cited files → review appendix"], "osint", True),
    ("Runtime (opt-in)", ["sealed loopback container PoC · never live hosts"], "auto", True),
    ("Evidence gate (deterministic)", ["typed ledger · proof level · open obligations"], "osint", False),
    ("Review questions (opt-in)", ["private architecture queue · answers re-validate"], "auto", True),
    ("Compose (opt-in)", ["exact-context attack paths for review · no escalation"], "auto", True),
    ("Stage 5 · Report", ["proof-aware report + submission drafts"], "auto", False),
    ("You: review + submit \U0001F44B", ["manual — never automated"], "manual", False),
]
# Side notes: (anchor stage title, title, lines, kind, connector style or None)
SIDE = [
    ("Stage 3 · Audit", "Opt-in", ["chat, fix verification,", "impact review, accepted risks"], "note", None),
    ("Stage 5 · Report", "⚠ argo live (opt-in)", ["separate command · authorized,", "in-scope read-only probes"], "live", "live"),
]


def text(x, y, s, size, colour, weight=None, anchor="middle", italic=False):
    attrs = [f'x="{x}"', f'y="{y}"', f'text-anchor="{anchor}"', 'dominant-baseline="central"',
             f'font-size="{size}"', f'fill="{colour}"']
    if weight:
        attrs.append(f'font-weight="{weight}"')
    if italic:
        attrs.append('font-style="italic"')
    return f"<text {' '.join(attrs)}>{escape(s, quote=False)}</text>"


def box(x, y, w, h, kind, dashed, rx=8):
    fill, stroke, _, _ = STYLE[kind]
    dash = ' stroke-dasharray="4 3"' if dashed else ""
    width = "1" if dashed else "0.6"
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" '
            f'stroke="{stroke}" stroke-width="{width}"{dash}/>')


def arrow(x1, y1, x2, y2, colour="#5F5E5A", dashed=False):
    dash = ' stroke-dasharray="3 3"' if dashed else ""
    return (f'<path d="M{x1} {y1} L{x2} {y2}" fill="none" stroke="{colour}" stroke-width="1.2"'
            f'{dash} marker-end="url(#arrow)"/>')


def build() -> str:
    out: list[str] = []
    # inputs row
    y0 = 44
    inputs = [(40, "Program brief", "optional · bug-bounty mode", True),
              (247, "Codebase repo", "local folder or git URL", False),
              (454, "Useful links", "site, docs, advisory", False)]
    for x, t, sub, dashed in inputs:
        out.append(box(x, y0, 186, 56, "input", dashed))
        out.append(text(x + 93, y0 + 19, t, 14, STYLE["input"][2], 500))
        out.append(text(x + 93, y0 + 39, sub, 12, STYLE["input"][3]))
    y = y0 + 56 + 44
    for x, _, _, _ in inputs:          # straight down when above Ingest, else one elbow
        cx = x + 93
        if MAIN_X + 10 <= cx <= MAIN_X + MAIN_W - 10:
            out.append(arrow(cx, y0 + 56, cx, y - 2))
        else:
            tx = MAIN_X + MAIN_W - 40
            out.append(f'<path d="M{cx} {y0 + 56} L{cx} {y - 22} L{tx} {y - 22} L{tx} {y - 2}" '
                       f'fill="none" stroke="#5F5E5A" stroke-width="1.2" marker-end="url(#arrow)"/>')
    centres: dict[str, tuple[int, int]] = {}
    for i, (title, subs, kind, optional) in enumerate(STAGES):
        h = 30 + 18 * len(subs)
        out.append(box(MAIN_X, y, MAIN_W, h, kind, optional))
        _, _, tc, sc = STYLE[kind]
        out.append(text(CX, y + 17, title, 14, tc, 500))
        for j, s in enumerate(subs):
            out.append(text(CX, y + 36 + 18 * j, s, 12 if len(s) < 60 else 11, sc))
        centres[title] = (y, h)
        if i < len(STAGES) - 1:
            out.append(arrow(CX, y + h, CX, y + h + GAP - 2))
        y += h + GAP
    for anchor, title, lines, kind, conn in SIDE:
        ay, ah = centres[anchor]
        h = 22 + 15 * len(lines)
        sy = ay + (ah - h) // 2
        out.append(box(SIDE_X, sy, SIDE_W, h, kind, True, rx=7))
        _, _, tc, sc = STYLE[kind]
        out.append(text(SIDE_X + SIDE_W / 2, sy + 13, title, 11.5, tc, 500))
        for j, s in enumerate(lines):
            out.append(text(SIDE_X + SIDE_W / 2, sy + 29 + 15 * j, s, 10.5, sc))
        if conn:
            out.append(arrow(MAIN_X + MAIN_W, ay + ah // 2, SIDE_X - 2, ay + ah // 2,
                             STYLE[kind][1], dashed=True))
    # legend + footers
    y += 6
    legend = [("input", "inputs"), ("auto", "automated (offline)"), ("osint", "OSINT / evidence"),
              ("live", "live (opt-in)"), ("manual", "manual gate")]
    lx = 40
    for kind, label in legend:
        fill, stroke, _, _ = STYLE[kind]
        out.append(f'<rect x="{lx}" y="{y}" width="13" height="13" rx="3" fill="{fill}" '
                   f'stroke="{stroke}" stroke-width="0.5"/>')
        out.append(text(lx + 19, y + 7, label, 12, "#444441", anchor="start"))
        lx += 34 + 7 * len(label)
    out.append(text(40, y + 30, "dashed border = optional stage (opt-in / opt-out)", 10.5, "#888",
                    anchor="start"))
    out.append(text(340, y + 52, "Every LLM call: backend + redaction-safe account label in llm_log.jsonl",
                    10.5, "#888"))
    out.append(text(340, y + 70, "Two modes, one engine: omit the brief (dashed) for a general/local "
                    "code audit; add it for bug-bounty triage.", 11, "#888", italic=True))
    height = y + 92
    desc = ("Execution order of argo pipeline: Stage 0 Ingest creates scope.json; private target "
            "memory and optional incremental review; Stage 1 Research (opt-out OSINT); Stage 2 Recon; "
            "Stage 3 Audit; optional SCA and second opinion; Stage 4 Validate with citation grounding; "
            "optional corroboration, deep verify, ASan PoC, freshness check and sandboxed runtime; a "
            "deterministic evidence gate; optional review questions and attack-path composition; "
            "Stage 5 Report; a manual review and submission gate. Live probing is a separate, "
            "authorization-gated command. Backends: Claude Code, Codex (OpenAI or local open-source "
            "models), Gemini, Mistral (API or Vibe).")
    head = (f'<svg width="{W}" viewBox="0 0 {W} {height}" role="img" font-family="-apple-system, '
            f'Segoe UI, Roboto, Helvetica, Arial, sans-serif" xmlns="http://www.w3.org/2000/svg">\n'
            f"<title>End-to-end pipeline flow</title>\n<desc>{escape(desc)}</desc>\n"
            '<defs><marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" '
            'markerHeight="6" orient="auto-start-reverse"><path d="M2 1L8 5L2 9" fill="none" '
            'stroke="#5F5E5A" stroke-width="1.5" stroke-linecap="round" '
            'stroke-linejoin="round"/></marker></defs>\n'
            f'<rect width="{W}" height="{height}" fill="#FFFFFF"/>\n')
    top = text(340, 20, "backends: Claude Code · Codex (OpenAI / local-OSS) · Gemini · Mistral (API · Vibe)",
               11, "#888")
    return head + top + "\n" + "\n".join(out) + "\n</svg>\n"


if __name__ == "__main__":
    path = Path(__file__).with_name("pipeline_flow.svg")
    path.write_text(build(), encoding="utf-8", newline="\n")
    print(f"wrote {path}")
