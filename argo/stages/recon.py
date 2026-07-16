"""Stage 2 — Recon + prompt synthesis.

Render ``00_recon_synthesis_meta_prompt.md`` with the scope + repo path and run it with
READ-ONLY repo access. The model profiles the repo, reconciles it with scope, and emits the
complementary custom audit prompts (each conforming to ``01_audit_prompt_template.md.j2``),
plus ``repo_profile.json`` and ``synthesis_notes.md``.

Guardrail: every generated audit prompt is verified to carry the scope's prohibited techniques
verbatim and the safety template's required sections; the run FAILS otherwise.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from ..archetype import canonicalize
from ..config import ARTIFACT_TOOLS
from ..context import RunContext, collect_output_files
from ..guardrails import (
    assert_audit_prompt_wellformed,
    assert_prohibited_present,
    ensure_prohibited_present,
)
from ..knowledge import format_for_prompt

_RESEARCH_BRIEF_CAP = 9000   # cap the injected Stage-0 brief so it can't dominate the recon prompt
# A transient cutoff of the recon-synthesis session (machine sleep, network blip, model stop_sequence)
# can write ground_truth.json + repo_profile.json but NOT the per-focus audit_*.md prompts, which aborts
# the whole run with "no audit prompts". The synthesis is read-only and idempotent, so retry it.
_RECON_MAX_ATTEMPTS = 2
from ..rendering import ensure_design_context_present, fill_placeholders, with_artifact_contract
from ..census import ensure_variant_census_present
from ..checklists import (
    detect_crypto,
    detect_free_then_reparse,
    detect_native,
    ensure_coverage_checklist_present,
)
from ..runner import RunnerError


def _is_audit_prompt(name: str) -> bool:
    """A recon-generated audit prompt. Real models drift between ``audit_foo.md`` and
    ``audit-foo.md`` (underscore vs hyphen) — accept either."""
    return bool(re.match(r"audit[-_]", name, re.I)) and name.lower().endswith(".md")


def _canonical_prompt_name(name: str) -> str:
    """Normalize an audit-prompt filename to the ``audit_<rest>.md`` form the audit stage globs."""
    return name if name.startswith("audit_") else "audit_" + name[len("audit"):].lstrip("-_")


def _repo_url(scope) -> str:
    for a in scope.source_repo_assets:
        s = a.asset.strip().lower()
        if s.startswith(("http://", "https://", "git@", "ssh://", "git://")) or s.endswith(".git"):
            return a.asset
    return ""


def run(ctx: RunContext) -> list[Path]:
    scope = ctx.load_scope()
    scope_json_text = ctx.scope_path.read_text(encoding="utf-8")

    meta_prompt = (ctx.assets_dir / "00_recon_synthesis_meta_prompt.md").read_text(encoding="utf-8")
    rendered = fill_placeholders(meta_prompt, {
        "SCOPE_JSON": scope_json_text,
        "PROGRAM_BRIEF_RAW": scope.program_brief_raw or "",
        "REPO_PATH": str(ctx.repo_dir.resolve()),
        "REPO_URL": _repo_url(scope),
        "TARGET_TYPE": scope.target_type,
    })

    # The headless session cannot see pipeline/prompts/, so inline the template the generated
    # prompts must conform to.
    template_text = (ctx.assets_dir / "01_audit_prompt_template.md.j2").read_text(encoding="utf-8")
    rendered += (
        "\n\n---\n\n## TEMPLATE THE GENERATED AUDIT PROMPTS MUST CONFORM TO "
        "(01_audit_prompt_template.md.j2)\n\n```jinja\n" + template_text + "\n```\n"
    )

    # Inject the curated vulnerability-class index as ADDITIONAL reference (archetype-keyed);
    # additive context, the model still classifies and discovers on its own.
    rendered += "\n\n---\n\n" + format_for_prompt() + "\n"

    # Inject the Stage-0 web research brief if present (opt-out --research): known CVEs, security
    # history, where to focus. Additive — the model still classifies + discovers on its own.
    if ctx.research_brief_path.exists():
        brief = ctx.research_brief_path.read_text(encoding="utf-8")[:_RESEARCH_BRIEF_CAP]
        rendered += ("\n\n---\n\n## EXTERNAL THREAT INTELLIGENCE (Stage-0 web research — additive)\n\n"
                     + brief + "\n\nUse this to PRIORITIZE the audit; it is not exhaustive — still "
                     "classify and discover on your own.\n")

    # Guardrail: prohibited techniques must be present in the prompt we send (they live inside
    # SCOPE_JSON). Fail the run otherwise.
    assert_prohibited_present(rendered, scope.prohibited_techniques)

    prompt = with_artifact_contract(
        rendered,
        artifacts=[
            {"type": "repo_profile", "filename": "repo_profile.json", "schema": None,
             "desc": "structured repo profile incl. residual_unknowns and a top-level `archetype` "
                     "field set to ONE canonical key: web_api_cms | plugin_extension | "
                     "library_sdk | cli_desktop | agent_llm_mcp | mobile | data_ml | "
                     "smart_contract | firmware | iac | other"},
            {"type": "audit_prompt", "filename": "audit_<focus-slug>.md", "schema": None,
             "desc": "ONE file per generated custom audit prompt; lowercase kebab slug; each "
                     "MUST conform to the template above (carry the scope + prohibited "
                     "techniques verbatim, the per-finding format, and the deliverables)"},
            # repo_profile.json should also carry a canonical `archetype` (see desc above);
            # captured below for cost/benchmark grouping.
            {"type": "synthesis_notes", "filename": "synthesis_notes.md", "schema": None,
             "desc": "why you split the audit this way, deprioritized surfaces, residual unknowns"},
            {"type": "ground_truth", "filename": "ground_truth.json", "schema": None,
             "desc": "structured ground-truth pack: per-focus invariants, baseline-correct refs, "
                     "variant_families (with concrete member lists), and fp_carveouts, plus global "
                     "fp_carveouts/advisory_classes/dependency_risks (see meta-prompt OUTPUT A2)"},
        ],
    )

    work = ctx.work_dir("recon")
    files: list[Path] = []
    last_exc: RunnerError | None = None
    for attempt in range(1, _RECON_MAX_ATTEMPTS + 1):
        try:
            result = ctx.runner.run(
                prompt=prompt,
                run_dir=ctx.run_dir,
                work_dir=work,
                model=ctx.config.model_for("recon"),
                stage="recon",
                run_id=ctx.run_id,
                repo_dir=ctx.repo_dir,          # READ-ONLY repo access
                allowed_tools=ARTIFACT_TOOLS,
                label="recon-synthesis" if attempt == 1 else f"recon-synthesis-retry-{attempt}",
            )
            files = collect_output_files(result, "*")
        except RunnerError as exc:
            # Session died (e.g. timeout / machine sleep) but may have already written artifacts to
            # scratch. Recover them; the well-formedness guardrail below still gates every prompt.
            last_exc = exc
            files = sorted(p for p in work.glob("*") if p.is_file())
            print(f"[recon] session failed ({exc}); recovered {len(files)} partial artifact(s) "
                  "from the scratch dir", file=sys.stderr)

        # A transient cutoff can write ground_truth.json + repo_profile.json but NOT the audit_*.md
        # prompts, which would abort the whole run. If no audit prompt was produced, retry the
        # synthesis (read-only, idempotent); otherwise proceed with what we have.
        if any(_is_audit_prompt(f.name) for f in files):
            break
        if attempt < _RECON_MAX_ATTEMPTS:
            print(f"[recon] attempt {attempt}/{_RECON_MAX_ATTEMPTS} produced no audit prompts "
                  "(transient cutoff?); retrying recon-synthesis", file=sys.stderr)

    if not files and last_exc is not None:
        raise last_exc

    ctx.prompts_out_dir.mkdir(parents=True, exist_ok=True)

    # Cheap repo signals that gate the mandatory coverage checklist injected into every audit prompt
    # (memory-safety for native code; crypto-primitive quality when crypto is present). Detected
    # deterministically so the lens can't be dropped by the recon model's focus choices.
    native = detect_native(ctx.repo_dir)
    has_crypto = detect_crypto(ctx.repo_dir)
    # High-precision idiom pre-scan: at least one `free(x)` shortly followed by `&x` with no
    # intervening `x = NULL` — the free-then-reparse / free-then-reuse double-free shape. When
    # present, the native lens gets an extra HIGH-SIGNAL callout so the auditor can't skim past it.
    free_reparse = native and detect_free_then_reparse(ctx.repo_dir)

    prompt_paths: list[Path] = []
    for f in files:
        if f.name == "repo_profile.json":
            json.loads(f.read_text(encoding="utf-8-sig"))  # must be valid JSON
            ctx.repo_profile_path.write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
        elif f.name == "ground_truth.json":
            # Best-effort: the authoritative ground truth is baked into each audit prompt; this
            # structured copy feeds validate/report. A malformed pack must NOT fail the run.
            try:
                json.loads(f.read_text(encoding="utf-8-sig"))
                ctx.ground_truth_path.write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
            except (OSError, ValueError) as exc:
                print(f"[recon] ground_truth.json present but unreadable ({exc}); "
                      "continuing (prompts carry the ground truth inline)", file=sys.stderr)
        elif f.name == "synthesis_notes.md":
            (ctx.run_dir / "synthesis_notes.md").write_text(
                f.read_text(encoding="utf-8"), encoding="utf-8")
        elif _is_audit_prompt(f.name):
            text = f.read_text(encoding="utf-8")
            # Deterministically re-insert any prohibited technique the model paraphrased away
            # (only ever ADDS the scope's own constraints) before the hard gate below.
            text = ensure_prohibited_present(text, scope.prohibited_techniques)
            # And guarantee the impact-discipline + accepted-by-design context is present, so the
            # audit doesn't over-claim (IMDS-style) or flag intended behaviors as bugs.
            text = ensure_design_context_present(text, scope.accepted_risks)
            # Guarantee the mandatory coverage lenses (memory-safety / resource-exhaustion /
            # crypto-primitive + one-finding-per-root-cause) reach the audit regardless of the focus.
            text = ensure_coverage_checklist_present(
                text, native=native, has_crypto=has_crypto, free_reparse=free_reparse)
            # Turn the open-ended "census every sibling" lens into a closed-ended worksheet: inject the
            # concrete extent (site count + files) of each pre-scanned defect family, so the auditor
            # clears an enumerated list instead of rediscovering the family's spread.
            text = ensure_variant_census_present(text, ctx.repo_dir)
            # Guardrail: a generated prompt that lost the RoE / prohibited techniques fails here.
            assert_audit_prompt_wellformed(text, scope.prohibited_techniques)
            # Normalize the filename so the model's `audit-foo.md` is picked up by audit's
            # `audit_*.md` glob (real models drift between `audit_` and `audit-`).
            dst = ctx.prompts_out_dir / _canonical_prompt_name(f.name)
            dst.write_text(text, encoding="utf-8")
            prompt_paths.append(dst)

    if not prompt_paths:
        raise RuntimeError("recon: no audit prompts were generated (audit_*.md)")
    if not ctx.repo_profile_path.exists():
        raise RuntimeError("recon: repo_profile.json was not produced")

    _warn_shallow_prompts(prompt_paths)
    if not ctx.ground_truth_path.exists():
        print("[recon] WARNING: ground_truth.json was not produced — the audit prompts still "
              "carry ground truth inline, but validate/report lose the structured carve-outs",
              file=sys.stderr)

    _capture_archetype(ctx)
    return sorted(prompt_paths)


# Section headers a gen-2 (target-specific) audit prompt must carry. Soft check: a missing section
# means recon fell back to a generic prompt — log it loudly, but never fail the run over phrasing.
_DEPTH_SECTIONS = (
    "INVARIANT CHECKLIST",
    "BASELINE-CORRECT REFERENCES",
    "VARIANT FAMILIES",
    "FALSE-POSITIVE CARVE-OUTS",
)


def _warn_shallow_prompts(prompt_paths: list[Path]) -> None:
    for p in prompt_paths:
        text = p.read_text(encoding="utf-8")
        missing = [s for s in _DEPTH_SECTIONS if s.lower() not in text.lower()]
        if missing:
            print(f"[recon] WARNING: {p.name} is missing ground-truth section(s) {missing} — "
                  "it may be too generic (the depth+precision uplift expects all four)",
                  file=sys.stderr)


def _detect_archetype(repo_profile: dict, synthesis: str) -> str:
    """Canonical archetype: from repo_profile.archetype, else parsed from synthesis_notes."""
    raw = (repo_profile or {}).get("archetype")
    if not raw:
        m = re.search(r"^#{1,4}\s*Archetype[^\n]*\n+([^\n]+)", synthesis or "", re.I | re.M)
        raw = m.group(1) if m else ""
    return canonicalize(str(raw))


def _capture_archetype(ctx: RunContext) -> None:
    """Persist the recon-classified archetype into meta.json (for cost/benchmark grouping)."""
    try:
        profile = json.loads(ctx.repo_profile_path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        profile = {}
    synth_path = ctx.run_dir / "synthesis_notes.md"
    synth = synth_path.read_text(encoding="utf-8") if synth_path.exists() else ""
    archetype = _detect_archetype(profile if isinstance(profile, dict) else {}, synth)
    try:
        meta = json.loads(ctx.meta_path.read_text(encoding="utf-8-sig"))
        meta["archetype"] = archetype
        ctx.meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    except (OSError, ValueError):
        pass  # telemetry only — never fail the run over it
