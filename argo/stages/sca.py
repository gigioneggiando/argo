"""Stage SCA — Software-composition analysis.

Read the project's dependency manifests/lockfiles (deterministic file collection) and run ONE
offline session that flags pinned versions with known published advisories. Emits a synthetic
``dependencies`` focus into ``findings/`` so the normal validate + report flow consumes it.

Source-only, no network (uses the model's advisory knowledge — never a registry/advisory API).
A no-op (returns None) when the repo has no recognizable dependency manifests.
"""

from __future__ import annotations

import sys
from pathlib import Path

from ..config import ARTIFACT_TOOLS
from ..context import BudgetExceeded, RunContext, collect_output_files
from ..guardrails import assert_prohibited_present
from ..rendering import fill_placeholders, with_artifact_contract
from ..runner import RunnerError
from .audit import _normalize_findings_doc  # reuse the drift-tolerant normalizer

# Dependency manifests / lockfiles worth reading, across ecosystems. Central version files and
# lockfiles first (most authoritative). Globbed case-insensitively, recursively, but capped.
_MANIFEST_NAMES = (
    "Directory.Packages.props", "packages.config",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "requirements-dev.txt", "Pipfile.lock", "poetry.lock", "pyproject.toml",
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
    "Gemfile.lock", "composer.json", "composer.lock",
)
_MANIFEST_GLOBS = ("*.csproj",)            # patterns (vs exact names)

_MAX_FILES = 40
_MAX_FILE_BYTES = 20_000
_MAX_TOTAL_BYTES = 160_000


def _log(msg: str) -> None:
    print(f"[sca] {msg}", file=sys.stderr)


def _collect_manifests(repo_dir: Path) -> list[Path]:
    found: list[Path] = []
    seen: set[Path] = set()
    names = {n.lower() for n in _MANIFEST_NAMES}
    for p in sorted(repo_dir.rglob("*")):
        if not p.is_file():
            continue
        nm = p.name.lower()
        is_manifest = nm in names or any(p.match(g) for g in _MANIFEST_GLOBS)
        if is_manifest and p not in seen:
            # skip vendored/3rd-party trees that would explode the count
            parts = {part.lower() for part in p.parts}
            if parts & {"node_modules", "vendor", ".git", "bin", "obj", "dist", "build"}:
                continue
            found.append(p)
            seen.add(p)
        if len(found) >= _MAX_FILES:
            break
    # Central version files / lockfiles first.
    found.sort(key=lambda p: (0 if p.name.lower() in
               {"directory.packages.props", "package-lock.json", "yarn.lock", "go.sum",
                "cargo.lock", "poetry.lock", "gemfile.lock", "composer.lock"} else 1, str(p)))
    return found


def _render_manifests(repo_dir: Path, manifests: list[Path]) -> str:
    chunks: list[str] = []
    total = 0
    for p in manifests:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = p.relative_to(repo_dir).as_posix()
        body = text[:_MAX_FILE_BYTES]
        if len(text) > _MAX_FILE_BYTES:
            body += "\n... (truncated) ..."
        block = f"### {rel}\n```\n{body}\n```"
        if total + len(block) > _MAX_TOTAL_BYTES:
            chunks.append("... (manifest budget exceeded; remaining files omitted) ...")
            break
        total += len(block)
        chunks.append(block)
    return "\n\n".join(chunks)


def run(ctx: RunContext) -> Path | None:
    if not ctx.config.sca_enabled:
        return None
    scope = ctx.load_scope()
    manifests = _collect_manifests(ctx.repo_dir)
    if not manifests:
        _log("no dependency manifests found; skipping SCA")
        return None
    try:
        ctx.assert_budget()
    except BudgetExceeded as exc:
        _log(f"budget reached; skipping SCA ({exc})")
        return None

    template = (ctx.assets_dir / "03_dependency_audit_prompt.md").read_text(encoding="utf-8")
    rendered = fill_placeholders(template, {
        "PROGRAM_NAME": scope.program_name,
        "REPO_PATH": str(ctx.repo_dir.resolve()),
        "PROHIBITED_TECHNIQUES": "\n".join(f"- {p}" for p in scope.prohibited_techniques),
        "MANIFESTS": _render_manifests(ctx.repo_dir, manifests),
    })
    assert_prohibited_present(rendered, scope.prohibited_techniques)   # guardrail

    findings_filename = "SECURITY_FINDINGS__dependencies.json"
    prompt = with_artifact_contract(
        rendered,
        artifacts=[{"type": "findings", "filename": findings_filename,
                    "schema": "findings_schema.json",
                    "desc": "dependency findings (known-vulnerable pinned versions)"}],
        extra_rules=["Detection and reporting ONLY: do not patch, do not contact any host/registry."],
    )
    schema_text = (ctx.assets_dir / "findings_schema.json").read_text(encoding="utf-8")
    prompt += ("\n\n## FINDINGS JSON SCHEMA (the file MUST validate against this)\n```json\n"
               + schema_text + "\n```\n")

    work = ctx.work_dir("sca")
    _log(f"scanning {len(manifests)} manifest file(s)")
    try:
        result = ctx.runner.run(
            prompt=prompt, run_dir=ctx.run_dir, work_dir=work,
            model=ctx.config.model_for("sca"), stage="sca", run_id=ctx.run_id,
            repo_dir=ctx.repo_dir, allowed_tools=ARTIFACT_TOOLS, label="sca-dependencies")
        files = collect_output_files(result, "SECURITY_FINDINGS__*.json")
    except RunnerError as exc:
        files = sorted(work.glob("SECURITY_FINDINGS__*.json"))
        if not files:
            _log(f"SCA session failed, no partial artifact ({exc})")
            return None
    if not files:
        _log("SCA produced no findings file")
        return None

    import json
    chosen = next((f for f in files if f.name == findings_filename), files[0])
    try:
        raw_doc = json.loads(chosen.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _log(f"SCA findings file is not valid JSON ({exc}); skipping")
        return None
    doc, repaired, unrec, _coerced = _normalize_findings_doc(raw_doc, ctx, scope, "dependencies")
    doc["audit_focus"] = "dependencies"
    n = len(doc.get("findings", []))
    if n == 0:
        _log("no confidently-vulnerable dependencies found")
        return None
    if repaired:
        _log(f"schema-repaired {len(repaired)} dependency finding(s)")
    ctx.findings_dir.mkdir(parents=True, exist_ok=True)
    out = ctx.findings_dir / "dependencies.json"
    out.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    _log(f"{n} dependency finding(s) -> {out.name}")
    return out
