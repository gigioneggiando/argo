"""Stage SCA — Software-composition analysis.

Read the project's dependency manifests/lockfiles (deterministic file collection) and run ONE
offline session that flags pinned versions with known published advisories. Emits a synthetic
``dependencies`` focus into ``findings/`` so the normal validate + report flow consumes it.

Source-only, no network (uses the model's advisory knowledge — never a registry/advisory API).
A no-op (returns None) when the repo has no recognizable dependency manifests.
"""

from __future__ import annotations

import json
import re
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


# --- deterministic pin extraction (give the model exact name@version@file:line, not raw files) ---
_DOTNET_VER = re.compile(r'<Package(?:Version|Reference)\s+Include="([^"]+)"[^>]*\bVersion="([^"]+)"', re.I)
_PKGCFG = re.compile(r'<package\s+id="([^"]+)"\s+version="([^"]+)"', re.I)
_REQ = re.compile(r'^\s*([A-Za-z0-9_.\-]+)\s*(?:==|>=|~=|<=|@)\s*([0-9][^\s;#]*)')
_GOMOD = re.compile(r'^\s*([^\s/]+/[^\s]+)\s+v([0-9][^\s]*)')
_MAX_PINS = 400


def _extract_pins(repo_dir: Path, manifests: list[Path]) -> list[dict]:
    """Best-effort (ecosystem, name, version, file:line) pins from the common manifests, so the
    model judges concrete versions instead of fishing them out of raw files."""
    pins: list[dict] = []

    def add(name: str, version: str, rel: str, line: int | None):
        pins.append({"name": name.strip(), "version": str(version).strip(),
                     "ref": f"{rel}:{line}" if line else rel})

    for p in manifests:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = p.relative_to(repo_dir).as_posix()
        lines = text.splitlines()
        nm = p.name.lower()
        if nm.endswith(".csproj") or nm in ("directory.packages.props", "directory.build.props"):
            for i, ln in enumerate(lines, 1):
                for m in _DOTNET_VER.finditer(ln):
                    add(m.group(1), m.group(2), rel, i)
        elif nm == "packages.config":
            for i, ln in enumerate(lines, 1):
                for m in _PKGCFG.finditer(ln):
                    add(m.group(1), m.group(2), rel, i)
        elif nm == "package.json":
            try:
                data = json.loads(text)
                for sect in ("dependencies", "devDependencies", "peerDependencies"):
                    for k, v in (data.get(sect) or {}).items():
                        ln = next((i for i, l in enumerate(lines, 1) if f'"{k}"' in l), None)
                        add(k, v, rel, ln)
            except ValueError:
                pass
        elif nm.startswith("requirements") and nm.endswith(".txt"):
            for i, ln in enumerate(lines, 1):
                m = _REQ.match(ln)
                if m:
                    add(m.group(1), m.group(2), rel, i)
        elif nm == "go.mod":
            for i, ln in enumerate(lines, 1):
                m = _GOMOD.match(ln)
                if m:
                    add(m.group(1), "v" + m.group(2), rel, i)
        if len(pins) >= _MAX_PINS:
            break

    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for pin in pins:
        key = (pin["name"].lower(), pin["version"])
        if key not in seen:
            seen.add(key)
            out.append(pin)
    return out[:_MAX_PINS]


def _format_pins(pins: list[dict]) -> str:
    if not pins:
        return "(could not auto-extract pins; read the manifests above directly)"
    return "\n".join(f"- {p['name']} {p['version']}  ({p['ref']})" for p in pins)


# --- deterministic known-vulnerable matching (kills model variance on the high-confidence cases) ---
_KNOWN_PATH = Path(__file__).resolve().parent.parent / "data" / "known_vuln_deps.json"


def _load_known() -> list[dict]:
    try:
        return json.loads(_KNOWN_PATH.read_text(encoding="utf-8-sig")).get("entries", [])
    except (OSError, ValueError):
        return []


def _vparts(v: str) -> list[int]:
    out = []
    for part in str(v).split("."):
        m = re.match(r"\d+", part)
        out.append(int(m.group()) if m else 0)
    return out


def _vle(a: str, b: str) -> bool:
    """a <= b on dotted numeric versions (suffixes ignored)."""
    pa, pb = _vparts(a), _vparts(b)
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    return pa <= pb


def _match_known(pins: list[dict]) -> list[dict]:
    """Deterministically flag pins that match the curated known-vulnerable list. Always runs,
    independent of the model, so the high-confidence advisories are never missed to variance."""
    known = _load_known()
    out: list[dict] = []
    idx = 1
    for pin in pins:
        nm, ver = pin["name"].lower(), pin["version"]
        for e in known:
            if e.get("name", "").lower() != nm:
                continue
            hit = ("prefix" in e and ver.startswith(e["prefix"])) or ("max" in e and _vle(ver, e["max"]))
            if not hit:
                continue
            out.append({
                "id": f"DEP-KNOWN-{idx:03d}",
                "title": f"Known-vulnerable pinned dependency: {pin['name']} {ver}",
                "severity": e.get("severity", "Low"), "confidence": "High",
                "cwe": e.get("cwe", "CWE-937"),
                "owasp": "A06:2021 - Vulnerable and Outdated Components",
                "affected": [pin["ref"]],
                "vulnerable_flow": f"{pin['name']} is pinned at {ver} ({pin['ref']}).",
                "why_vulnerable": f"{e.get('advisory', 'known advisory')}. Pinned version {ver} is in "
                                  "the vulnerable range (matched against Argo's curated known-vuln list).",
                "exploit_scenario": "Reachability depends on whether the vulnerable API is exercised; "
                                    "flagged from the manifest — verify against the advisory database.",
                "impact": "Inherits the dependency advisory's impact if the vulnerable path is reachable.",
                "recommended_fix": f"Bump {pin['name']} to {e.get('fixed', 'a fixed version')}.",
                "source": "sca-known-list"})
            idx += 1
            break
    return out


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

    pins = _extract_pins(ctx.repo_dir, manifests)
    template = (ctx.assets_dir / "03_dependency_audit_prompt.md").read_text(encoding="utf-8")
    rendered = fill_placeholders(template, {
        "PROGRAM_NAME": scope.program_name,
        "REPO_PATH": str(ctx.repo_dir.resolve()),
        "PROHIBITED_TECHNIQUES": "\n".join(f"- {p}" for p in scope.prohibited_techniques),
        "PINS": _format_pins(pins),
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
    det = _match_known(pins)                       # deterministic — always runs, model-independent
    if det:
        _log(f"{len(det)} known-vulnerable pin(s) matched deterministically")
    _log(f"scanning {len(manifests)} manifest file(s); {len(pins)} pin(s); asking the model for the long tail")
    llm_findings: list[dict] = []
    files: list[Path] = []
    try:
        result = ctx.runner.run(
            prompt=prompt, run_dir=ctx.run_dir, work_dir=work,
            model=ctx.config.model_for("sca"), stage="sca", run_id=ctx.run_id,
            repo_dir=ctx.repo_dir, allowed_tools=ARTIFACT_TOOLS, label="sca-dependencies")
        files = collect_output_files(result, "SECURITY_FINDINGS__*.json")
    except RunnerError as exc:
        files = sorted(work.glob("SECURITY_FINDINGS__*.json"))
        if not files:
            _log(f"SCA model session failed ({exc}); using deterministic matches only")
    if files:
        chosen = next((f for f in files if f.name == findings_filename), files[0])
        try:
            ndoc, repaired, _unrec, _c = _normalize_findings_doc(
                json.loads(chosen.read_text(encoding="utf-8-sig")), ctx, scope, "dependencies")
            llm_findings = ndoc.get("findings", [])
            if repaired:
                _log(f"schema-repaired {len(repaired)} model dependency finding(s)")
        except (ValueError, OSError) as exc:
            _log(f"SCA model findings unreadable ({exc}); using deterministic matches only")

    det_refs = {(d.get("affected") or [None])[0] for d in det}
    merged = det + [f for f in llm_findings if (f.get("affected") or [None])[0] not in det_refs]
    if not merged:
        _log("no vulnerable dependencies found")
        return None
    doc = {"program_name": scope.program_name, "audit_focus": "dependencies",
           "generated_at": ctx.timestamp(), "findings": merged}
    ctx.findings_dir.mkdir(parents=True, exist_ok=True)
    out = ctx.findings_dir / "dependencies.json"
    out.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    _log(f"{len(merged)} dependency finding(s) ({len(det)} deterministic + "
         f"{len(merged) - len(det)} model) -> {out.name}")
    return out
