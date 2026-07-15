"""Stage 1 — Ingest.

Parse the program brief into ``scope.json`` (LLM extraction, then schema validation), set the
structural live-interaction flags, and copy/clone the target repo into the run dir READ-ONLY.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from ..config import ARTIFACT_TOOLS
from ..context import RunContext, collect_output_files
from ..models import AssetVersion, RunMeta, Scope
from ..rendering import sha256_text, with_artifact_contract
from ..schemas import validate_scope

# Default hard limits injected when the brief does not state them. A real program effectively
# always forbids these; an empty prohibited_techniques list would also trip the render-time
# guardrail downstream, so we never allow it to be empty.
_DEFAULT_PROHIBITED = [
    "no denial-of-service / stress / volumetric testing",
    "no automated scanning or exploitation against live hosts",
    "no social engineering",
    "no physical testing",
    "no testing against production user data",
]

_ASSET_FILES = (
    "00_recon_synthesis_meta_prompt.md",
    "01_audit_prompt_template.md.j2",
    "02_adversarial_validation_prompt.md",
    "scope_schema.json",
    "findings_schema.json",
)

_EXTRACTION_PROMPT = """\
# SCOPE EXTRACTION (pipeline stage 1)

You are extracting a structured, authoritative scope object from a bug-bounty program brief.
This is an AUTHORIZED engagement. Read the brief and emit a single `scope.json` that validates
against the JSON Schema below. Be conservative and literal — do not invent in-scope assets.

Rules:
- Copy the brief verbatim into `program_brief_raw`.
- `target_type` is "source_and_live" only if the brief clearly authorizes a live asset;
  otherwise "source_only".
- `automation_allowed`: set true ONLY if the brief explicitly permits automated tooling/scanners;
  if it is unclear or unstated, set it to false (stricter is safer).
- `prohibited_techniques` MUST be non-empty. Include every hard limit the brief states, AND if
  the brief is silent, include these conservative defaults verbatim:
{defaults}
- Put the in-scope source repository as an `in_scope` entry of type "source_repo".

JSON SCHEMA (scope_schema.json):
```json
{schema}
```

PROGRAM BRIEF (raw):
```
{brief}
```
"""


def _make_readonly(root: Path) -> None:
    """Best-effort: strip write bits from every file so no session can patch the repo. The
    primary guarantee is the runner's tool restriction (no Edit/Write into the repo); this is
    defense-in-depth."""
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            p = Path(dirpath) / name
            try:
                mode = p.stat().st_mode
                os.chmod(p, mode & ~0o222)
            except OSError:
                pass  # never fail the run over a chmod


def _strip_nulls(obj):
    """Recursively drop dict keys whose value is ``None``. Real models routinely emit optional
    fields as ``null`` (e.g. ``"rate_limits": null``); the JSON Schema treats a null optional
    as a type error, so we normalize null-as-absent BEFORE the schema gate. A required field
    emitted as null becomes missing and still fails validation loudly."""
    if isinstance(obj, dict):
        return {k: _strip_nulls(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_strip_nulls(v) for v in obj]
    return obj


def _is_url(source: str) -> bool:
    s = source.strip().lower()
    return (
        s.startswith(("http://", "https://", "git@", "ssh://", "git://"))
        or s.endswith(".git")
    )


def _log(msg: str) -> None:
    print(f"[ingest] {msg}", file=sys.stderr)


# --------------------------------------------------------------- curated reference links
def _normalize_link(url: str) -> str:
    """Normalized dedup/comparison key: trim, lowercase scheme+host (keep path case), strip a
    single trailing slash. Used only for comparison; the stored value stays verbatim."""
    parts = urlsplit(url.strip())
    norm = urlunsplit((parts.scheme.lower(), parts.netloc.lower(),
                       parts.path, parts.query, parts.fragment))
    if norm.endswith("/"):
        norm = norm[:-1]
    return norm


def _is_http_url(line: str) -> bool:
    parts = urlsplit(line.strip())
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def _parse_links_file(path: Path) -> tuple[list[str], int]:
    """Read curated reference links, one URL per line. Returns ``(valid_urls_in_order,
    skipped_count)``.

    Blank lines and lines starting with ``#`` are ignored. Only ``http(s)`` URLs are accepted;
    any other line is SKIPPED with a warning (never fails the whole ingest). Raises
    ``FileNotFoundError`` if the file does not exist; an empty/all-comment file yields no links
    and no error."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"--links file not found: {p}")
    valid: list[str] = []
    skipped = 0
    for raw_line in p.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if _is_http_url(line):
            valid.append(line)
        else:
            skipped += 1
            _log(f"--links: skipping malformed link (not http/https): {line!r}")
    return valid, skipped


def _merge_reference_links(
    extracted: list[str], user_links: list[str], repo_arg: str
) -> tuple[list[str], dict]:
    """Merge curated ``--links`` (FIRST, verbatim — they are curated) with extracted links
    (appended only if new). Dedup by normalized key, first occurrence wins, value stored
    verbatim. Any link whose normalized value equals the ``--repo`` argument is DROPPED — the
    code repo belongs in ``--repo``, never in ``reference_links``."""
    repo_norm = _normalize_link(repo_arg)
    seen: set[str] = set()
    merged: list[str] = []
    stats = {"user_added": 0, "extracted_added": 0, "deduped": 0, "dropped_repo": 0}

    def consider(link: str, *, is_user: bool) -> None:
        n = _normalize_link(link)
        if n == repo_norm:
            stats["dropped_repo"] += 1
            _log(f"--links: dropping {link!r} - it matches --repo; the code repo belongs in "
                 "--repo, not reference_links")
            return
        if n in seen:
            stats["deduped"] += 1
            return
        seen.add(n)
        merged.append(link)
        stats["user_added" if is_user else "extracted_added"] += 1

    for link in user_links:          # curated user links first (verbatim)
        consider(link, is_user=True)
    for link in extracted:           # then extraction-derived links not already present
        consider(link, is_user=False)
    return merged, stats


def acquire_repo(source: str, dest: Path, *, is_url: bool, commit: str | None = None) -> None:
    """Clone (URL) or copy (local path) the target source into ``dest`` and mark it read-only.

    ``commit`` pins the analyzed source to a specific revision (reproducible benchmark corpora / a
    known-CVE checkout): for a URL it fetches that revision (falling back to a full clone + checkout
    if the host disallows fetch-by-sha); for a local path it checks the copy out at that revision.
    Without ``commit`` the behaviour is unchanged (shallow clone of the default head / plain copy).

    Note: cloning the source repository from its host (e.g. GitHub) fetches SOURCE — it is not
    contacting the bug-bounty program's live target host, which no stage ever does.
    """
    if dest.exists():
        raise FileExistsError(f"repo dir already exists: {dest}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    if is_url:
        if commit:
            _clone_at_commit(source, dest, commit)
        else:
            subprocess.run(
                ["git", "clone", "--depth", "1", source, str(dest)],
                check=True, capture_output=True, text=True,
            )
    else:
        src = Path(source).expanduser().resolve()
        if not src.is_dir():
            raise NotADirectoryError(f"local repo path is not a directory: {src}")
        shutil.copytree(src, dest)
        if commit:
            if not (dest / ".git").exists():
                shutil.rmtree(dest, ignore_errors=True)
                raise RuntimeError(f"cannot pin commit {commit}: '{src}' is not a git repository")
            subprocess.run(["git", "-C", str(dest), "checkout", "--quiet", commit],
                           check=True, capture_output=True, text=True)
    _make_readonly(dest)


def _clone_at_commit(url: str, dest: Path, commit: str) -> None:
    """Materialize ``url`` at exactly ``commit``. Prefer a shallow fetch of that single revision
    (fast, minimal); fall back to a full clone + checkout for hosts that reject fetch-by-sha."""
    try:
        dest.mkdir(parents=True)
        for args in (["init", "--quiet"],
                     ["remote", "add", "origin", url],
                     ["fetch", "--depth", "1", "--quiet", "origin", commit],
                     ["checkout", "--quiet", "FETCH_HEAD"]):
            subprocess.run(["git", "-C", str(dest), *args],
                           check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError:
        shutil.rmtree(dest, ignore_errors=True)          # start clean for the fallback
        subprocess.run(["git", "clone", "--quiet", url, str(dest)],
                       check=True, capture_output=True, text=True)
        subprocess.run(["git", "-C", str(dest), "checkout", "--quiet", commit],
                       check=True, capture_output=True, text=True)


def repo_commit(repo_dir: Path) -> tuple[str | None, str | None]:
    """Best-effort pinned commit of the acquired repo copy: (sha, iso-date), or (None, None) if it
    is not a git tree. Read-only; never fails the run."""
    if not (repo_dir / ".git").exists():
        return None, None
    try:
        sha = subprocess.run(["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
                             check=True, capture_output=True, text=True).stdout.strip()
        date = subprocess.run(["git", "-C", str(repo_dir), "show", "-s", "--format=%cs", "HEAD"],
                              capture_output=True, text=True).stdout.strip() or None
        return (sha or None), date
    except (subprocess.SubprocessError, OSError):
        return None, None


def _repo_name(repo: str, is_url: bool) -> str:
    if is_url:
        n = repo.rstrip("/").split("/")[-1]
        n = n[:-4] if n.lower().endswith(".git") else n
        return n or "local-review"
    return Path(repo).expanduser().resolve().name or "local-review"


def _local_scope(repo: str, is_url: bool) -> dict:
    """Synthesize a minimal **source-only** scope for a local/personal codebase audited WITHOUT a
    bug-bounty brief. The folder itself is the scope; conservative prohibited-technique defaults
    apply; no live hosts. Deterministic — the ingest stage spends zero tokens in this mode."""
    name = _repo_name(repo, is_url)
    return {
        "program_name": name,
        "platform": "local",
        "target_type": "source_only",
        "in_scope": [{"asset": repo, "type": "source_repo"}],
        "out_of_scope": [],
        "prohibited_techniques": list(_DEFAULT_PROHIBITED),
        "automation_allowed": True,
        "reference_links": [],
        "program_brief_raw": (
            f"Local source-only security review of '{name}'. The owner's own or private codebase, "
            "analyzed statically — no live hosts are contacted and nothing is submitted."),
    }


def _asset_versions(assets_dir: Path) -> list[AssetVersion]:
    out: list[AssetVersion] = []
    for name in _ASSET_FILES:
        text = (assets_dir / name).read_text(encoding="utf-8")
        out.append(AssetVersion(path=f"prompts/{name}", sha256=sha256_text(text)))
    return out


def run(ctx: RunContext, *, brief_path: Path | None, repo: str, repo_is_url: bool | None = None,
        links_path: Path | None = None, accepted_risks_path: Path | None = None,
        commit: str | None = None) -> Scope:
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    is_url = _is_url(repo) if repo_is_url is None else repo_is_url

    if brief_path is None:
        # --- Local / personal review (no bug-bounty brief): synthesize the scope, zero tokens ---
        raw = _local_scope(repo, is_url)
        (ctx.run_dir / "brief.txt").write_text(raw["program_brief_raw"], encoding="utf-8")
        _log(f"ingest: local source-only review of '{raw['program_name']}' "
             "(no brief — synthesized scope, zero-token ingest)")
    else:
        # --- Bug-bounty program: LLM extraction of brief -> scope.json --------------------
        brief_text = Path(brief_path).read_text(encoding="utf-8")
        (ctx.run_dir / "brief.txt").write_text(brief_text, encoding="utf-8")
        schema_text = (ctx.assets_dir / "scope_schema.json").read_text(encoding="utf-8")
        prompt = _EXTRACTION_PROMPT.format(
            defaults="\n".join(f"  - {d}" for d in _DEFAULT_PROHIBITED),
            schema=schema_text,
            brief=brief_text,
        )
        prompt = with_artifact_contract(
            prompt,
            artifacts=[{
                "type": "scope", "filename": "scope.json", "schema": "scope_schema.json",
                "desc": "the extracted scope object",
            }],
        )
        result = ctx.runner.run(
            prompt=prompt,
            run_dir=ctx.run_dir,
            work_dir=ctx.work_dir("ingest"),
            model=ctx.config.model_for("ingest"),
            stage="ingest",
            run_id=ctx.run_id,
            repo_dir=None,                 # brief text only; no repo, no live host
            allowed_tools=ARTIFACT_TOOLS,
            label="scope-extraction",
        )
        files = collect_output_files(result, "scope.json")
        scope_files = [f for f in files if f.name == "scope.json"]
        if not scope_files:
            raise RuntimeError("ingest: model did not produce scope.json")
        raw = json.loads(scope_files[0].read_text(encoding="utf-8"))
        raw = _strip_nulls(raw)                     # null optional fields == absent (real models)
        raw.setdefault("program_brief_raw", brief_text)

    # Conservative post-processing the code owns (not left to the model):
    if not raw.get("prohibited_techniques"):
        raw["prohibited_techniques"] = list(_DEFAULT_PROHIBITED)

    # Curated --links are purely ADDITIVE to the extracted reference_links, merged here (before
    # the schema gate, so the merged result is what gets validated and written to scope.json).
    if links_path is not None:
        user_links, n_skipped = _parse_links_file(Path(links_path))
        merged, stats = _merge_reference_links(
            raw.get("reference_links") or [], user_links, repo)
        raw["reference_links"] = merged
        _log(f"--links: {stats['user_added']} added, {n_skipped} skipped (malformed), "
             f"{stats['deduped']} duplicate(s) ignored, {stats['dropped_repo']} dropped "
             f"(== --repo); {stats['extracted_added']} extracted link(s) kept")

    # Accepted-risk / design context (out-of-band file): the vendor's intended behaviors / known
    # limitations, injected downstream so they aren't re-reported as bugs. Additive; never inferred.
    if accepted_risks_path is not None:
        risks_text = Path(accepted_risks_path).read_text(encoding="utf-8").strip()
        if risks_text:
            raw["accepted_risks"] = risks_text
            _log(f"--accepted-risks: loaded {len(risks_text)} chars of design context")

    validate_scope(raw, ctx.assets_dir)            # schema gate
    scope = Scope.model_validate(raw)
    if not scope.prohibited_techniques:            # guardrail precondition for every render
        raise RuntimeError("ingest: scope.prohibited_techniques is empty after extraction")

    ctx.scope_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    ctx.scope = scope

    # --- acquire repo read-only ------------------------------------------------------
    repo_source = repo
    acquire_repo(repo, ctx.repo_dir, is_url=is_url, commit=commit)
    commit_sha, commit_date = repo_commit(ctx.repo_dir)   # pin the analyzed source (reproducibility)

    # --- meta.json (reproducibility + cost control) ----------------------------------
    meta = RunMeta(
        run_id=ctx.run_id,
        created_at=ctx.timestamp(),
        program_name=scope.program_name,
        target_type=scope.target_type,
        repo_source=repo_source,
        repo_is_url=is_url,
        repo_commit=commit_sha,
        repo_commit_date=commit_date,
        runner=ctx.config.runner,
        stage_models=dict(ctx.config.stage_models),
        live_forbidden=True,                                   # always
        automation_forbidden=not bool(scope.automation_allowed),
        asset_versions=_asset_versions(ctx.assets_dir),
    )
    ctx.meta_path.write_text(meta.model_dump_json(indent=2), encoding="utf-8")
    return scope
