"""Stage RUNTIME (opt-in, sandboxed) — confirm/refute findings with HTTP-level PoCs.

Safety model (see docs/runtime-verification-study.md): build the OSS target from the CLONED SOURCE
into an EPHEMERAL, EGRESS-BLOCKED, LOOPBACK-ONLY container and probe ONLY that local instance. The
program's real in-scope hosts are NEVER contacted. This stage is OFF by default and best-effort —
it gracefully skips (never fails the run) when runtime is disabled, Docker is absent, no launcher
recipe is given, or no probe plan exists.

Two-container design so the target image needs no probe tooling:
  * app container   — ``docker run -d --network=none`` runs the built app on 127.0.0.1:PORT
                      (only loopback exists in the namespace → no egress possible);
  * probe container — ``--network=container:<app>`` joins that SAME sealed namespace and runs a
                      FIXED stdlib probe runner (not model-controlled) against 127.0.0.1:PORT.

R1: the probe plan is hand-written at ``runs/<id>/runtime_probe_plan.json`` (LLM generation is R2).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ..config import ARTIFACT_TOOLS
from ..context import RunContext, collect_output_files
from ..guardrails import (assert_loopback_only, validate_probe_plan, RuntimeProbeError,
                          assert_prohibited_present)
from ..rendering import fill_placeholders, with_artifact_contract
from ..runner import RunnerError
from ..verify import _copy_repo

_PROBE_IMAGE = "python:3-alpine"   # standard, app-agnostic probe tooling (joins the sealed netns)


def _log(msg: str) -> None:
    print(f"[runtime] {msg}", file=sys.stderr)


def _docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


# The FIXED in-container probe runner. Not model-controlled. Polls for boot, then replays the
# validated plan against loopback with per-request timeout + a rate cap, recording observations.
_PROBE_RUNNER = r'''
import json, time, urllib.request, urllib.error, socket, http.cookiejar
cfg = json.load(open("/work/probe_cfg.json"))
plan = json.load(open("/work/probe_plan.json"))
port = cfg["port"]; base = "http://127.0.0.1:%d" % port
# wait for boot
deadline = time.time() + cfg["boot_timeout"]
up = False
while time.time() < deadline:
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=2); s.close(); up = True; break
    except OSError:
        time.sleep(1)

def send(opener, req):
    path = req.get("path", "/")
    url = path if path.startswith("http") else base + (path if path.startswith("/") else "/" + path)
    data = req.get("body")
    body = data.encode("utf-8") if isinstance(data, str) else None
    r = urllib.request.Request(url, data=body, method=req.get("method", "GET").upper(),
                               headers=req.get("headers") or {})
    rec = {"method": r.get_method(), "path": path}
    try:
        with opener.open(r, timeout=cfg["req_timeout"]) as resp:
            rec.update(status=resp.status, body_snippet=resp.read(2048).decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        snippet = e.read(2048).decode("utf-8", "replace") if hasattr(e, "read") else ""
        rec.update(status=e.code, body_snippet=snippet)
    except Exception as e:
        rec.update(status=None, error=str(e)[:300])
    return rec

results = {"booted": up, "findings": []}
sent = 0
for entry in plan:
    fr = {"finding_id": entry.get("finding_id"), "requests": []}
    # Per-finding cookie jar so an auth/login step's session carries into the probes.
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    auth = entry.get("auth")
    if isinstance(auth, dict) and sent < cfg["max_requests"]:
        sent += 1
        ar = send(opener, auth); ar["auth"] = True
        fr["requests"].append(ar)
        time.sleep(cfg["interval"])
    for req in entry.get("requests", []):
        if sent >= cfg["max_requests"]:
            fr["requests"].append({"skipped": "max_requests cap reached"}); continue
        sent += 1
        rec = send(opener, req); rec["expect"] = req.get("expect")
        ex = req.get("expect") or {}
        ok = True
        if "status" in ex:
            want = ex["status"]; want = want if isinstance(want, list) else [want]
            ok = ok and rec.get("status") in want
        for needle in (ex.get("body_contains") or []):
            ok = ok and (needle in (rec.get("body_snippet") or ""))
        rec["expect_met"] = ok
        fr["requests"].append(rec)
        time.sleep(cfg["interval"])
    results["findings"].append(fr)
json.dump(results, open("/work/results.json", "w"), indent=2)
'''


def _run_sandbox(ctx: RunContext, copy_dir: Path, work_dir: Path, plan: list[dict],
                 launcher: dict) -> dict | None:
    cfg = ctx.config
    name = f"argo-rt-{ctx.run_id}"[:60]
    (work_dir / "probe_plan.json").write_text(json.dumps(plan), encoding="utf-8")
    (work_dir / "probe_runner.py").write_text(_PROBE_RUNNER, encoding="utf-8")
    (work_dir / "probe_cfg.json").write_text(json.dumps({
        "port": launcher["port"], "boot_timeout": launcher["boot_timeout"],
        "req_timeout": cfg.runtime_request_timeout_s, "max_requests": cfg.runtime_max_requests,
        "interval": cfg.runtime_min_request_interval_s}), encoding="utf-8")

    start = launcher.get("run_cmd")
    env_flags = [a for k, v in (launcher.get("env") or {}).items() for a in ("-e", f"{k}={v}")]
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)   # stale cleanup
    try:
        # App container: sealed (only loopback). The isolated source copy is mounted read-only at
        # /src for the build-at-run model; a self-contained image (mount_source=False) uses its
        # baked /src. With a run_cmd we `sh -lc` it; without one we use the image's own CMD.
        mount = ["-v", f"{copy_dir.resolve().as_posix()}:/src:ro"] if launcher.get("mount_source") else []
        cmd = ["docker", "run", "-d", "--rm", "--name", name, "--network=none",
               *mount, *env_flags, "-w", "/src", launcher["image"]]
        if start:
            cmd += ["sh", "-lc", start]
        up = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if up.returncode != 0:
            _log(f"app container failed to start: {(up.stderr or up.stdout)[:300]}")
            return None
        # Probe container: joins the SAME sealed namespace; runs the fixed stdlib runner.
        total_timeout = launcher["boot_timeout"] + cfg.runtime_request_timeout_s * cfg.runtime_max_requests + 60
        pr = subprocess.run(
            ["docker", "run", "--rm", f"--network=container:{name}",
             "-v", f"{work_dir.resolve().as_posix()}:/work", _PROBE_IMAGE, "python", "/work/probe_runner.py"],
            capture_output=True, text=True, timeout=total_timeout)
        res_path = work_dir / "results.json"
        if not res_path.is_file():
            _log(f"probe runner produced no results.json (exit {pr.returncode})")
            tail = ((pr.stderr or "") + (pr.stdout or "")).strip()[-600:]
            if tail:
                _log(f"probe container output: {tail}")
            return None
        return json.loads(res_path.read_text(encoding="utf-8"))
    except subprocess.TimeoutExpired:
        _log("sandbox timed out")
        return None
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


# ------------------------------------------------------------------ R3: launcher auto-detection
def _dockerfile_expose(df: Path) -> int | None:
    """The first EXPOSE port in a Dockerfile, if any."""
    try:
        for line in df.read_text(encoding="utf-8", errors="replace").splitlines():
            s = line.strip()
            if s.upper().startswith("EXPOSE"):
                return int(s.split()[1].split("/")[0])
    except (OSError, ValueError, IndexError):
        pass
    return None


def _build_image(ctx: RunContext, dockerfile: Path, context: Path) -> str | None:
    """docker-build a Dockerfile (network on) into a throwaway tag for the sealed run."""
    tag = f"argo-rt-auto-{ctx.run_id}".lower().replace("_", "-")[:60]
    _log(f"building image from {dockerfile.name} (network on; may take a while)...")
    try:
        r = subprocess.run(
            ["docker", "build", "-f", str(dockerfile.resolve()), "-t", tag, str(context.resolve())],
            capture_output=True, text=True, timeout=ctx.config.runtime_build_timeout_s)
    except subprocess.TimeoutExpired:
        _log("docker build timed out")
        return None
    if r.returncode != 0:
        _log(f"docker build failed: {((r.stderr or '') + (r.stdout or '')).strip()[-400:]}")
        return None
    return tag


def _launcher_from_recipe(recipe: dict, ctx: RunContext, base_dir: Path) -> dict | None:
    """Turn an argo-runtime.json recipe ({image|dockerfile, run_cmd?, port?, env?, ...}) into a
    resolved launcher; builds the Dockerfile if the recipe names one."""
    cfg = ctx.config
    image = recipe.get("image")
    if recipe.get("dockerfile"):
        df = base_dir / recipe["dockerfile"]
        context = (base_dir / recipe["build_context"]) if recipe.get("build_context") else ctx.repo_dir
        image = _build_image(ctx, df, context)
    if not image:
        return None
    return {"image": image, "run_cmd": recipe.get("run_cmd"),
            "port": int(recipe.get("port", cfg.runtime_port)),
            "mount_source": bool(recipe.get("mount_source", False)),
            "env": recipe.get("env") or {},
            "boot_timeout": int(recipe.get("boot_timeout", cfg.runtime_boot_timeout_s))}


def _resolve_launcher(ctx: RunContext, scope) -> dict | None:
    """Provisioning resolution (priority): explicit config -> argo-runtime.json recipe -> the repo's
    own Dockerfile. Returns a launcher dict or None (graceful skip)."""
    cfg = ctx.config
    if cfg.runtime_image and cfg.runtime_run_cmd:
        return {"image": cfg.runtime_image, "run_cmd": cfg.runtime_run_cmd, "port": cfg.runtime_port,
                "mount_source": cfg.runtime_mount_source, "env": {},
                "boot_timeout": cfg.runtime_boot_timeout_s}
    for cand in (ctx.repo_dir / "argo-runtime.json", ctx.repo_dir / ".argo" / "runtime.json",
                 ctx.run_dir / "runtime_recipe.json"):
        if cand.is_file():
            try:
                recipe = json.loads(cand.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                _log(f"recipe {cand.name} unreadable ({exc}); skipping it")
                continue
            launcher = _launcher_from_recipe(recipe, ctx, cand.parent)
            if launcher:
                _log(f"using launcher recipe {cand.name}")
                return launcher
    df = ctx.repo_dir / "Dockerfile"
    if df.is_file():
        image = _build_image(ctx, df, ctx.repo_dir)
        if image:
            port = _dockerfile_expose(df) or cfg.runtime_port
            _log(f"built the repo's own Dockerfile (port {port}); using its default CMD")
            return {"image": image, "run_cmd": None, "port": port, "mount_source": False,
                    "env": {}, "boot_timeout": cfg.runtime_boot_timeout_s}
    return None


# --------------------------------------------------------------------- R2: LLM propose / interpret
def _findings_for_prompt(ctx: RunContext) -> list[dict]:
    """The validated findings, trimmed to what a probe author needs."""
    vf = ctx.validated_findings_path
    if not vf.is_file():
        return []
    try:
        doc = json.loads(vf.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    keep = ("id", "title", "severity", "affected", "vulnerable_flow", "why_vulnerable",
            "exploit_scenario")
    return [{k: f.get(k) for k in keep if f.get(k) is not None} for f in doc.get("findings", [])]


def _generate_plan(ctx: RunContext, scope) -> list | None:
    """R2: an LLM 'propose' session designs a loopback-only probe plan from the findings (offline,
    read-only repo). Returns the parsed plan, or None on failure/empty."""
    cfg = ctx.config
    findings = _findings_for_prompt(ctx)
    if not findings:
        _log("no validated findings to generate probes for; skipping")
        return None
    state_note = ("State-changing methods (POST/PUT/PATCH/DELETE) are permitted but use them only "
                  "for non-destructive confirmations." if cfg.runtime_allow_state_changing
                  else "ONLY GET/HEAD/OPTIONS are permitted — no writes.")
    template = (ctx.assets_dir / "04_runtime_probe_prompt.md").read_text(encoding="utf-8")
    creds = cfg.runtime_credentials
    creds_note = (f"Test credentials you MAY use in an `auth` login step: {json.dumps(creds)}."
                  if creds else "No test credentials provided — only anonymous probes are possible; "
                  "for findings that need a session, omit them.")
    rendered = fill_placeholders(template, {
        "PROGRAM_NAME": scope.program_name, "REPO_PATH": str(ctx.repo_dir.resolve()),
        "PORT": str(cfg.runtime_port), "FINDINGS_JSON": json.dumps(findings, indent=2),
        "PROHIBITED_TECHNIQUES": "\n".join(f"- {p}" for p in scope.prohibited_techniques),
        "MAX_REQUESTS": str(cfg.runtime_max_requests),
        "METHOD_HINT": "GET/HEAD/OPTIONS" if not cfg.runtime_allow_state_changing else "GET/HEAD/OPTIONS, and POST/PUT only if non-destructive",
        "STATE_CHANGING_NOTE": state_note, "CREDENTIALS_NOTE": creds_note})
    assert_prohibited_present(rendered, scope.prohibited_techniques)
    prompt = with_artifact_contract(rendered, artifacts=[{
        "type": "probe_plan", "filename": "runtime_probe_plan.json", "schema": None,
        "desc": "the loopback-only probe plan (list of {finding_id, requests})"}])
    work = ctx.work_dir("runtime", "propose")
    try:
        result = ctx.runner.run(prompt=prompt, run_dir=ctx.run_dir, work_dir=work,
                                model=cfg.model_for("runtime"), stage="runtime", run_id=ctx.run_id,
                                repo_dir=ctx.repo_dir, allowed_tools=ARTIFACT_TOOLS, label="runtime-propose")
        files = collect_output_files(result, "runtime_probe_plan.json")
    except RunnerError as exc:
        _log(f"probe-plan generation failed ({exc}); skipping")
        return None
    if not files:
        _log("probe-plan generation produced no file; skipping")
        return None
    try:
        plan = json.loads(files[0].read_text(encoding="utf-8"))
        plan = plan.get("plan", plan) if isinstance(plan, dict) else plan
    except (OSError, ValueError) as exc:
        _log(f"generated probe plan is not valid JSON ({exc}); skipping")
        return None
    if isinstance(plan, list) and plan:
        (ctx.run_dir / "runtime_probe_plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
        _log(f"LLM generated a probe plan for {len(plan)} finding(s)")
        return plan
    _log("LLM proposed no probeable findings")
    return None


def _interpret(ctx: RunContext, results: dict) -> dict:
    """R2: an LLM 'interpret' session judges each finding confirmed/refuted/inconclusive from the
    observed responses. Returns {finding_id: verdict_dict}; empty on failure (falls back to expect_met)."""
    probe_findings = []
    for f in results.get("findings", []):
        probe_findings.append({"finding_id": f.get("finding_id"), "requests": [
            {"method": r.get("method"), "path": r.get("path"), "status": r.get("status"),
             "body_snippet": (r.get("body_snippet") or "")[:600], "expect_met": r.get("expect_met")}
            for r in f.get("requests", [])]})
    if not probe_findings:
        return {}
    template = (ctx.assets_dir / "05_runtime_interpret_prompt.md").read_text(encoding="utf-8")
    rendered = fill_placeholders(template, {
        "PROBE_FINDINGS_JSON": json.dumps(probe_findings, indent=2),
        "BOOTED": str(results.get("booted"))})
    prompt = with_artifact_contract(rendered, artifacts=[{
        "type": "runtime_verdicts", "filename": "runtime_verdicts.json", "schema": None,
        "desc": "per-finding runtime verdicts"}])
    work = ctx.work_dir("runtime", "interpret")
    try:
        result = ctx.runner.run(prompt=prompt, run_dir=ctx.run_dir, work_dir=work,
                                model=ctx.config.model_for("runtime"), stage="runtime", run_id=ctx.run_id,
                                repo_dir=None, allowed_tools=ARTIFACT_TOOLS, label="runtime-interpret")
        files = collect_output_files(result, "runtime_verdicts.json")
        if not files:
            return {}
        doc = json.loads(files[0].read_text(encoding="utf-8"))
    except (RunnerError, OSError, ValueError) as exc:
        _log(f"interpretation failed ({exc}); falling back to expectation matching")
        return {}
    return {v.get("finding_id"): v for v in doc.get("verdicts", []) if v.get("finding_id")}


def run(ctx: RunContext) -> Path | None:
    cfg = ctx.config
    if not cfg.runtime_enabled:
        return None
    scope = ctx.load_scope()
    plan_path = ctx.run_dir / "runtime_probe_plan.json"
    if plan_path.is_file():
        try:
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            plan = plan.get("plan", plan) if isinstance(plan, dict) else plan
            if not isinstance(plan, list):
                raise ValueError("probe plan must be a list of {finding_id, requests:[...]}")
        except (OSError, ValueError) as exc:
            _log(f"invalid probe plan ({exc}); skipping")
            return None
    else:
        # R2: no hand-written plan -> generate one with the LLM (offline, validated below).
        plan = _generate_plan(ctx, scope)
        if not plan:
            return None

    # SAFETY GATES (hard): loopback-only + anti-DoS caps. A violation aborts runtime, never proceeds.
    assert_loopback_only(plan, scope)
    validate_probe_plan(plan, max_requests=cfg.runtime_max_requests,
                        max_payload_bytes=cfg.runtime_max_payload_bytes,
                        allow_state_changing=cfg.runtime_allow_state_changing)

    if not _docker_ok():
        _log("Docker unavailable; skipping runtime verification (graceful)")
        return None
    # R3: resolve a launcher — explicit config, else an argo-runtime.json recipe, else the repo's
    # own Dockerfile (auto-built). None -> graceful skip.
    launcher = _resolve_launcher(ctx, scope)
    if launcher is None:
        _log("no launcher (config / argo-runtime.json / repo Dockerfile); skipping (graceful)")
        return None

    tmp = Path(tempfile.mkdtemp(prefix="argo-runtime-"))
    copy_dir = tmp / "src"
    work_dir = ctx.work_dir("runtime")
    work_dir.mkdir(parents=True, exist_ok=True)
    try:
        if launcher.get("mount_source"):
            _copy_repo(ctx.repo_dir, copy_dir)
        _log(f"running '{launcher['image']}' (sealed, --network=none) and probing loopback")
        results = _run_sandbox(ctx, copy_dir, work_dir, plan, launcher)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if results is None:
        return None

    # R2: LLM interprets the observations into per-finding verdicts (falls back to expect_met).
    verdicts = _interpret(ctx, results)
    if verdicts:
        results["verdicts"] = list(verdicts.values())

    out = ctx.run_dir / "runtime_results.json"
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    _attach_to_findings(ctx, results, verdicts)
    confirmed = sum(1 for v in verdicts.values() if v.get("runtime_verdict") == "runtime_confirmed") \
        if verdicts else sum(1 for f in results.get("findings", [])
                             for r in f.get("requests", []) if r.get("expect_met"))
    _log(f"booted={results.get('booted')}; {confirmed} finding(s) runtime-confirmed -> {out.name}")
    return out


def _attach_to_findings(ctx: RunContext, results: dict, verdicts: dict) -> None:
    """Merge a per-finding ``runtime`` evidence block into validated_findings.json (best-effort).
    Uses the LLM verdict when present; else falls back to the deterministic expectation match."""
    vf = ctx.validated_findings_path
    if not vf.is_file():
        return
    try:
        doc = json.loads(vf.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    by_id = {f.get("finding_id"): f for f in results.get("findings", [])}
    for finding in doc.get("findings", []):
        ev = by_id.get(finding.get("id"))
        if not ev:
            continue
        v = verdicts.get(finding.get("id"))
        if v:
            verdict, evidence = v.get("runtime_verdict", "runtime_inconclusive"), v.get("evidence")
        else:
            any_met = any(r.get("expect_met") for r in ev.get("requests", []))
            verdict, evidence = ("runtime_confirmed" if any_met else "runtime_inconclusive"), None
        finding.setdefault("validation", {})["runtime"] = {
            "booted": results.get("booted"), "verdict": verdict,
            "evidence": evidence, "probes": ev.get("requests", []),
        }
    vf.write_text(json.dumps(doc, indent=2), encoding="utf-8")
