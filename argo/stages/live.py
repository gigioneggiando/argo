"""Stage LIVE (L1) — OPT-IN, heavily gated live testing of the program's IN-SCOPE assets.

⚠️  This is the one stage that touches a real, external host. It is a DELIBERATE, opt-in exception to
Argo's "never contact a live host" rule, intended only for AUTHORIZED bug-bounty engagements whose
rules of engagement permit automated interaction. OFF by default.

Hard rails (all enforced in code, see guardrails.py):
  * ``assert_live_authorized`` — refuses unless the scope's RoE authorize it (automation_allowed,
    safe_harbor not explicitly false, prohibited_techniques declared).
  * ``assert_inscope_only`` — every request must use an ABSOLUTE URL whose host is an in-scope asset;
    out-of-scope / unknown hosts are hard-blocked. NEVER touches anything but in-scope assets.
  * ``validate_probe_plan`` — read-only methods only (unless live_allow_writes), request/rate/size caps.
  * a FIXED executor makes the requests (not a model shell); every request is written to an audit log.

L1 reads a hand-written ``runs/<id>/live_probe_plan.json`` (LLM generation is L2). Read-only by default.
"""

from __future__ import annotations

import http.cookiejar
import json
import sys
import time
import urllib.error
import urllib.request

from ..config import ARTIFACT_TOOLS
from ..context import RunContext, collect_output_files
from ..guardrails import (assert_inscope_only, assert_live_authorized, assert_live_write_policy,
                          validate_probe_plan, assert_prohibited_present)
from ..rendering import fill_placeholders, with_artifact_contract
from ..runner import RunnerError


def _log(msg: str) -> None:
    print(f"[live] {msg}", file=sys.stderr)


def _send(opener, req: dict, cfg) -> tuple[dict, dict]:
    url = str(req.get("url") or req.get("path"))
    method = str(req.get("method", "GET")).upper()
    data = req.get("body")
    body = data.encode("utf-8") if isinstance(data, str) else None
    r = urllib.request.Request(url, data=body, method=method, headers=req.get("headers") or {})
    rec = {"method": method, "url": url, "expect": req.get("expect")}
    # Audit entry: minimal + accountable (method/url/status/size). Read requests omit headers/body so
    # secrets aren't logged; STATE-CHANGING requests (L3) record the body — a mutation MUST be fully
    # accountable (the body is the action), and a write payload is the analyst's own, not a secret leak.
    audit = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "method": method, "url": url}
    if method not in ("GET", "HEAD", "OPTIONS") and data is not None:
        audit["body"] = str(data)[:1000]
    try:
        with opener.open(r, timeout=cfg.live_request_timeout_s) as resp:
            snippet = resp.read(2048).decode("utf-8", "replace")
            rec.update(status=resp.status, body_snippet=snippet)
            audit.update(status=resp.status, bytes=len(snippet))
    except urllib.error.HTTPError as e:
        snippet = e.read(2048).decode("utf-8", "replace") if hasattr(e, "read") else ""
        rec.update(status=e.code, body_snippet=snippet)
        audit.update(status=e.code)
    except Exception as e:                                   # network error, DNS, timeout, ...
        rec.update(status=None, error=str(e)[:300])
        audit.update(error=str(e)[:200])
    ex = req.get("expect") or {}
    ok = True
    if "status" in ex:
        want = ex["status"]
        ok = ok and rec.get("status") in (want if isinstance(want, list) else [want])
    for needle in (ex.get("body_contains") or []):
        ok = ok and (needle in (rec.get("body_snippet") or ""))
    rec["expect_met"] = ok
    return rec, audit


def _execute(ctx: RunContext, plan: list[dict]) -> tuple[dict, list[dict]]:
    cfg = ctx.config
    results: dict = {"findings": []}
    audit: list[dict] = []
    sent = 0
    for entry in plan:
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        fr = {"finding_id": entry.get("finding_id"), "requests": []}
        for req in entry.get("requests", []):
            if sent >= cfg.live_max_requests:
                fr["requests"].append({"skipped": "live_max_requests cap reached"})
                continue
            sent += 1
            rec, alog = _send(opener, req, cfg)
            fr["requests"].append(rec)
            audit.append(alog)
            time.sleep(cfg.live_min_request_interval_s)         # rate cap (anti-DoS)
        results["findings"].append(fr)
    return results, audit


# --------------------------------------------------------------------- L2: LLM propose / interpret
def _findings_for_prompt(ctx: RunContext) -> list[dict]:
    """The validated findings, trimmed to what a live-probe author needs."""
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


def _inscope_web_assets(scope) -> list[str]:
    return [a.asset for a in getattr(scope, "in_scope", []) if getattr(a, "type", None) in ("web", "api")]


def _generate_plan(ctx: RunContext, scope) -> list | None:
    """L2: an OFFLINE LLM 'propose' session designs an in-scope-only live probe plan from the validated
    findings (read-only repo, NO network tools — only the executor later touches the network). The plan
    is validated by the same hard gates before any request. Returns the parsed plan, or None."""
    cfg = ctx.config
    findings = _findings_for_prompt(ctx)
    if not findings:
        _log("no validated findings to generate live probes for; skipping")
        return None
    hosts = _inscope_web_assets(scope)
    if not hosts:
        _log("scope has no in-scope web/api host; nothing to probe live")
        return None
    state_note = (
        f"State-changing methods (POST/PUT/PATCH) are permitted but ONLY for NON-DESTRUCTIVE "
        f"confirmations, at most {cfg.live_max_writes} in total. DELETE is NEVER permitted. Prefer "
        f"creating a single throwaway/benign value over modifying real data, and never delete, "
        f"overwrite, or corrupt anything. Each write must carry an `expect` that proves the issue."
        if cfg.live_allow_writes else "ONLY GET/HEAD/OPTIONS are permitted — no writes.")
    template = (ctx.assets_dir / "06_live_probe_prompt.md").read_text(encoding="utf-8")
    rendered = fill_placeholders(template, {
        "PROGRAM_NAME": scope.program_name, "REPO_PATH": str(ctx.repo_dir.resolve()),
        "IN_SCOPE_HOSTS": "\n".join(f"- {h}" for h in hosts),
        "OUT_OF_SCOPE": "\n".join(f"- {x}" for x in scope.out_of_scope) or "- (none listed)",
        "PROHIBITED_TECHNIQUES": "\n".join(f"- {p}" for p in scope.prohibited_techniques),
        "FINDINGS_JSON": json.dumps(findings, indent=2),
        "MAX_REQUESTS": str(cfg.live_max_requests),
        "METHOD_HINT": "GET/HEAD/OPTIONS" if not cfg.live_allow_writes
                       else "GET/HEAD/OPTIONS, and POST/PUT only if non-destructive",
        "STATE_CHANGING_NOTE": state_note})
    assert_prohibited_present(rendered, scope.prohibited_techniques)
    prompt = with_artifact_contract(rendered, artifacts=[{
        "type": "probe_plan", "filename": "live_probe_plan.json", "schema": None,
        "desc": "the in-scope-only live probe plan (list of {finding_id, requests})"}])
    work = ctx.work_dir("live", "propose")
    try:
        result = ctx.runner.run(prompt=prompt, run_dir=ctx.run_dir, work_dir=work,
                                model=cfg.model_for("live"), stage="live", run_id=ctx.run_id,
                                repo_dir=ctx.repo_dir, allowed_tools=ARTIFACT_TOOLS, label="live-propose")
        files = collect_output_files(result, "live_probe_plan.json")
    except RunnerError as exc:
        _log(f"live probe-plan generation failed ({exc}); skipping")
        return None
    if not files:
        _log("live probe-plan generation produced no file; skipping")
        return None
    try:
        plan = json.loads(files[0].read_text(encoding="utf-8"))
        plan = plan.get("plan", plan) if isinstance(plan, dict) else plan
    except (OSError, ValueError) as exc:
        _log(f"generated live probe plan is not valid JSON ({exc}); skipping")
        return None
    if isinstance(plan, list) and plan:
        (ctx.run_dir / "live_probe_plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
        _log(f"LLM generated a live probe plan for {len(plan)} finding(s)")
        return plan
    _log("LLM proposed no in-scope probeable findings")
    return None


def _interpret(ctx: RunContext, results: dict) -> dict:
    """L2: an OFFLINE LLM 'interpret' session judges each finding live_confirmed/refuted/inconclusive
    from the observed responses. Returns {finding_id: verdict}; empty on failure (falls back to expect_met)."""
    probe_findings = []
    for f in results.get("findings", []):
        probe_findings.append({"finding_id": f.get("finding_id"), "requests": [
            {"method": r.get("method"), "url": r.get("url"), "status": r.get("status"),
             "body_snippet": (r.get("body_snippet") or "")[:600], "expect_met": r.get("expect_met")}
            for r in f.get("requests", []) if "skipped" not in r]})
    if not probe_findings:
        return {}
    template = (ctx.assets_dir / "07_live_interpret_prompt.md").read_text(encoding="utf-8")
    rendered = fill_placeholders(template, {"PROBE_FINDINGS_JSON": json.dumps(probe_findings, indent=2)})
    prompt = with_artifact_contract(rendered, artifacts=[{
        "type": "live_verdicts", "filename": "live_verdicts.json", "schema": None,
        "desc": "per-finding live verdicts"}])
    work = ctx.work_dir("live", "interpret")
    try:
        result = ctx.runner.run(prompt=prompt, run_dir=ctx.run_dir, work_dir=work,
                                model=ctx.config.model_for("live"), stage="live", run_id=ctx.run_id,
                                repo_dir=None, allowed_tools=ARTIFACT_TOOLS, label="live-interpret")
        files = collect_output_files(result, "live_verdicts.json")
        if not files:
            return {}
        doc = json.loads(files[0].read_text(encoding="utf-8"))
    except (RunnerError, OSError, ValueError) as exc:
        _log(f"interpretation failed ({exc}); falling back to expectation matching")
        return {}
    return {v.get("finding_id"): v for v in doc.get("verdicts", []) if v.get("finding_id")}


def _attach_to_findings(ctx: RunContext, results: dict, verdicts: dict) -> None:
    """Merge a per-finding ``live`` evidence block into validated_findings.json (best-effort)."""
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
            verdict, evidence = v.get("live_verdict", "live_inconclusive"), v.get("evidence")
        else:
            any_met = any(r.get("expect_met") for r in ev.get("requests", []))
            verdict, evidence = ("live_confirmed" if any_met else "live_inconclusive"), None
        finding.setdefault("validation", {})["live"] = {
            "verdict": verdict, "evidence": evidence, "probes": ev.get("requests", [])}
    vf.write_text(json.dumps(doc, indent=2), encoding="utf-8")


def run(ctx: RunContext):
    cfg = ctx.config
    if not cfg.live_enabled:
        return None
    plan_path = ctx.run_dir / "live_probe_plan.json"
    has_plan = plan_path.is_file()
    if not has_plan and not ctx.validated_findings_path.is_file():
        _log("no live_probe_plan.json and no validated findings to generate from; skipping")
        return None
    scope = ctx.load_scope()
    if has_plan:
        try:
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            plan = plan.get("plan", plan) if isinstance(plan, dict) else plan
            if not isinstance(plan, list):
                raise ValueError("live probe plan must be a list of {finding_id, requests:[...]}")
        except (OSError, ValueError) as exc:
            _log(f"invalid live probe plan ({exc}); skipping")
            return None
    else:
        # L2: no hand-written plan -> generate one with the LLM (offline, validated by the gates below).
        plan = _generate_plan(ctx, scope)
        if not plan:
            return None

    # ---- HARD GATES (any failure aborts; nothing is sent) -------------------------------------
    assert_live_authorized(scope)                               # RoE authorizes live interaction
    assert_inscope_only(plan, scope)                            # in-scope-only, out-of-scope blocked
    validate_probe_plan(plan, max_requests=cfg.live_max_requests,
                        max_payload_bytes=cfg.live_max_payload_bytes,
                        allow_state_changing=cfg.live_allow_writes)   # read-only + caps
    assert_live_write_policy(plan, allow_writes=cfg.live_allow_writes,
                             max_writes=cfg.live_max_writes)          # L3: DELETE blocked + write cap

    targets = sorted({str(r.get("url") or r.get("path")) for e in plan for r in e.get("requests", [])})
    _log(f"[WARNING] LIVE: probing {len(targets)} in-scope URL(s) "
         f"({'read-only' if not cfg.live_allow_writes else 'WRITES ENABLED'}); every request is audit-logged")
    results, audit = _execute(ctx, plan)

    # L2: LLM interprets the observations into per-finding verdicts (falls back to expect_met).
    verdicts = _interpret(ctx, results)
    if verdicts:
        results["verdicts"] = list(verdicts.values())

    (ctx.run_dir / "live_audit_log.jsonl").write_text(
        "\n".join(json.dumps(a) for a in audit) + ("\n" if audit else ""), encoding="utf-8")
    out = ctx.run_dir / "live_results.json"
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    _attach_to_findings(ctx, results, verdicts)
    confirmed = sum(1 for v in verdicts.values() if v.get("live_verdict") == "live_confirmed") \
        if verdicts else sum(1 for f in results["findings"]
                             for r in f.get("requests", []) if r.get("expect_met"))
    _log(f"{len(audit)} live request(s) made; {confirmed} finding(s) live-confirmed "
         f"-> {out.name} (+ live_audit_log.jsonl)")
    return out
