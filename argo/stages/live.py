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

from ..context import RunContext
from ..guardrails import assert_inscope_only, assert_live_authorized, validate_probe_plan


def _log(msg: str) -> None:
    print(f"[live] {msg}", file=sys.stderr)


def _send(opener, req: dict, cfg) -> tuple[dict, dict]:
    url = str(req.get("url") or req.get("path"))
    method = str(req.get("method", "GET")).upper()
    data = req.get("body")
    body = data.encode("utf-8") if isinstance(data, str) else None
    r = urllib.request.Request(url, data=body, method=method, headers=req.get("headers") or {})
    rec = {"method": method, "url": url, "expect": req.get("expect")}
    # Audit entry: minimal + accountable (method/url/status/size) — no headers/body so secrets aren't logged.
    audit = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "method": method, "url": url}
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


def run(ctx: RunContext):
    cfg = ctx.config
    if not cfg.live_enabled:
        return None
    plan_path = ctx.run_dir / "live_probe_plan.json"
    if not plan_path.is_file():
        _log("no live_probe_plan.json (L1 expects a hand-written plan); skipping")
        return None
    scope = ctx.load_scope()
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        plan = plan.get("plan", plan) if isinstance(plan, dict) else plan
        if not isinstance(plan, list):
            raise ValueError("live probe plan must be a list of {finding_id, requests:[...]}")
    except (OSError, ValueError) as exc:
        _log(f"invalid live probe plan ({exc}); skipping")
        return None

    # ---- HARD GATES (any failure aborts; nothing is sent) -------------------------------------
    assert_live_authorized(scope)                               # RoE authorizes live interaction
    assert_inscope_only(plan, scope)                            # in-scope-only, out-of-scope blocked
    validate_probe_plan(plan, max_requests=cfg.live_max_requests,
                        max_payload_bytes=cfg.live_max_payload_bytes,
                        allow_state_changing=cfg.live_allow_writes)   # read-only + caps

    targets = sorted({str(r.get("url") or r.get("path")) for e in plan for r in e.get("requests", [])})
    _log(f"[WARNING] LIVE: probing {len(targets)} in-scope URL(s) "
         f"({'read-only' if not cfg.live_allow_writes else 'WRITES ENABLED'}); every request is audit-logged")
    results, audit = _execute(ctx, plan)

    (ctx.run_dir / "live_audit_log.jsonl").write_text(
        "\n".join(json.dumps(a) for a in audit) + ("\n" if audit else ""), encoding="utf-8")
    out = ctx.run_dir / "live_results.json"
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    met = sum(1 for f in results["findings"] for r in f.get("requests", []) if r.get("expect_met"))
    _log(f"{len(audit)} live request(s) made; {met} met expectation -> {out.name} (+ live_audit_log.jsonl)")
    return out
