"""L1 live-testing safety core: RoE authorization gate + in-scope-only scope-lock + stage gating.
The gate tests touch no network; the one executor test runs a loopback server that the test scope
explicitly declares in-scope (so the scope-lock authorizes it) to prove caps + audit log work."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import pytest

from argo.guardrails import (assert_inscope_only, assert_live_authorized, assert_live_write_policy,
                             LiveNotAuthorizedError, LiveScopeError, LiveWriteError, RuntimeProbeError)
from argo.stages import live


def _scope(in_scope=(("api.acme.com", "api"),), oos=("legacy.acme.com",),
           automation_allowed=True, safe_harbor=True, prohibited=("no DoS",)):
    return SimpleNamespace(
        in_scope=[SimpleNamespace(asset=a, type=t) for a, t in in_scope],
        out_of_scope=list(oos),
        automation_allowed=automation_allowed,
        safe_harbor=safe_harbor,
        prohibited_techniques=list(prohibited))


# ------------------------------------------------------------ RoE authorization gate
def test_authorized_when_roe_permit():
    assert_live_authorized(_scope())                              # no raise


def test_refused_when_automation_not_allowed():
    for val in (False, None):
        with pytest.raises(LiveNotAuthorizedError):
            assert_live_authorized(_scope(automation_allowed=val))


def test_refused_when_safe_harbor_explicitly_false():
    with pytest.raises(LiveNotAuthorizedError):
        assert_live_authorized(_scope(safe_harbor=False))


def test_refused_when_no_prohibited_techniques():
    with pytest.raises(LiveNotAuthorizedError):
        assert_live_authorized(_scope(prohibited=()))


# ------------------------------------------------------------ in-scope-only scope-lock
def test_inscope_absolute_url_ok():
    plan = [{"finding_id": "F1", "requests": [
        {"method": "GET", "url": "https://api.acme.com/v1/users"}]}]
    assert_inscope_only(plan, _scope())                           # no raise


def test_inscope_wildcard_subdomain_ok():
    plan = [{"finding_id": "F1", "requests": [
        {"method": "GET", "url": "https://app.acme.com/health"}]}]
    assert_inscope_only(plan, _scope(in_scope=(("*.acme.com", "web"),)))


def test_inscope_wildcard_does_not_overmatch():
    plan = [{"finding_id": "F1", "requests": [
        {"method": "GET", "url": "https://acme.com.evil.net/x"}]}]
    with pytest.raises(LiveScopeError):
        assert_inscope_only(plan, _scope(in_scope=(("*.acme.com", "web"),)))


def test_rejects_unknown_host():
    plan = [{"finding_id": "F1", "requests": [{"method": "GET", "url": "https://evil.com/x"}]}]
    with pytest.raises(LiveScopeError):
        assert_inscope_only(plan, _scope())


def test_rejects_out_of_scope_host():
    plan = [{"finding_id": "F1", "requests": [
        {"method": "GET", "url": "https://legacy.acme.com/x"}]}]
    with pytest.raises(LiveScopeError):
        assert_inscope_only(plan, _scope(in_scope=(("*.acme.com", "web"),)))


def test_rejects_relative_path_no_host():
    plan = [{"finding_id": "F1", "requests": [{"method": "GET", "path": "/v1/users"}]}]
    with pytest.raises(LiveScopeError):
        assert_inscope_only(plan, _scope())


def test_rejects_loopback_for_live():
    plan = [{"finding_id": "F1", "requests": [{"method": "GET", "url": "http://127.0.0.1/x"}]}]
    with pytest.raises(LiveScopeError):
        assert_inscope_only(plan, _scope())


def test_no_inscope_hosts_refuses():
    plan = [{"finding_id": "F1", "requests": [{"method": "GET", "url": "https://api.acme.com/x"}]}]
    with pytest.raises(LiveScopeError):
        assert_inscope_only(plan, _scope(in_scope=(("repo.git", "source_repo"),)))


# ------------------------------------------------------------ stage gating (no network)
def test_live_off_by_default_returns_none(env):
    ctx = env()                                                   # live_enabled defaults False
    assert live.run(ctx) is None


def test_live_enabled_without_plan_returns_none(env):
    ctx = env(live_enabled=True)
    assert live.run(ctx) is None                                 # no live_probe_plan.json -> skip


# ------------------------------------------------------------ executor (loopback server, in-scope)
class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect-out":                # 302 off-host (out of scope)
            self.send_response(302)
            self.send_header("Location", "https://evil.com/x")
            self.end_headers()
            return
        if self.path == "/redirect-in":                 # 302 to an in-scope path
            self.send_response(302)
            self.send_header("Location", "/landing")
            self.end_headers()
            return
        if self.path == "/denied":                      # a control baseline that should be forbidden
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"forbidden")
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"hello-from-live")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"created")

    def log_message(self, *a):
        pass


@pytest.fixture
def loopback_server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()          # release the socket immediately
        t.join(timeout=2)           # don't leave a worker thread lingering into later tests


def _write_scope(ctx, host):
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    ctx.scope_path.write_text(json.dumps({
        "program_name": "test", "platform": "test", "target_type": "source_and_live",
        "in_scope": [{"asset": host, "type": "web"}],
        "out_of_scope": [], "prohibited_techniques": ["no DoS"],
        "safe_harbor": True, "automation_allowed": True}), encoding="utf-8")


def test_executor_makes_requests_and_audits(env, loopback_server):
    ctx = env(live_enabled=True, live_min_request_interval_s=0.0)
    _write_scope(ctx, loopback_server)
    (ctx.run_dir / "live_probe_plan.json").write_text(json.dumps([
        {"finding_id": "F1", "requests": [
            {"method": "GET", "url": f"http://{loopback_server}/a",
             "expect": {"status": 200, "body_contains": ["hello-from-live"]}},
            {"method": "GET", "url": f"http://{loopback_server}/b", "expect": {"status": 404}}]}]),
        encoding="utf-8")

    out = live.run(ctx)
    assert out is not None
    results = json.loads(out.read_text(encoding="utf-8"))
    reqs = results["findings"][0]["requests"]
    assert reqs[0]["status"] == 200 and reqs[0]["expect_met"] is True
    assert reqs[1]["status"] == 200 and reqs[1]["expect_met"] is False   # expected 404, got 200
    audit = (ctx.run_dir / "live_audit_log.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(audit) == 2 and all(json.loads(a)["status"] == 200 for a in audit)


def test_oversized_plan_rejected_before_any_request(env, loopback_server):
    ctx = env(live_enabled=True, live_min_request_interval_s=0.0, live_max_requests=2)
    _write_scope(ctx, loopback_server)
    (ctx.run_dir / "live_probe_plan.json").write_text(json.dumps([
        {"finding_id": "F1", "requests": [
            {"method": "GET", "url": f"http://{loopback_server}/{i}"} for i in range(5)]}]),
        encoding="utf-8")

    with pytest.raises(RuntimeProbeError):                       # anti-DoS: reject whole plan, fail loud
        live.run(ctx)
    assert not (ctx.run_dir / "live_audit_log.jsonl").exists()   # nothing was sent


# ------------------------------------------------------------ L2: LLM propose / interpret (offline)
_ONE_FINDING = {"findings": [{
    "id": "MOCK-1", "title": "anon admin endpoint", "severity": "High", "affected": ["a.cs:1"],
    "vulnerable_flow": "x", "why_vulnerable": "y", "exploit_scenario": "z"}]}


def test_l2_generate_plan_uses_inscope_host(env):
    ctx = env()                                                 # mock runner
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    ctx.validated_findings_path.write_text(json.dumps(_ONE_FINDING), encoding="utf-8")
    scope = SimpleNamespace(program_name="t", prohibited_techniques=["no DoS"],
                            in_scope=[SimpleNamespace(asset="api.acme.com", type="api")],
                            out_of_scope=[])
    plan = live._generate_plan(ctx, scope)
    assert plan and plan[0]["finding_id"] == "MOCK-1"
    assert plan[0]["requests"][0]["url"].startswith("https://api.acme.com/")
    # the generated plan must survive the in-scope scope-lock
    from argo.guardrails import assert_inscope_only
    assert_inscope_only(plan, _scope(in_scope=(("api.acme.com", "api"),)))
    assert (ctx.run_dir / "live_probe_plan.json").is_file()


def test_l2_generate_plan_no_inscope_host_skips(env):
    ctx = env()
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    ctx.validated_findings_path.write_text(json.dumps(_ONE_FINDING), encoding="utf-8")
    scope = SimpleNamespace(program_name="t", prohibited_techniques=["no DoS"],
                            in_scope=[SimpleNamespace(asset="repo.git", type="source_repo")],
                            out_of_scope=[])
    assert live._generate_plan(ctx, scope) is None             # no web/api host -> nothing to probe


def test_l2_interpret(env):
    ctx = env()
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    results = {"findings": [{"finding_id": "MOCK-1", "requests": [
        {"method": "GET", "url": "https://api.acme.com/x", "status": 200,
         "body_snippet": "secret", "expect_met": True}]}]}
    verdicts = live._interpret(ctx, results)
    assert verdicts.get("MOCK-1", {}).get("live_verdict") == "live_confirmed"


def test_l2_run_end_to_end_generates_executes_attaches(env, loopback_server):
    """No hand-written plan: run() LLM-generates an in-scope plan, the gates pass, the fixed executor
    hits the in-scope loopback server, interpret judges it, and the verdict is attached to the finding."""
    ctx = env(live_enabled=True, live_min_request_interval_s=0.0)
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    ctx.scope_path.write_text(json.dumps({
        "program_name": "t", "platform": "t", "target_type": "source_and_live",
        "in_scope": [{"asset": f"http://{loopback_server}", "type": "web"}],
        "out_of_scope": [], "prohibited_techniques": ["no DoS"],
        "safe_harbor": True, "automation_allowed": True}), encoding="utf-8")
    ctx.validated_findings_path.write_text(json.dumps(_ONE_FINDING), encoding="utf-8")

    out = live.run(ctx)                                         # no plan file -> L2 generates one
    assert out is not None
    results = json.loads(out.read_text(encoding="utf-8"))
    assert results["findings"][0]["requests"][0]["status"] == 200
    doc = json.loads(ctx.validated_findings_path.read_text(encoding="utf-8"))
    assert doc["findings"][0]["validation"]["live"]["verdict"] == "live_confirmed"
    assert (ctx.run_dir / "live_audit_log.jsonl").is_file()


def test_executor_blocked_when_out_of_scope(env, loopback_server):
    ctx = env(live_enabled=True, live_min_request_interval_s=0.0)
    _write_scope(ctx, loopback_server)                           # only loopback_server is in-scope
    (ctx.run_dir / "live_probe_plan.json").write_text(json.dumps([
        {"finding_id": "F1", "requests": [{"method": "GET", "url": "https://evil.com/x"}]}]),
        encoding="utf-8")

    with pytest.raises(LiveScopeError):                          # scope-lock aborts before any request
        live.run(ctx)
    assert not (ctx.run_dir / "live_audit_log.jsonl").exists()   # nothing was sent


# ------------------------------------------------------------ L3: state-changing write policy
def _post(url, n=1):
    return [{"finding_id": "F1", "requests": [
        {"method": "POST", "url": url, "body": "{\"k\":\"v\"}"} for _ in range(n)]}]


def test_l3_delete_never_allowed_even_with_writes():
    plan = [{"finding_id": "F1", "requests": [{"method": "DELETE", "url": "https://api.acme.com/x"}]}]
    with pytest.raises(LiveWriteError):
        assert_live_write_policy(plan, allow_writes=True, max_writes=5)


def test_l3_writes_blocked_without_optin():
    with pytest.raises(LiveWriteError):
        assert_live_write_policy(_post("https://api.acme.com/x"), allow_writes=False, max_writes=5)


def test_l3_writes_within_cap_ok():
    assert_live_write_policy(_post("https://api.acme.com/x", n=3), allow_writes=True, max_writes=5)


def test_l3_write_cap_enforced():
    with pytest.raises(LiveWriteError):
        assert_live_write_policy(_post("https://api.acme.com/x", n=6), allow_writes=True, max_writes=5)


def test_l3_audit_records_body_for_writes(env, loopback_server):
    ctx = env(live_enabled=True, live_min_request_interval_s=0.0, live_allow_writes=True)
    _write_scope(ctx, loopback_server)
    (ctx.run_dir / "live_probe_plan.json").write_text(json.dumps([
        {"finding_id": "F1", "requests": [
            {"method": "POST", "url": f"http://{loopback_server}/x", "body": "{\"k\":\"v\"}",
             "expect": {"status": 200, "body_contains": ["created"]}}]}]), encoding="utf-8")

    out = live.run(ctx)
    assert out is not None
    results = json.loads(out.read_text(encoding="utf-8"))
    assert results["findings"][0]["requests"][0]["expect_met"] is True
    audit = json.loads((ctx.run_dir / "live_audit_log.jsonl").read_text(encoding="utf-8").strip())
    assert audit["method"] == "POST" and audit["body"] == "{\"k\":\"v\"}"   # mutation fully recorded


# ------------------------------------------------------------ robustness: redirects + differential
def _run_one(ctx, loopback_server, request):
    _write_scope(ctx, loopback_server)
    (ctx.run_dir / "live_probe_plan.json").write_text(json.dumps([
        {"finding_id": "F1", "requests": [request]}]), encoding="utf-8")
    out = live.run(ctx)
    return json.loads(out.read_text(encoding="utf-8"))["findings"][0]["requests"][0]


def test_redirect_out_of_scope_not_followed(env, loopback_server):
    ctx = env(live_enabled=True, live_min_request_interval_s=0.0)
    rec = _run_one(ctx, loopback_server, {"method": "GET", "url": f"http://{loopback_server}/redirect-out"})
    assert rec["status"] == 302                                  # we stopped at the redirect
    assert rec["redirect_out_of_scope"].startswith("https://evil.com")
    assert rec["redirect_chain"][0]["followed"] is False and rec["redirect_chain"][0]["reason"] == "out_of_scope"


def test_redirect_in_scope_followed(env, loopback_server):
    ctx = env(live_enabled=True, live_min_request_interval_s=0.0)
    rec = _run_one(ctx, loopback_server, {"method": "GET", "url": f"http://{loopback_server}/redirect-in"})
    assert rec["status"] == 200 and "hello-from-live" in rec["body_snippet"]   # followed in-scope hop
    assert any(h["followed"] for h in rec["redirect_chain"])


def test_user_agent_and_evidence_headers_captured(env, loopback_server):
    ctx = env(live_enabled=True, live_min_request_interval_s=0.0)
    rec = _run_one(ctx, loopback_server, {"method": "GET", "url": f"http://{loopback_server}/",
                                          "expect": {"status": 200}})
    assert "response_headers" in rec                             # evidence headers attached
    assert ctx.config.live_user_agent.startswith("Argo-live")


def test_differential_control_attached(env, loopback_server):
    ctx = env(live_enabled=True, live_min_request_interval_s=0.0)
    rec = _run_one(ctx, loopback_server, {
        "method": "GET", "url": f"http://{loopback_server}/admin", "expect": {"status": 200},
        "control": {"method": "GET", "url": f"http://{loopback_server}/denied",
                    "expect": {"status": [403]}}})
    assert rec["status"] == 200                                  # the (mock) probe
    assert rec["control"]["status"] == 403                       # the baseline differs -> a real signal
    # both requests are audit-logged; the control entry is tagged
    audit = [json.loads(x) for x in
             (ctx.run_dir / "live_audit_log.jsonl").read_text(encoding="utf-8").strip().splitlines()]
    assert len(audit) == 2 and any(a.get("role") == "control" for a in audit)


def test_control_request_is_scope_locked(env, loopback_server):
    ctx = env(live_enabled=True, live_min_request_interval_s=0.0)
    _write_scope(ctx, loopback_server)
    (ctx.run_dir / "live_probe_plan.json").write_text(json.dumps([
        {"finding_id": "F1", "requests": [
            {"method": "GET", "url": f"http://{loopback_server}/x",
             "control": {"method": "GET", "url": "https://evil.com/baseline"}}]}]), encoding="utf-8")
    with pytest.raises(LiveScopeError):                          # the nested control is gated too
        live.run(ctx)
    assert not (ctx.run_dir / "live_audit_log.jsonl").exists()


def test_l3_delete_in_run_aborts_before_sending(env, loopback_server):
    ctx = env(live_enabled=True, live_min_request_interval_s=0.0, live_allow_writes=True)
    _write_scope(ctx, loopback_server)
    (ctx.run_dir / "live_probe_plan.json").write_text(json.dumps([
        {"finding_id": "F1", "requests": [{"method": "DELETE", "url": f"http://{loopback_server}/x"}]}]),
        encoding="utf-8")

    with pytest.raises(LiveWriteError):
        live.run(ctx)
    assert not (ctx.run_dir / "live_audit_log.jsonl").exists()
