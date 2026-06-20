"""R1 runtime verification: the safety validators (loopback-only + anti-DoS caps), the stage's
graceful-skip gating, and an optional Docker-gated end-to-end sealed-sandbox proof."""

import json
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from argo.guardrails import (assert_loopback_only, validate_probe_plan, RuntimeProbeError)
from argo.stages import runtime as rt


def _scope(in_scope=("api.acme.com",), oos=("legacy.acme.com",)):
    return SimpleNamespace(
        in_scope=[SimpleNamespace(asset=a) for a in in_scope],
        out_of_scope=list(oos))


# ----------------------------------------------------------------- loopback-only gate
def test_loopback_relative_paths_ok():
    plan = [{"finding_id": "F1", "requests": [
        {"method": "GET", "path": "/umbraco/backofficeHub/negotiate"},
        {"method": "GET", "path": "/server/status", "headers": {"Host": "localhost"}}]}]
    assert_loopback_only(plan, _scope())            # no raise


def test_loopback_explicit_localhost_url_ok():
    plan = [{"finding_id": "F1", "requests": [{"method": "GET", "path": "http://127.0.0.1:8080/x"}]}]
    assert_loopback_only(plan, _scope())


def test_loopback_rejects_external_url():
    plan = [{"finding_id": "F1", "requests": [{"method": "GET", "path": "http://evil.com/x"}]}]
    with pytest.raises(RuntimeProbeError):
        assert_loopback_only(plan, _scope())


def test_loopback_rejects_scope_host_reference():
    plan = [{"finding_id": "F1", "requests": [
        {"method": "GET", "path": "/x", "headers": {"Host": "api.acme.com"}}]}]
    with pytest.raises(RuntimeProbeError):
        assert_loopback_only(plan, _scope())


def test_loopback_rejects_protocol_relative_external():
    plan = [{"finding_id": "F1", "requests": [{"method": "GET", "path": "//evil.com/x"}]}]
    with pytest.raises(RuntimeProbeError):
        assert_loopback_only(plan, _scope())


# ----------------------------------------------------------------- anti-DoS / method caps
def test_plan_rejects_too_many_requests():
    plan = [{"finding_id": "F", "requests": [{"method": "GET", "path": "/"} for _ in range(60)]}]
    with pytest.raises(RuntimeProbeError):
        validate_probe_plan(plan, max_requests=50, max_payload_bytes=8192, allow_state_changing=False)


def test_plan_rejects_state_changing_when_readonly():
    plan = [{"finding_id": "F", "requests": [{"method": "POST", "path": "/x"}]}]
    with pytest.raises(RuntimeProbeError):
        validate_probe_plan(plan, max_requests=50, max_payload_bytes=8192, allow_state_changing=False)


def test_plan_allows_state_changing_when_opted_in():
    plan = [{"finding_id": "F", "requests": [{"method": "POST", "path": "/x", "body": "{}"}]}]
    validate_probe_plan(plan, max_requests=50, max_payload_bytes=8192, allow_state_changing=True)


def test_plan_rejects_oversized_body():
    plan = [{"finding_id": "F", "requests": [{"method": "GET", "path": "/", "body": "x" * 9000}]}]
    with pytest.raises(RuntimeProbeError):
        validate_probe_plan(plan, max_requests=50, max_payload_bytes=8192, allow_state_changing=False)


# ----------------------------------------------------------------- stage gating (Docker-free)
def test_runtime_off_by_default_returns_none(env):
    ctx = env()                                     # runtime_enabled defaults False
    assert rt.run(ctx) is None


def test_runtime_enabled_no_plan_no_findings_skips(env):
    ctx = env(runtime_enabled=True)
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    (ctx.run_dir / "scope.json").write_text(json.dumps({
        "program_name": "rt", "platform": "local", "target_type": "source_only",
        "in_scope": [{"asset": "x", "type": "source_repo"}], "out_of_scope": [],
        "prohibited_techniques": ["no DoS"], "automation_allowed": True}), encoding="utf-8")
    # no hand-written plan AND no validated findings -> nothing to probe -> graceful skip
    assert rt.run(ctx) is None


# ----------------------------------------------------------------- R2: LLM propose / interpret
_VALID_SCOPE = {
    "program_name": "rt", "platform": "local", "target_type": "source_only",
    "in_scope": [{"asset": "x", "type": "source_repo"}], "out_of_scope": [],
    "prohibited_techniques": ["no DoS"], "automation_allowed": True}

_ONE_FINDING = {"findings": [{
    "id": "MOCK-1", "title": "anon endpoint", "severity": "Medium", "affected": ["a.cs:1"],
    "vulnerable_flow": "x", "why_vulnerable": "y", "exploit_scenario": "z"}]}


def test_r2_generate_plan(env):
    ctx = env()
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    ctx.validated_findings_path.write_text(json.dumps(_ONE_FINDING), encoding="utf-8")
    scope = SimpleNamespace(program_name="rt", prohibited_techniques=["no DoS"],
                            in_scope=[], out_of_scope=[])
    plan = rt._generate_plan(ctx, scope)
    assert plan and plan[0]["finding_id"] == "MOCK-1"
    assert (ctx.run_dir / "runtime_probe_plan.json").is_file()


def test_r2_interpret(env):
    ctx = env()
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    results = {"booted": True, "findings": [{"finding_id": "MOCK-1", "requests": [
        {"method": "GET", "path": "/status", "status": 200, "body_snippet": "ok", "expect_met": True}]}]}
    verdicts = rt._interpret(ctx, results)
    assert verdicts.get("MOCK-1", {}).get("runtime_verdict") == "runtime_confirmed"


def test_r2_run_generates_plan_then_skips_without_recipe(env):
    """With no hand-written plan, run() LLM-generates one, validates it, then gracefully skips when
    there's no launcher recipe — and the generated plan persists."""
    ctx = env(runtime_enabled=True)
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    (ctx.run_dir / "scope.json").write_text(json.dumps(_VALID_SCOPE), encoding="utf-8")
    ctx.validated_findings_path.write_text(json.dumps(_ONE_FINDING), encoding="utf-8")
    assert rt.run(ctx) is None                      # no runtime_image -> graceful skip
    assert (ctx.run_dir / "runtime_probe_plan.json").is_file()   # but the LLM plan was generated


# ----------------------------------------------------------------- end-to-end (Docker-gated)
def _docker_ready():
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except Exception:
        return False


@pytest.mark.skipif(not _docker_ready(), reason="Docker not available")
def test_sealed_sandbox_end_to_end(env, tmp_path):
    """Build+run a trivial app in a sealed (--network=none) container and probe its loopback —
    proving the safety harness end-to-end. Uses python:3-alpine as both app and probe image."""
    ctx = env(runtime_enabled=True)
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    # minimal scope.json so load_scope passes
    (ctx.run_dir / "scope.json").write_text(json.dumps({
        "program_name": "rt", "platform": "local", "target_type": "source_only",
        "in_scope": [{"asset": "x", "type": "source_repo"}], "out_of_scope": [],
        "prohibited_techniques": ["no DoS"], "automation_allowed": True}), encoding="utf-8")
    ctx.repo_dir.mkdir(parents=True, exist_ok=True)
    (ctx.repo_dir / "README.md").write_text("hi", encoding="utf-8")
    (ctx.run_dir / "runtime_probe_plan.json").write_text(json.dumps([
        {"finding_id": "F1", "requests": [
            {"method": "GET", "path": "/README.md", "expect": {"status": [200], "body_contains": ["hi"]}}]}]),
        encoding="utf-8")
    ctx.config = ctx.config.with_overrides(
        runtime_image="python:3-alpine",
        runtime_run_cmd="python -m http.server 8080 --bind 127.0.0.1",
        runtime_port=8080, runtime_boot_timeout_s=60)
    out = rt.run(ctx)
    if out is None:
        pytest.skip("image pull/build unavailable in this environment")
    res = json.loads(out.read_text(encoding="utf-8"))
    assert res["booted"] is True
    met = [r for f in res["findings"] for r in f["requests"] if r.get("expect_met")]
    assert met, f"no probe met expectation: {res}"
