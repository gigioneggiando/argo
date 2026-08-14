"""Stage ASAN_POC: the zero-cost CWE/extension gate, deterministic sanitizer-output parsing, the
graceful no-Docker skip, best-effort per-finding behavior, and (Docker-gated) a real end-to-end
compile+run+catch of a genuine heap-buffer-overflow."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from argo.rendering import render_prompt_pair
from argo.stages import asan_poc

ASSETS_DIR = Path(__file__).resolve().parent.parent / "argo" / "prompts"


def _finding(fid: str, *, cwe, affected: list[str]) -> dict:
    return {"id": fid, "title": "t", "severity": "High", "confidence": "High", "cwe": cwe,
           "affected": affected, "vulnerable_flow": "", "why_vulnerable": "", "impact": "",
           "exploit_scenario": "", "recommended_fix": ""}


def _write_scope(ctx) -> None:
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    (ctx.run_dir / "scope.json").write_text(json.dumps({
        "program_name": "asan-test", "platform": "local", "target_type": "source_only",
        "in_scope": [{"asset": "x", "type": "source_repo"}], "out_of_scope": [],
        "prohibited_techniques": ["no DoS"], "automation_allowed": True}), encoding="utf-8")


def _write_repo_file(ctx, rel_path: str, content: str) -> None:
    p = ctx.repo_dir / rel_path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _write_validated_findings(ctx, findings: list[dict]) -> None:
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    ctx.validated_findings_path.write_text(
        json.dumps({"findings": findings}, indent=2), encoding="utf-8")


# ------------------------------------------------------------ neutral-register companion prompt
def test_neutral_harness_prompt_companion_exists_and_renders():
    """asan_poc._harness_session uses render_prompt_pair -- confirm the .neutral.md companion is
    actually found and renders cleanly with the same placeholders as the primary template, so a
    moderation-flagged harness-authoring session (confirmed live, see runner._CLAUDE_REFUSAL_SIGNATURE)
    gets a real same-backend retry instead of no recovery at all."""
    mapping = {"FINDING_JSON": "{}", "CODE_EXCERPTS": "(none)", "REPO_PATH": "/repo",
              "PROHIBITED_TECHNIQUES": "- no DoS"}
    prompt, neutral = render_prompt_pair(ASSETS_DIR, "10_asan_harness_prompt.md", mapping)
    assert neutral is not None
    assert "{{" not in neutral  # every placeholder resolved
    assert "harness.c" in neutral and "NOTES.md" in neutral


# --------------------------------------------------------------------------------- _applies gate
def test_applies_requires_memory_safety_cwe_and_c_cpp_file():
    assert asan_poc._applies(_finding("F1", cwe="CWE-787", affected=["src/parser.c:10"]))
    assert asan_poc._applies(_finding("F2", cwe=["CWE-125"], affected=["src/decode.cpp:5"]))


def test_applies_rejects_non_memory_safety_cwe():
    assert not asan_poc._applies(_finding("F3", cwe="CWE-863", affected=["src/auth.c:1"]))


def test_applies_rejects_non_c_cpp_files():
    assert not asan_poc._applies(_finding("F4", cwe="CWE-787", affected=["main.go:1"]))


def test_applies_true_if_any_affected_ref_is_c_cpp():
    f = _finding("F5", cwe="CWE-125", affected=["docs/README.md:1", "src/x.h:9"])
    assert asan_poc._applies(f)


def test_applies_false_on_missing_cwe_or_affected():
    assert not asan_poc._applies({"id": "F6"})
    assert not asan_poc._applies(_finding("F7", cwe=None, affected=["x.c:1"]))


# ------------------------------------------------------------------- deterministic output parsing
def test_parse_confirmed_on_real_asan_error_shape():
    output = (
        "=================================================================\n"
        "==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...\n"
        "WRITE of size 1 at 0x... thread T0\n"
        "    #0 0x... in main harness.c:5:10\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow harness.c:5:10 in main\n"
    )
    out = asan_poc._parse_sanitizer_output(output, exit_code=1)
    assert out["verdict"] == "confirmed"
    assert "heap-buffer-overflow" in out["sanitizer_summary"]
    assert out["reason"] is None


def test_parse_crashed_no_sanitizer_output():
    out = asan_poc._parse_sanitizer_output("Segmentation fault (core dumped)\n", exit_code=139)
    assert out["verdict"] == "crashed_no_sanitizer_output"
    assert "139" in out["sanitizer_summary"]


def test_parse_not_reproduced_on_clean_exit():
    out = asan_poc._parse_sanitizer_output("harness ran fine\n", exit_code=0)
    assert out["verdict"] == "not_reproduced"
    assert out["sanitizer_summary"] is None


# ---------------------------------------------------------------------------------- run() gating
def test_run_off_by_default(env):
    ctx = env()  # asan_poc_enabled defaults False
    assert asan_poc.run(ctx) is None


def test_run_no_validated_findings(env):
    ctx = env(asan_poc_enabled=True)
    assert asan_poc.run(ctx) is None


def test_run_no_eligible_findings(env):
    ctx = env(asan_poc_enabled=True)
    _write_validated_findings(ctx, [_finding("F1", cwe="CWE-863", affected=["auth.go:1"])])
    assert asan_poc.run(ctx) is None


def test_run_skips_gracefully_without_docker(env, monkeypatch):
    ctx = env(asan_poc_enabled=True)
    _write_scope(ctx)
    _write_validated_findings(ctx, [_finding("F1", cwe="CWE-787", affected=["x.c:1"])])
    monkeypatch.setattr(asan_poc, "_docker_ok", lambda: False)

    def _boom(*a, **k):
        raise AssertionError("must not attempt a harness session when Docker is unavailable")
    monkeypatch.setattr(asan_poc, "_run_one", _boom)
    assert asan_poc.run(ctx) is None


def test_run_respects_max_findings_cap(env, monkeypatch):
    ctx = env(asan_poc_enabled=True, asan_poc_max_findings=1)
    _write_scope(ctx)
    _write_validated_findings(ctx, [
        _finding("F1", cwe="CWE-787", affected=["x.c:1"]),
        _finding("F2", cwe="CWE-787", affected=["x.c:1"]),
    ])
    monkeypatch.setattr(asan_poc, "_docker_ok", lambda: True)
    seen = []
    monkeypatch.setattr(asan_poc, "_run_one", lambda ctx, scope, f: seen.append(f["id"]) or None)
    asan_poc.run(ctx)
    assert seen == ["F1"]


# ---------------------------------------------------------------------------- best-effort per-finding
def test_best_effort_one_failure_does_not_abort_others(env, monkeypatch):
    ctx = env(asan_poc_enabled=True)
    _write_scope(ctx)
    _write_repo_file(ctx, "vuln.c", "int f(void){return 0;}\n")
    _write_validated_findings(ctx, [
        _finding("F1", cwe="CWE-787", affected=["vuln.c:1"]),
        _finding("F2", cwe="CWE-787", affected=["vuln.c:1"]),
    ])
    monkeypatch.setattr(asan_poc, "_docker_ok", lambda: True)

    calls = []

    def fake_compile_and_run(cfg, run_id, fid, copy_dir, harness_path):
        calls.append(fid)
        if fid == "F1":
            raise RuntimeError("boom (simulated infra failure)")
        return {"verdict": "confirmed", "sanitizer_summary": "heap-buffer-overflow",
               "crash_trace": "...", "reason": None}

    monkeypatch.setattr(asan_poc, "_compile_and_run", fake_compile_and_run)
    out = asan_poc.run(ctx)
    assert calls == ["F1", "F2"]           # F2 still attempted after F1 raised
    assert out is not None
    doc = json.loads(out.read_text(encoding="utf-8"))
    by_id = {f["id"]: f for f in doc["findings"]}
    assert "asan_poc" not in by_id["F1"].get("validation", {})
    assert by_id["F2"]["validation"]["asan_poc"]["verdict"] == "confirmed"


def test_attach_to_findings_never_refutes_not_reproduced(env, monkeypatch):
    """A clean (non-crashing) harness run must not change the finding's own verdict -- only
    validation.asan_poc gets the new evidence block."""
    ctx = env(asan_poc_enabled=True)
    _write_scope(ctx)
    _write_repo_file(ctx, "vuln.c", "int f(void){return 0;}\n")
    _write_validated_findings(ctx, [_finding("F1", cwe="CWE-787", affected=["vuln.c:1"])])
    ctx.validated_findings_path.write_text(json.dumps({"findings": [
        {**_finding("F1", cwe="CWE-787", affected=["vuln.c:1"]),
         "validation": {"verdict": "confirmed"}}]}), encoding="utf-8")
    monkeypatch.setattr(asan_poc, "_docker_ok", lambda: True)
    monkeypatch.setattr(asan_poc, "_compile_and_run", lambda *a, **k: {
        "verdict": "not_reproduced", "sanitizer_summary": None, "crash_trace": None, "reason": None})
    out = asan_poc.run(ctx)
    doc = json.loads(out.read_text(encoding="utf-8"))
    f = doc["findings"][0]
    assert f["validation"]["verdict"] == "confirmed"          # untouched
    assert f["validation"]["asan_poc"]["verdict"] == "not_reproduced"


# ----------------------------------------------------------------- end-to-end (Docker-gated)
def _docker_ready() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except Exception:
        return False


@pytest.mark.skipif(not _docker_ready(), reason="Docker not available")
def test_asan_poc_end_to_end_catches_a_real_heap_overflow(env):
    """The mock LLM session emits tests/fixtures/happy/asan_poc/F1.c (a real, textbook
    heap-buffer-overflow one-liner) as harness.c; the REAL compile+run+parse cycle must catch it
    via genuine clang + ASan inside the sandboxed container -- proving the deterministic pipeline
    end-to-end, not just the mock glue."""
    ctx = env(asan_poc_enabled=True)
    _write_scope(ctx)
    # affected must be a .c/.h file for _applies() to gate this finding in at all -- the mock
    # handler ignores repo content anyway (it always emits the F1.c fixture), so this file's
    # CONTENT is irrelevant, only its extension matters here.
    _write_repo_file(ctx, "vuln.c", "int f(void){return 0;}\n")
    _write_validated_findings(ctx, [_finding("F1", cwe="CWE-787", affected=["vuln.c:1"])])
    out = asan_poc.run(ctx)
    if out is None:
        pytest.skip("image pull unavailable in this environment")
    doc = json.loads(out.read_text(encoding="utf-8"))
    verdict = doc["findings"][0]["validation"]["asan_poc"]
    if verdict["verdict"] == "not_attempted":
        pytest.fail(f"harness did not compile/run for a REAL reason, not just an unavailable "
                   f"environment (Docker is confirmed present when this test runs at all): "
                   f"{verdict['reason']}")
    assert verdict["verdict"] == "confirmed"
    assert "heap-buffer-overflow" in verdict["sanitizer_summary"]
