"""Runtime recipe containment, probe-host parsing, and fallback scratch-dir isolation."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from argo.config import PipelineConfig
from argo.guardrails import RuntimeProbeError, assert_loopback_only
from argo.ledger import Ledger
from argo.runner import ClaudeRunner, FallbackRunner, RunnerError
from argo.stages import runtime as rt

_SCOPE = SimpleNamespace(in_scope=[SimpleNamespace(asset="api.acme.com")], out_of_scope=[])


@pytest.mark.parametrize("recipe", [
    {"dockerfile": "../outside/Dockerfile"},
    {"dockerfile": "Dockerfile", "build_context": ".."},
    {"dockerfile": "Dockerfile", "build_context": "../../etc"},
])
def test_runtime_recipe_paths_stay_inside_recipe_dir(tmp_path, monkeypatch, recipe):
    base = tmp_path / "repo"
    base.mkdir()
    (base / "Dockerfile").write_text("FROM scratch\n")
    monkeypatch.setattr(rt, "_build_image", lambda *a, **k: pytest.fail("build must not run"))
    ctx = SimpleNamespace(config=PipelineConfig())
    assert rt._launcher_from_recipe(recipe, ctx, base) is None


@pytest.mark.parametrize("path", ["HTTP://evil.com/x", "Https://evil.com/", "http:/evil.com/x",
                                  "http:evil.com", "//evil.com/x"])
def test_probe_host_rejects_any_external_or_hostless_url(path):
    plan = [{"finding_id": "F1", "requests": [{"method": "GET", "path": path}]}]
    with pytest.raises(RuntimeProbeError):
        assert_loopback_only(plan, _SCOPE)


def test_probe_host_accepts_uppercase_loopback_url():
    plan = [{"finding_id": "F1", "requests": [{"method": "GET", "path": "HTTP://127.0.0.1:8080/x"}]}]
    assert_loopback_only(plan, _SCOPE)


class _Writes(ClaudeRunner):
    """Writes a findings file named after itself, then fails or succeeds."""

    def __init__(self, cfg, led, name, fail):
        super().__init__(cfg, led)
        self.name, self.fail = name, fail

    def _invoke(self, *, work_dir, **kw):
        (work_dir / f"SECURITY_FINDINGS__{self.name}.json").write_text("{}")
        if self.fail:
            raise RunnerError("blip", retryable=True, failure_kind="rate_limited")
        return {"is_error": False, "result": "ok", "usage": {}, "total_cost_usd": 0.0,
                "num_turns": 1, "session_id": "s", "subtype": "success"}


def test_fallback_does_not_mix_failed_attempt_artifacts(tmp_path):
    led = Ledger(tmp_path / "l.sqlite")
    cfg = PipelineConfig()
    fb = FallbackRunner(cfg, led, [_Writes(cfg, led, "first", True), _Writes(cfg, led, "second", False)])
    work = tmp_path / "run" / "audit" / "focus"
    fb.run(prompt="p", run_dir=tmp_path / "run", work_dir=work, model="m", stage="audit",
           run_id="R", label="focus")
    assert sorted(p.name for p in work.iterdir()) == ["SECURITY_FINDINGS__second.json"]
    aside = work.with_name("focus.failed-1")
    assert (aside / "SECURITY_FINDINGS__first.json").is_file()   # kept for diagnosis
    led.close()
