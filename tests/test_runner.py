"""The runner is the tool-guardrail chokepoint: even if a stage asks for network/mutation
tools, run() must strip them before any session launches, and the headless command must
hard-disallow them."""

from pathlib import Path

from argo.config import PipelineConfig, NETWORK_TOOLS, MUTATION_TOOLS
from argo.ledger import Ledger
from argo.runner import ClaudeRunner, HeadlessClaudeRunner


class _CaptureRunner(ClaudeRunner):
    captured = None

    def _invoke(self, *, prompt, work_dir, model, repo_dir, allowed, disallowed, policy=None,
                stage, run_id, label, session_budget_usd=None, timeout_s=None):
        self.captured = {"allowed": allowed, "disallowed": disallowed, "policy": policy,
                         "session_budget_usd": session_budget_usd, "timeout_s": timeout_s}
        return {"is_error": False, "result": "ok",
                "usage": {"input_tokens": 1, "output_tokens": 2},
                "total_cost_usd": 0.0, "num_turns": 1, "session_id": "x", "subtype": "success"}


def test_run_strips_network_and_mutation_tools(tmp_path):
    ledger = Ledger(tmp_path / "l.sqlite")
    runner = _CaptureRunner(PipelineConfig(), ledger)
    runner.run(
        prompt="p", run_dir=tmp_path / "run", work_dir=tmp_path / "run" / "w",
        model="m", stage="audit", run_id="R1",
        allowed_tools=("Read", "Grep", "Glob", "Write", "Bash", "WebFetch", "Edit"),
    )
    allowed = set(runner.captured["allowed"])
    assert allowed == {"Read", "Grep", "Glob", "Write"}
    assert not (allowed & (NETWORK_TOOLS | MUTATION_TOOLS))
    for t in NETWORK_TOOLS | MUTATION_TOOLS:
        assert t in runner.captured["disallowed"]
    # the call was logged (cost control)
    assert ledger.run_call_count("R1") == 1
    ledger.close()


def test_headless_cmd_is_readonly_sandboxed(tmp_path):
    ledger = Ledger(tmp_path / "l.sqlite")
    runner = HeadlessClaudeRunner(PipelineConfig(), ledger)
    cmd = runner._build_cmd(
        model="claude-opus-4-8", repo_dir=Path("repo"),
        allowed=["Read", "Grep", "Glob", "Write"],
        disallowed=sorted(NETWORK_TOOLS | MUTATION_TOOLS),
    )
    assert "--add-dir" in cmd
    assert "--permission-mode" in cmd and "bypassPermissions" in cmd
    assert "--disallowedTools" in cmd
    # no network tool ever appears in the allowed segment
    a = cmd.index("--allowedTools")
    d = cmd.index("--disallowedTools")
    allowed_segment = cmd[a + 1:d]
    assert not (set(allowed_segment) & NETWORK_TOOLS)
    assert "Bash" in cmd and "WebFetch" in cmd  # present only in the disallow segment
    ledger.close()
