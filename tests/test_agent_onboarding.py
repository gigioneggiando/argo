"""Keep the agent entry points and their executable onboarding examples usable offline."""

import hashlib
import json
import re
import shlex
import shutil
import socket
import tomllib
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from argo import cli
from argo.runner import AgentRunner, CodexRunner, GeminiRunner, HeadlessClaudeRunner
from conftest import _force_rmtree

ROOT = Path(__file__).resolve().parents[1]
ENTRY_POINTS = (
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    ".github/copilot-instructions.md",
    "docs/agent-guide.md",
)


def test_install_metadata_uses_consistent_spdx_licensing():
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["license"] == "Apache-2.0"
    assert not any(value.startswith("License ::")
                   for value in metadata["project"]["classifiers"])
    assert "setuptools>=77" in metadata["build-system"]["requires"]


def test_agent_entry_points_have_resolvable_local_links():
    for name in ENTRY_POINTS:
        path = ROOT / name
        assert path.is_file(), f"Missing agent entry point: {name}"
        text = path.read_text(encoding="utf-8")
        assert text.strip(), f"Empty agent entry point: {name}"
        for target in re.findall(r"\[[^\]]+\]\(([^\s)]+)\)", text):
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc:
                continue
            resolved = (path.parent / unquote(parsed.path)).resolve() if parsed.path else path
            assert resolved.is_relative_to(ROOT), f"Link escapes repository: {name}: {target}"
            assert resolved.exists(), f"Broken local link: {name}: {target}"
            if parsed.fragment and resolved.suffix == ".md":
                headings = re.findall(r"^#{1,6} (.+)$", resolved.read_text(encoding="utf-8"), re.MULTILINE)
                anchors = {re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
                           for heading in headings}
                assert unquote(parsed.fragment) in anchors, f"Broken heading: {name}: {target}"

    for name in ("CLAUDE.md", "GEMINI.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert re.search(r"^@(?:\./)?AGENTS\.md$", text, re.MULTILINE), name
    copilot = (ROOT / ".github/copilot-instructions.md").read_text(encoding="utf-8")
    assert "../AGENTS.md" in copilot


def _cli_examples(path):
    text = path.read_text(encoding="utf-8")
    for block in re.findall(r"```bash\n(.*?)\n```", text, re.DOTALL):
        for line in block.replace("\\\n", " ").splitlines():
            if line.startswith("python -m argo.cli "):
                yield shlex.split(line)[3:]


def test_documented_agent_commands_and_options_exist():
    app = get_command(cli.app)
    for name in ("AGENTS.md", "docs/agent-guide.md"):
        examples = list(_cli_examples(ROOT / name))
        assert examples, f"No CLI examples found in {name}"
        for args in examples:
            command = app if args[0].startswith("--") else app.commands[args[0]]
            options = {"--help"}
            for param in command.params:
                options.update(param.opts)
                options.update(param.secondary_opts)
            for token in args:
                if token.startswith("--"):
                    assert token.split("=", 1)[0] in options, (name, args, token)


def _checked_examples():
    text = (ROOT / "docs/agent-guide.md").read_text(encoding="utf-8")
    examples = re.findall(
        r"<!-- agent-check: ([a-z]+) -->\s*```bash\n(.*?)\n```", text, re.DOTALL
    )
    assert len(examples) == 4, "Update the acceptance cases when adding/removing checked snippets"
    assert {name for name, _ in examples} == {"screen", "plan", "routing", "demo"}
    return {name: shlex.split(command.replace("\\\n", " "))[3:]
            for name, command in examples}


@pytest.fixture
def offline_cli(monkeypatch, tmp_path):
    """Exercise the actual CLI, isolating state and failing closed on real inference/egress."""
    target = tmp_path / "tests" / "fixtures" / "repo"
    shutil.copytree(ROOT / "tests" / "fixtures" / "repo", target)
    shutil.copyfile(ROOT / "tests" / "fixtures" / "brief.txt", target.parent / "brief.txt")
    monkeypatch.chdir(tmp_path)

    violations = []

    def forbidden(*args, **kwargs):
        violations.append("real inference/network attempted")
        raise AssertionError("Onboarding examples must not invoke real models or the network")

    monkeypatch.setattr(AgentRunner, "_exec", forbidden)
    for runner in (HeadlessClaudeRunner, CodexRunner, GeminiRunner):
        monkeypatch.setattr(runner, "_invoke", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)

    original_config = cli._build_config

    def isolated_config(*args, **kwargs):
        return original_config(*args, **kwargs).with_overrides(
            ledger_path=tmp_path / "ledger.sqlite",
            target_memory_dir=tmp_path / ".argo-target-memory",
        )

    monkeypatch.setattr(cli, "_build_config", isolated_config)
    original_context = cli.build_context
    contexts = []

    def track_context(*args, **kwargs):
        ctx = original_context(*args, **kwargs)
        contexts.append(ctx)
        return ctx

    monkeypatch.setattr(cli, "build_context", track_context)
    before = {p.relative_to(target): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in target.rglob("*") if p.is_file()}
    yield CliRunner(), tmp_path
    for ctx in contexts:
        ctx.ledger.close()
    assert not violations, violations
    after = {p.relative_to(target): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in target.rglob("*") if p.is_file()}
    assert before == after, "Onboarding changed the source target"
    _force_rmtree(tmp_path / "runs")


@pytest.mark.parametrize("name", ["screen", "plan", "routing", "demo"])
def test_checked_onboarding_example(name, offline_cli):
    runner, root = offline_cli
    args = _checked_examples()[name]
    if name != "screen":
        assert args[args.index("--runner") + 1] == "mock"
    result = runner.invoke(cli.app, args)
    assert result.exit_code == 0, (result.output, result.exception)
    stdout = result.stdout
    if name == "demo":
        # Pipeline currently prints a report diagnostic before its final JSON summary.
        summary = re.search(r"(?m)^\{\n", stdout)
        assert summary, stdout
        stdout = stdout[summary.start():]
    data = json.loads(stdout)
    if name == "screen":
        assert data["fingerprint_id"] and data["files"] > 0
    elif name == "plan":
        assert data["plan_id"] and data["enabled_stages"]
        saved_plan = json.loads((root / data["plan_path"]).read_text(encoding="utf-8"))
        assert saved_plan["plan_id"] == data["plan_id"]
    elif name == "routing":
        assert data["runner"] == "mock" and data["stages"]
        assert all(stage["runner"] == "mock" for stage in data["stages"].values())
    else:
        run = root / "runs" / "agent-demo-output" / "agent-demo"
        assert Path(data["report"]).resolve() == run / "REPORT.md"
        assert (run / "REPORT.md").stat().st_size > 0
        status = json.loads((run / "status.json").read_text(encoding="utf-8"))
        assert status["state"] == "completed"
        findings = json.loads((run / "validated_findings.json").read_text(encoding="utf-8"))
        assert findings["findings"]
        drafts = list((run / "submission_drafts").glob("*.md"))
        assert drafts
        assert all("DRAFT - NOT SUBMITTED" in p.read_text(encoding="utf-8") for p in drafts)
        logs = [json.loads(line) for line in
                (run / "llm_log.jsonl").read_text(encoding="utf-8").splitlines()]
        assert logs
        assert not {"research", "corroborate", "runtime", "live", "asan_poc"} & {row["stage"] for row in logs}


def test_documented_resume_recovers_interrupted_mock_run(offline_cli, monkeypatch):
    from argo import orchestrator

    runner, root = offline_cli
    original_validate = orchestrator.do_validate

    def interrupted(_ctx):
        raise KeyboardInterrupt()

    monkeypatch.setattr(orchestrator, "do_validate", interrupted)
    stopped = runner.invoke(cli.app, _checked_examples()["demo"])
    assert stopped.exit_code != 0
    run = root / "runs" / "agent-demo-output" / "agent-demo"
    before = (run / "llm_log.jsonl").read_text(encoding="utf-8").splitlines()
    config = json.loads((run / "config.json").read_text(encoding="utf-8"))
    assert config["runner"] == "mock"
    monkeypatch.setattr(orchestrator, "do_validate", original_validate)

    args = next(args for args in _cli_examples(ROOT / "docs/agent-guide.md")
                if args[0] == "resume" and "--runs-dir" in args)
    args = ["agent-demo" if arg == "RUN_ID" else
            "runs/agent-demo-output" if arg == "path/to/original-runs" else arg for arg in args]
    resumed = runner.invoke(cli.app, args)
    assert resumed.exit_code == 0, (resumed.output, resumed.exception)
    status = json.loads((run / "status.json").read_text(encoding="utf-8"))
    assert status["state"] == "completed"
    assert (run / "REPORT.md").is_file()
    after = (run / "llm_log.jsonl").read_text(encoding="utf-8").splitlines()
    assert after[:len(before)] == before
    assert not {"ingest", "recon", "audit"} & {json.loads(line)["stage"] for line in after[len(before):]}
