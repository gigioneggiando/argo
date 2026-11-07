"""Backend-agnostic repo-integrity check around every LLM session (runner.repo_fingerprint /
_assert_repo_unchanged in AgentRunner._run_attempt): a session that mutates the audited repo copy
fails closed with failure_kind="repo_mutated", on every backend, and the call is still logged."""

import json
import os
import time

import pytest

from argo.config import PipelineConfig
from argo.ledger import Ledger
from argo.runner import MockClaudeRunner, RunnerError, repo_fingerprint


def _repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "README.md").write_text("hi\n", encoding="utf-8")
    return repo


def _run(tmp_path, monkeypatch, repo, mutate=None, raise_after=None):
    r = MockClaudeRunner(PipelineConfig(runner="mock"), Ledger(tmp_path / "l.sqlite"))
    real_invoke = MockClaudeRunner._invoke

    def invoke(self, **kw):
        if mutate:
            mutate(repo)
        if raise_after:
            raise raise_after
        return real_invoke(self, **kw)

    monkeypatch.setattr(MockClaudeRunner, "_invoke", invoke)
    try:
        return r, r.run(prompt="audit prompt", run_dir=tmp_path, work_dir=tmp_path / "work",
                        model="m", stage="audit", run_id="R", repo_dir=repo, label="x")
    finally:
        r.ledger.close()


def test_fingerprint_stable_and_none_without_repo(tmp_path):
    repo = _repo(tmp_path)
    assert repo_fingerprint(repo) == repo_fingerprint(repo)
    assert repo_fingerprint(None) is None
    assert repo_fingerprint(tmp_path / "missing") is None


def _bump_mtime(p):
    st = p.stat()
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))


@pytest.mark.parametrize("mutation", [
    lambda r: (r / "src" / "a.py").write_text("x = 2\n", encoding="utf-8"),     # same-size edit
    lambda r: (r / "new.txt").write_text("planted", encoding="utf-8"),           # create
    lambda r: (r / "README.md").unlink(),                                         # delete
    lambda r: (r / "README.md").rename(r / "README.txt"),                         # rename
    lambda r: (r / "src" / "b").mkdir(),                                          # new dir
    lambda r: os.chmod(r / "src" / "a.py", 0o444),                                # chmod
    lambda r: _bump_mtime(r / "src" / "a.py"),                                    # touch
], ids=["edit", "create", "delete", "rename", "mkdir", "chmod", "touch"])
def test_each_mutation_changes_fingerprint(tmp_path, mutation):
    repo = _repo(tmp_path)
    os.chmod(repo / "src" / "a.py", 0o644)
    # The repo copy predates the session by far more than one mtime tick; without this, a
    # same-size edit made within the same timestamp granularity (seen on Windows CI) is
    # indistinguishable by metadata, which is not the situation the check guards.
    st = (repo / "src" / "a.py").stat()
    os.utime(repo / "src" / "a.py", ns=(st.st_atime_ns, st.st_mtime_ns - 5_000_000_000))
    before = repo_fingerprint(repo)
    mutation(repo)
    assert repo_fingerprint(repo) != before


def test_untouched_repo_session_passes(tmp_path, monkeypatch):
    _, result = _run(tmp_path, monkeypatch, _repo(tmp_path))
    assert result is not None


def test_mutating_session_fails_closed_and_is_logged(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    with pytest.raises(RunnerError) as ei:
        _run(tmp_path, monkeypatch, repo,
             mutate=lambda r: (r / "src" / "a.py").write_text("pwned\n", encoding="utf-8"))
    assert ei.value.failure_kind == "repo_mutated"
    assert ei.value.retryable is False
    rows = [json.loads(l) for l in (tmp_path / "llm_log.jsonl").read_text(encoding="utf-8").splitlines()]
    assert rows and rows[-1]["failure_kind"] == "repo_mutated"


def test_mutation_detected_even_when_session_errors(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    with pytest.raises(RunnerError) as ei:
        _run(tmp_path, monkeypatch, repo,
             mutate=lambda r: (r / "x").write_text("y", encoding="utf-8"),
             raise_after=RunnerError("boom", retryable=True, failure_kind="timeout"))
    assert ei.value.failure_kind == "repo_mutated"
    assert isinstance(ei.value.__cause__, RunnerError)


def test_session_error_without_mutation_is_unchanged(tmp_path, monkeypatch):
    with pytest.raises(RunnerError) as ei:
        _run(tmp_path, monkeypatch, _repo(tmp_path),
             raise_after=RunnerError("boom", retryable=True, failure_kind="timeout"))
    assert ei.value.failure_kind == "timeout"


def test_fingerprint_is_cheap_on_a_few_thousand_files(tmp_path):
    repo = tmp_path / "big"
    for d in range(40):
        sub = repo / f"d{d}"
        sub.mkdir(parents=True)
        for f in range(50):
            (sub / f"f{f}.go").write_text("package x\n", encoding="utf-8")
    t = time.perf_counter()
    repo_fingerprint(repo)
    assert time.perf_counter() - t < 1.0
