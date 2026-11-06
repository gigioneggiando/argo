"""Qualified-name citations (``io.x.Foo.bar():26``) resolve to real ``path:line`` before grounding.

Regression (Mistral Medium moquette replay, 2026-11-06): four DoS findings citing Java FQNs were
dropped pre-validation as "primary affected file not in repo"."""

from types import SimpleNamespace

import pytest

from argo.grounding import RepoIndex, ground_finding

SERDES = "src/main/java/io/moquette/persistence/SerdesUtils.java"


@pytest.fixture
def repo(tmp_path):
    for rel in (SERDES, "src/main/java/io/moquette/broker/Server.java",
                "a/Dup.java", "b/Dup.java", "pkg/util.py"):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("class X { readProperties(); load_config(); run(); }\n" * 60, encoding="utf-8")
    return RepoIndex(tmp_path, set())


@pytest.mark.parametrize("ref,expected", [
    ("io.moquette.persistence.SerdesUtils.readProperties():26-35", f"{SERDES}:26-35"),
    ("io.moquette.persistence.SerdesUtils.readProperties()", SERDES),
    ("io.moquette.persistence.SerdesUtils:40", f"{SERDES}:40"),
    ("SerdesUtils.readProperties():12", f"{SERDES}:12"),
    ("pkg.util.load_config():3", "pkg/util.py:3"),
    (f"{SERDES}:26", f"{SERDES}:26"),                     # already a path: untouched
    ("Dup.run():5", "Dup.run():5"),                       # ambiguous basename: untouched
    ("com.example.Missing.run():5", "com.example.Missing.run():5"),
    ("not a citation at all", "not a citation at all"),
    ("", ""),
])
def test_normalize_ref(repo, ref, expected):
    assert repo.normalize_ref(ref) == expected


def test_resolved_fqn_is_grounded(repo):
    ref = repo.normalize_ref("io.moquette.persistence.SerdesUtils.readProperties():26-35")
    finding = SimpleNamespace(affected=[ref], title="t", why_vulnerable="w",
                              vulnerable_flow="v", recommended_fix="r")
    assert ground_finding(repo, finding)["missing_files"] == []
