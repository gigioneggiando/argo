"""split_ref: non-numeric locators after a real path must not turn the whole string into a "file".

Regression (Qwen3.5-9B moquette replay, 2026-11-05): `.../CTrie.java:addToTree()` was judged
"not in repo" by citation grounding and the finding was dropped before validation."""

from types import SimpleNamespace

import pytest

from argo.grounding import RepoIndex, ground_finding
from argo.ranking import split_ref


@pytest.mark.parametrize("ref,expected", [
    ("src/api/orders.py:4", ("src/api/orders.py", "4")),
    ("a/B.java:12-14 (foo)", ("a/B.java", "12")),
    ("file.js:73, :79 (desc)", ("file.js", "73")),
    ("broker/x/CTrie.java:addToTree()", ("broker/x/CTrie.java", "")),
    ("a/B.java (method x)", ("a/B.java", "")),
    ("a/B.java#L10", ("a/B.java", "10")),
    ("a/B.java, line 7", ("a/B.java", "7")),
    ("a/B.java:readString() line 40", ("a/B.java", "40")),
    ("src/a.py", ("src/a.py", "")),
    ("README", ("README", "")),
    ("Class.method", ("Class.method", "")),
])
def test_split_ref(ref, expected):
    assert split_ref(ref) == expected


def test_method_locator_is_grounded(tmp_path):
    f = tmp_path / "broker" / "subscriptions" / "CTrie.java"
    f.parent.mkdir(parents=True)
    f.write_text("class CTrie { void addToTree() {} }\n", encoding="utf-8")
    finding = SimpleNamespace(affected=["broker/subscriptions/CTrie.java:addToTree()"], title="t",
                              why_vulnerable="w", vulnerable_flow="v", recommended_fix="r")
    out = ground_finding(RepoIndex(tmp_path, set()), finding)
    assert out["missing_files"] == []


def test_truly_missing_file_still_flagged(tmp_path):
    (tmp_path / "x.py").write_text("pass\n", encoding="utf-8")
    finding = SimpleNamespace(affected=["gguf/gguf_tools.c:gguf_get_tensor()"], title="t",
                              why_vulnerable="w", vulnerable_flow="v", recommended_fix="r")
    out = ground_finding(RepoIndex(tmp_path, set()), finding)
    assert out["missing_files"] == ["gguf/gguf_tools.c:gguf_get_tensor()"]
