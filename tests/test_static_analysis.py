from __future__ import annotations

import json

import pytest

from argo.static_analysis import (
    _MAX_INDEX_REFS_PER_NAME,
    _iter_source_files,
    _repo_call_index,
    analyze_location,
    build_static_context,
)


@pytest.mark.parametrize(
    ("name", "source", "line", "language", "symbol", "expected_call"),
    [
        (
            "sample.py",
            "def normalize(v):\n    return v\n\ndef handler(request):\n"
            "    data = request.value\n    clean = normalize(data)\n    sink(clean)\n",
            7,
            "python",
            "handler",
            "sink",
        ),
        (
            "sample.js",
            "function handler(input) {\n  const clean = normalize(input);\n  sink(clean);\n}\n",
            3,
            "javascript",
            "handler",
            "sink",
        ),
        (
            "sample.ts",
            "function handler(input: string) {\n  const clean = normalize(input);\n  sink(clean);\n}\n",
            3,
            "typescript",
            "handler",
            "sink",
        ),
        (
            "sample.cs",
            "class Example {\n  void Handler(string input) {\n"
            "    var clean = Normalize(input);\n    Sink(clean);\n  }\n}\n",
            4,
            "c_sharp",
            "Handler",
            "Sink",
        ),
    ],
)
def test_analyze_location_supported_languages(
    tmp_path, name, source, line, language, symbol, expected_call
):
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")

    ctx = analyze_location(tmp_path, f"{name}:{line}")

    assert ctx.language == language
    assert ctx.symbol is not None
    assert ctx.symbol.name == symbol
    assert any(expected_call in call.name for call in ctx.calls)


def test_local_def_use_and_possible_incoming_are_syntactic(tmp_path):
    (tmp_path / "target.py").write_text(
        "def normalize(v):\n    return v\n\n"
        "def handler(request):\n"
        "    raw = request.value\n"
        "    clean = normalize(raw)\n"
        "    sink(clean)\n",
        encoding="utf-8",
    )
    (tmp_path / "routes.py").write_text(
        "from target import handler\n\n"
        "def route(req):\n"
        "    return handler(req)\n",
        encoding="utf-8",
    )

    ctx = analyze_location(tmp_path, "target.py:7")

    assert ctx.symbol is not None and ctx.symbol.name == "handler"
    assert any(step.name == "clean" and step.defined_at_line == 6 for step in ctx.local_def_use)
    assert any(ref.file == "routes.py" and ref.caller == "route" for ref in ctx.possible_incoming)


def test_path_escape_is_rejected(tmp_path):
    ctx = analyze_location(tmp_path, "../outside.py:1")

    assert ctx.symbol is None
    assert any("outside the repository" in note for note in ctx.notes)


def test_static_context_is_explicitly_non_semantic(tmp_path):
    (tmp_path / "sample.py").write_text(
        "def f(x):\n    y = normalize(x)\n    sink(y)\n",
        encoding="utf-8",
    )

    rendered = build_static_context(tmp_path, ["sample.py:3"])

    first, payload = rendered.split("\n", 1)
    assert "does NOT prove runtime reachability" in first
    data = json.loads(payload)
    assert data[0]["symbol"]["name"] == "f"


def test_calls_and_serialized_context_are_hard_bounded(tmp_path):
    calls = "\n".join(f"    call_{i}(value)" for i in range(200))
    (tmp_path / "many_calls.py").write_text(
        "def handler(value):\n" + calls + "\n",
        encoding="utf-8",
    )

    ctx = analyze_location(tmp_path, "many_calls.py:2")
    assert len(ctx.calls) == 64

    rendered = build_static_context(tmp_path, ["many_calls.py:2"], max_bytes=1024)
    assert len(rendered.encode("utf-8")) <= 1024
    assert (
        "static context truncated to byte budget" in rendered
        or "static context omitted: byte budget exceeded" in rendered
        or "deterministic static context omitted" in rendered
    )


def test_source_scan_is_sorted_pruned_and_size_bounded(tmp_path):
    (tmp_path / "b.py").write_text("print('b')\n", encoding="utf-8")
    (tmp_path / "a.py").write_text("print('a')\n", encoding="utf-8")
    (tmp_path / "too_large.py").write_text("x = '" + ("z" * 500) + "'\n", encoding="utf-8")
    skipped = tmp_path / "node_modules"
    skipped.mkdir()
    (skipped / "first.py").write_text("print('skip')\n", encoding="utf-8")

    files = list(_iter_source_files(
        tmp_path, max_files=10, max_file_bytes=100, max_total_bytes=1000
    ))

    assert [path.name for path in files] == ["a.py", "b.py"]
    assert all("node_modules" not in path.parts for path in files)


def test_possible_incoming_order_is_reproducible(tmp_path):
    (tmp_path / "target.py").write_text(
        "def handler(value):\n    return value\n",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text(
        "from target import handler\n\ndef caller_b(v):\n    return handler(v)\n",
        encoding="utf-8",
    )
    (tmp_path / "a.py").write_text(
        "from target import handler\n\ndef caller_a(v):\n    return handler(v)\n",
        encoding="utf-8",
    )

    ctx = analyze_location(tmp_path, "target.py:2")

    assert [(ref.file, ref.caller) for ref in ctx.possible_incoming[:2]] == [
        ("a.py", "caller_a"),
        ("b.py", "caller_b"),
    ]


def test_dense_call_index_is_bounded_without_rewalking_the_tree(tmp_path):
    calls = "\n".join("    target(value)" for _ in range(500))
    (tmp_path / "dense.py").write_text(
        "def target(value):\n    return value\n\n"
        "def handler(value):\n" + calls + "\n",
        encoding="utf-8",
    )

    _repo_call_index.cache_clear()
    ctx = analyze_location(tmp_path, "dense.py:2")
    index = _repo_call_index(str(tmp_path.resolve()))

    assert ctx.symbol is not None and ctx.symbol.name == "target"
    assert len(ctx.possible_incoming) == _MAX_INDEX_REFS_PER_NAME
    assert len(index["target"]) == _MAX_INDEX_REFS_PER_NAME


def test_cited_file_over_static_analysis_limit_is_skipped(tmp_path):
    (tmp_path / "large.py").write_text(
        "def handler():\n    return '" + ("x" * (512 * 1024)) + "'\n",
        encoding="utf-8",
    )

    ctx = analyze_location(tmp_path, "large.py:2")

    assert any("exceeds static-analysis byte limit" in note for note in ctx.notes)


def test_static_context_handles_a_real_world_sized_python_function(tmp_path):
    """Regression for a native Tree-sitter 0.26 crash on larger Python trees."""
    body = "\n".join(f"    value_{i} = normalize(value_{i - 1})" for i in range(1, 800))
    (tmp_path / "realistic.py").write_text(
        "def normalize(value):\n    return value\n\n"
        "def prepare(value_0):\n" + body + "\n    return value_799\n",
        encoding="utf-8",
    )

    rendered = build_static_context(tmp_path, ["realistic.py:535"])

    assert "prepare" in rendered
