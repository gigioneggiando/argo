"""The per-finding validate path (validate_batch_size <= 1) never crashes on a malformed verdict."""

from argo.stages.validate import _parse_single_verdict


def test_malformed_verdict_files_are_flagged(tmp_path):
    for i, body in enumerate(["{not json", "[1, 2]",
                              '{"verdict": "confirmed", "validated_severity": 42}']):
        p = tmp_path / f"verdict_{i}.json"
        p.write_text(body, encoding="utf-8")
        v = _parse_single_verdict(p)
        assert v.verdict == "needs_runtime_verification"


def test_wellformed_verdict_parses(tmp_path):
    p = tmp_path / "verdict_ok.json"
    p.write_text('{"verdict": "refuted", "rationale": "guarded upstream"}', encoding="utf-8")
    assert _parse_single_verdict(p).verdict == "refuted"
