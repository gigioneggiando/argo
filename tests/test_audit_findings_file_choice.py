"""Audit picks the model-written findings file when the exactly-named one is Argo's untouched seed.

Regression (Qwen3-Coder-Next 80B, moquette replay 2026-11-05): the model wrote
SECURITY_FINDINGS__authz_acl.json (slug without `audit_`); Argo chose the exactly-named seed,
reported "no checkpointed findings" and re-ran the focus."""

import json

import pytest

from argo.stages.audit import _STREAMING_SEED_KEY, _choose_findings_file

EXPECTED = "SECURITY_FINDINGS__audit_authz_acl.json"


def _w(tmp_path, name, doc):
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def test_untouched_seed_loses_to_model_written_file(tmp_path):
    seed = _w(tmp_path, EXPECTED, {"findings": [], _STREAMING_SEED_KEY: True})
    other = _w(tmp_path, "SECURITY_FINDINGS__authz_acl.json", {"findings": [{"id": "A"}]})
    path, doc = _choose_findings_file([seed, other], EXPECTED)
    assert path == other and doc["findings"][0]["id"] == "A"


def test_model_updated_exact_file_wins(tmp_path):
    exact = _w(tmp_path, EXPECTED, {"findings": [{"id": "E"}]})
    other = _w(tmp_path, "SECURITY_FINDINGS__authz_acl.json", {"findings": [{"id": "A"}, {"id": "B"}]})
    path, _ = _choose_findings_file([other, exact], EXPECTED)
    assert path == exact


def test_seed_only_is_still_reported_as_seed(tmp_path):
    seed = _w(tmp_path, EXPECTED, {"findings": [], _STREAMING_SEED_KEY: True})
    path, doc = _choose_findings_file([seed], EXPECTED)
    assert path == seed and doc[_STREAMING_SEED_KEY] is True


def test_model_empty_answer_is_kept(tmp_path):
    exact = _w(tmp_path, EXPECTED, {"findings": []})            # model wrote "no findings"
    path, doc = _choose_findings_file([exact], EXPECTED)
    assert path == exact and _STREAMING_SEED_KEY not in doc


def test_invalid_json_skipped_if_another_parses(tmp_path):
    bad = tmp_path / EXPECTED
    bad.write_text("{broken", encoding="utf-8")
    other = _w(tmp_path, "SECURITY_FINDINGS__x.json", {"findings": [{"id": "A"}]})
    path, _ = _choose_findings_file([bad, other], EXPECTED)
    assert path == other


def test_all_invalid_raises(tmp_path):
    bad = tmp_path / EXPECTED
    bad.write_text("{broken", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        _choose_findings_file([bad], EXPECTED)
