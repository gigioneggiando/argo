"""Unit tests: dedup key / ref parsing, manifest extraction + glob fallback, schema gates."""

import json
from pathlib import Path

import pytest

from argo.ranking import dedup_key, split_ref, severity_rank, confidence_rank
from argo.rendering import extract_manifest, with_artifact_contract
from argo.schemas import SchemaValidationError, validate_findings, validate_scope
from argo.runner import LLMResult
from argo.context import collect_output_files

FIXTURES = Path(__file__).parent / "fixtures"


def test_split_ref_variants():
    assert split_ref("src/api/search.py:42") == ("src/api/search.py", "42")
    assert split_ref("src/api/x.py:42-50") == ("src/api/x.py", "42")
    assert split_ref("Service.method") == ("Service.method", "")


def test_dedup_key_stable_and_discriminating():
    a = dedup_key("src/api/search.py", "42", "CWE-89")
    b = dedup_key("SRC/API/search.py", "42", "cwe-89")   # normalized -> same
    c = dedup_key("src/api/search.py", "42", "CWE-79")   # different cwe -> different
    assert a == b
    assert a != c


def test_rank_orders():
    assert severity_rank("Critical") > severity_rank("High") > severity_rank("Informational")
    assert confidence_rank("Confirmed") > confidence_rank("Low")
    assert severity_rank("bogus") == 0


def test_extract_manifest_takes_last_valid_block():
    text = ("noise\n```json\n{\"x\":1}\n```\nmore\n"
            "```json\n{\"artifacts\":[{\"path\":\"a.json\"}],\"session_status\":\"complete\"}\n```")
    m = extract_manifest(text)
    assert m and m["artifacts"][0]["path"] == "a.json"
    assert extract_manifest("no blocks here") is None


def test_collect_output_files_glob_fallback(tmp_path):
    # No manifest in text -> must still find the file by globbing the scratch dir.
    (tmp_path / "SECURITY_FINDINGS__x.json").write_text("{}", encoding="utf-8")
    res = LLMResult(text="session died, no manifest", model="m", prompt_sha256="h",
                    work_dir=tmp_path)
    files = collect_output_files(res, "SECURITY_FINDINGS__*.json")
    assert [f.name for f in files] == ["SECURITY_FINDINGS__x.json"]


def test_findings_fixture_conforms_to_schema():
    for f in (FIXTURES / "happy" / "audit").glob("*.findings.json"):
        validate_findings(json.loads(f.read_text(encoding="utf-8")))


def test_scope_fixture_conforms_to_schema():
    validate_scope(json.loads((FIXTURES / "happy" / "ingest" / "scope.json").read_text("utf-8")))


def test_invalid_findings_rejected():
    with pytest.raises(SchemaValidationError):
        validate_findings({"program_name": "x"})  # missing required fields


def test_cost_report(tmp_path):
    from argo.ledger import Ledger
    from argo.costs import cost_report
    led = Ledger(tmp_path / "l.sqlite")
    # two runs, two models, two stages
    led.log_call(run_id="A", stage="recon", model="opus", prompt_sha256="h",
                 input_tokens=10, output_tokens=1000, cost_usd=0.50)
    led.log_call(run_id="A", stage="audit", model="sonnet", prompt_sha256="h",
                 input_tokens=10, output_tokens=2000, cost_usd=0.20)
    led.log_call(run_id="B", stage="audit", model="sonnet", prompt_sha256="h",
                 input_tokens=10, output_tokens=2000, cost_usd=0.20)
    rep = cost_report(led)
    assert rep["totals"] == {"calls": 3, "runs": 2, "cost_usd": 0.9,
                             "avg_cost_per_run": 0.45}
    by_model = {m["model"]: m for m in rep["by_model"]}
    assert by_model["opus"]["cost_usd"] == 0.5 and by_model["sonnet"]["calls"] == 2
    # sonnet is cheaper per 1k output tokens (0.40/4000*1000=0.10) than opus (0.50)
    assert rep["cheapest_model_per_1k_output"] == "sonnet"
    by_stage = {s["stage"]: s for s in rep["by_stage"]}
    assert by_stage["audit"]["cost_usd"] == 0.4
    # by_archetype only appears when a run->archetype map is supplied
    assert "by_archetype" not in rep
    rep2 = cost_report(led, run_archetypes={"A": "web_api_cms", "B": "plugin_extension"})
    by_arch = {a["archetype"]: a for a in rep2["by_archetype"]}
    assert by_arch["web_api_cms"]["cost_usd"] == 0.7 and by_arch["web_api_cms"]["runs"] == 1
    assert by_arch["plugin_extension"]["avg_cost_per_run"] == 0.2
    assert by_arch["web_api_cms"]["label"] == "Web / API / CMS"
    led.close()


def test_archetype_canonicalize():
    from argo.archetype import canonicalize, label
    assert canonicalize("plugin_extension") == "plugin_extension"   # already canonical
    assert canonicalize("A Minecraft plugin / mixin") == "plugin_extension"
    assert canonicalize("REST API backend with GraphQL") == "web_api_cms"
    assert canonicalize("Solidity smart contract") == "smart_contract"
    assert canonicalize("") == "other" and canonicalize(None) == "other"
    assert label("web_api_cms") == "Web / API / CMS"


def test_repo_commit_pinning(tmp_path):
    import shutil
    import subprocess
    from argo.stages.ingest import repo_commit
    if not shutil.which("git"):
        import pytest
        pytest.skip("git not available")
    repo = tmp_path / "g"
    repo.mkdir()
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "a@b.c",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "a@b.c"}
    import os
    e = {**os.environ, **env}
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "x.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "init"], check=True, env=e)
    sha, date = repo_commit(repo)
    assert sha and len(sha) == 40 and all(c in "0123456789abcdef" for c in sha)
    assert date and len(date) == 10                  # ISO yyyy-mm-dd
    assert repo_commit(tmp_path / "nope") == (None, None)   # non-git -> no crash


def test_recon_audit_prompt_name_normalization():
    from argo.stages.recon import _is_audit_prompt, _canonical_prompt_name
    # accept both underscore and hyphen (real models drift), reject other artifacts
    assert _is_audit_prompt("audit_p1_full.md") and _is_audit_prompt("audit-cross-instance.md")
    assert not _is_audit_prompt("repo_profile.json") and not _is_audit_prompt("synthesis_notes.md")
    assert not _is_audit_prompt("auditing.md")          # must be audit[-_], not just "audit"
    # normalize hyphenated names so the audit stage's audit_*.md glob picks them up
    assert _canonical_prompt_name("audit-cross-instance.md") == "audit_cross-instance.md"
    assert _canonical_prompt_name("audit_p1_full.md") == "audit_p1_full.md"


def test_local_scope_synthesis():
    from argo.stages.ingest import _local_scope, _repo_name
    assert _repo_name("https://github.com/org/My-Repo.git", True) == "My-Repo"
    assert _repo_name("https://gitlab.com/a/b/", True) == "b"
    s = _local_scope("/home/me/secret-proj", False)
    assert s["program_name"] == "secret-proj" and s["target_type"] == "source_only"
    assert s["platform"] == "local" and s["in_scope"][0]["type"] == "source_repo"
    assert len(s["prohibited_techniques"]) >= 3 and s["automation_allowed"] is True


def test_recon_detect_archetype():
    from argo.stages.recon import _detect_archetype
    assert _detect_archetype({"archetype": "library_sdk"}, "") == "library_sdk"
    # falls back to parsing the synthesis notes when repo_profile lacks the field
    notes = "# Synthesis\n\n## Archetype classification\nThis is a CLI / desktop tool.\n"
    assert _detect_archetype({}, notes) == "cli_desktop"
    assert _detect_archetype({}, "") == "other"


def test_vuln_index_loads_and_formats():
    from argo.knowledge import load_vuln_index, format_for_prompt
    idx = load_vuln_index()
    assert "plugin_extension" in idx and "general" in idx
    assert any(e["cwe"] == "CWE-502" for e in idx["plugin_extension"])   # unsafe deser class
    txt = format_for_prompt(idx)
    assert "VULNERABILITY-CLASS REFERENCE INDEX" in txt
    assert "plugin_extension" in txt and "CWE-502" in txt
    # framed as additive, not a hard constraint
    assert "do NOT limit yourself" in txt


def test_artifact_contract_mentions_readonly_and_manifest():
    out = with_artifact_contract("BODY", artifacts=[
        {"type": "findings", "filename": "f.json", "schema": "findings_schema.json", "desc": "d"}])
    assert "READ-ONLY" in out
    assert "f.json" in out
    assert "```json" in out  # manifest contract present
