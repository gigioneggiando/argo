"""Pydantic models for the structured documents that flow between stages.

These mirror ``scope_schema.json`` / ``findings_schema.json`` for ergonomic in-code access.
The JSON Schemas remain authoritative — :mod:`pipeline.schemas` is what gates each stage
boundary; these models are loaded *after* schema validation passes.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

TargetType = Literal["source_only", "source_and_live"]
Severity = Literal["Critical", "High", "Medium", "Low", "Informational"]
Confidence = Literal["Confirmed", "High", "Medium", "Low"]
Verdict = Literal["confirmed", "refuted", "needs_runtime_verification", "out_of_scope"]
# Corroboration cross-checks a surviving finding against the project's own docs + the repo's VCS
# history. ``corroborated`` = still real / reinforced; ``design_accepted`` = documented as intended
# (downgrade to accepted-risk, keep with a note); ``fixed_upstream`` = already patched in a newer
# commit/release (move to an appendix, do not report as active); ``unknown`` = could not determine.
CorroborationVerdict = Literal["corroborated", "design_accepted", "fixed_upstream", "unknown"]
# Deep-verify re-derives a surviving finding from scratch, with full repo tool access and no batching,
# and reasons ACROSS the whole survivor set (validate/corroborate deliberately judge one finding in
# isolation, so neither can notice that two findings share one root cause, or that one finding is
# actually bundling several independently-triggerable bugs). ``reconfirmed`` = independently re-derived,
# stands as written; ``corrected`` = the mechanism is real but a factual detail was wrong (see
# ``corrections``, finding kept with the fix folded in); ``split`` = this one finding is >=2 distinct
# bugs (see ``split_into``, original replaced by the sub-findings); ``merged`` = a duplicate/subset of
# another surviving finding by root cause, not just by dedup_key (see ``merged_into``, kept in an
# appendix, never silently deleted); ``refuted`` = deep re-derivation shows validate+corroborate were
# both wrong; ``inconclusive`` = could not be independently re-derived (session/backend failure, budget,
# or genuine ambiguity even after a real attempt — never a silent drop).
VerificationVerdict = Literal["reconfirmed", "corrected", "split", "merged", "refuted", "inconclusive"]


# --------------------------------------------------------------------------- scope
class InScopeAsset(BaseModel):
    model_config = ConfigDict(extra="allow")
    asset: str
    type: Literal["source_repo", "web", "api", "mobile", "binary", "other"]
    notes: Optional[str] = None


class Scope(BaseModel):
    """Structured scope + rules of engagement (see scope_schema.json)."""

    model_config = ConfigDict(extra="allow")

    program_name: str
    platform: str
    target_type: TargetType
    in_scope: list[InScopeAsset]
    out_of_scope: list[str] = Field(default_factory=list)
    prohibited_techniques: list[str] = Field(default_factory=list)
    severity_guidance: Optional[str] = None
    rate_limits: Optional[str] = None
    safe_harbor: Optional[bool] = None
    automation_allowed: Optional[bool] = None
    special_notes: Optional[str] = None
    reference_links: list[str] = Field(default_factory=list)
    program_brief_raw: Optional[str] = None
    # Free-text description of intended / accepted-by-design security behaviors for this target
    # (the vendor's threat model / known-limitations). Injected into audit + validate + corroborate
    # so behaviors the maintainers consider intentional are not reported as vulnerabilities. Sourced
    # from --accepted-risks (and, over time, from vendor replies / prior design_accepted verdicts).
    accepted_risks: Optional[str] = None

    @property
    def source_repo_assets(self) -> list[InScopeAsset]:
        return [a for a in self.in_scope if a.type == "source_repo"]


# ------------------------------------------------------------------------- findings
class Validation(BaseModel):
    model_config = ConfigDict(extra="allow")
    verdict: Verdict
    validated_confidence: Optional[Confidence] = None
    validated_severity: Optional[Severity] = None
    rationale: Optional[str] = None
    # Extra fields emitted by 02_adversarial_validation_prompt (kept via extra="allow"):
    refutation_attempts: Optional[list] = None
    surviving_data_flow: Optional[str] = None
    unmet_preconditions: Optional[list] = None
    live_verification_plan: Optional[str] = None


class Corroboration(BaseModel):
    """External cross-check of a finding against the project's docs + the repo's VCS history."""

    model_config = ConfigDict(extra="allow")
    verdict: CorroborationVerdict
    rationale: Optional[str] = None
    evidence_urls: list[str] = Field(default_factory=list)   # docs pages, commit/PR/release/advisory URLs
    fix_commit: Optional[str] = None        # commit SHA / PR / release tag that fixed it (fixed_upstream)
    doc_url: Optional[str] = None           # the doc page that documents the behavior (design_accepted)
    adjusted_severity: Optional[Severity] = None   # optional downgrade (e.g. design_accepted -> Low)


class Verification(BaseModel):
    """Deep-verify's independent re-derivation of a surviving finding (see ``VerificationVerdict``).

    Unlike :class:`Validation` (adversarial but per-finding-isolated, batched, excerpt-budgeted),
    this is the unbounded, one-session-per-finding, cross-finding-aware final pass — the same
    standard of rigor as a human re-reading every cited line and tracing every sibling function by
    hand before it goes in a report."""

    model_config = ConfigDict(extra="allow")
    verdict: VerificationVerdict
    rationale: Optional[str] = None
    # The mandatory "show your work" transcript: exact file:line trace, sibling/similar functions
    # checked and how they differ, ABI/struct/precondition assumptions confirmed against the actual
    # source (not the excerpt). Required for every verdict — including reconfirmed — so a human can
    # audit *how* the re-derivation was done, not just trust the verdict.
    independent_derivation: str = ""
    # verdict == "corrected": what was factually wrong in the original finding and the corrected facts.
    corrections: Optional[str] = None
    # verdict == "split": one fully independent Finding-shaped dict per distinct sub-bug (each must
    # stand on its own — its own affected/vulnerable_flow/why_vulnerable/exploit_scenario/impact).
    split_into: Optional[list[dict]] = None
    # verdict == "merged": the id of the OTHER surviving finding this is a duplicate/subset of.
    merged_into: Optional[str] = None
    # Other surviving finding ids considered during cross-finding clustering, even when the verdict
    # stayed reconfirmed (so a human can see what was compared against, not just the final call).
    related_finding_ids: list[str] = Field(default_factory=list)


class FreshnessCommit(BaseModel):
    """One commit touching a cited file on a branch that should be checked before reporting."""

    model_config = ConfigDict(extra="allow")
    sha: str
    subject: str
    author_date: str


class FreshnessFlag(BaseModel):
    """Informational same-file history touch found by the freshness check.

    This is not a verdict and does not change validation/corroboration/deep-verify status. A commit
    touching the same file is only a prompt for human review before sending a report.
    """

    model_config = ConfigDict(extra="allow")
    branch: str
    file_path: str
    commits: list[FreshnessCommit] = Field(default_factory=list)
    checked_at: str
    relation: Literal["audited_branch", "sibling_branch"] = "sibling_branch"


class Grounding(BaseModel):
    """Deterministic citation-grounding result attached at the validate stage: which of a
    finding's cited files / project-specific code symbols could NOT be found in the actual repo
    under audit. ``ungrounded`` symbols downgrade confidence and are surfaced to the adversarial
    validator; a missing primary file drops the finding pre-validation. See :mod:`argo.grounding`."""

    model_config = ConfigDict(extra="allow")
    status: Literal["grounded", "ungrounded"]
    missing_files: list[str] = Field(default_factory=list)
    missing_symbols: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    title: str
    severity: Severity
    confidence: Confidence
    cwe: str
    owasp: Optional[str] = None
    affected: list[str]
    vulnerable_flow: str
    why_vulnerable: str
    exploit_scenario: str
    impact: str
    recommended_fix: str
    action_plan: Optional[str] = None
    missing_tests: Optional[str] = None
    variants: Optional[str] = None
    live_verification_plan: Optional[str] = None
    dedup_key: Optional[str] = None
    validation: Optional[Validation] = None
    corroboration: Optional[Corroboration] = None
    verification: Optional[Verification] = None
    freshness_flag: Optional[list[FreshnessFlag]] = None
    grounding: Optional[Grounding] = None
    # Orchestrator bookkeeping (not in schema, allowed via extra="allow"):
    source_focus: Optional[str] = None
    # Which blind audit pass produced this raw finding ("primary" or "second-opinion-N"); set by
    # validate._load_all() from the containing FindingsFile's own source_pass, mirroring source_focus.
    # See stages/second_opinion.py.
    source_pass: Optional[str] = None
    # Populated at validate time when structural (_merge) or semantic (_semantic_dedup) dedup
    # collapses findings that came from >1 DISTINCT source_pass values into one survivor — i.e. this
    # exact finding (or a near-duplicate of it) was independently re-discovered by a separate blind
    # pass, not just by a different audit focus within the same pass. Strong corroboration signal,
    # surfaced in the report; deliberately NOT fed into validate/corroborate/verify's own prompts so
    # their judgment stays independent of how many passes agree.
    corroborating_passes: list[str] = Field(default_factory=list)


class FindingsFile(BaseModel):
    model_config = ConfigDict(extra="allow")
    program_name: str
    audit_focus: str
    generated_at: str
    findings: list[Finding]
    # Set only by stages/second_opinion.py when merging a blind sub-pass's findings into the primary
    # run's findings_dir; absent/None means "the primary pass" (see Finding.source_pass).
    source_pass: Optional[str] = None


# ----------------------------------------------------------------------- run meta
class AssetVersion(BaseModel):
    path: str
    sha256: str


class RunMeta(BaseModel):
    """Recorded per run in ``runs/<id>/meta.json`` for reproducibility + cost control."""

    model_config = ConfigDict(extra="allow")
    run_id: str
    created_at: str
    program_name: str
    target_type: TargetType
    repo_source: str
    repo_is_url: bool
    repo_commit: Optional[str] = None       # pinned HEAD SHA of the analyzed repo, if it is a git tree
    repo_commit_date: Optional[str] = None  # ISO date of that commit, if available
    requested_ref: Optional[str] = None     # raw --commit as given (branch/tag/sha), before
                                             # resolution to repo_commit; None if no --commit was
                                             # passed (default branch head). A branch-shaped value
                                             # here is the true audited branch name even when the
                                             # checkout ends up on a detached HEAD (pinned commit).
    runner: str
    stage_models: dict[str, str]
    # Structural guardrail flags:
    live_forbidden: bool = True       # always true; no stage may touch a live host
    automation_forbidden: bool = False  # true when automation_allowed is false/absent
    asset_versions: list[AssetVersion] = Field(default_factory=list)


# -------------------------------------------------------------------- manifest
class ArtifactRef(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str
    path: str
    status: Optional[str] = None


class ArtifactManifest(BaseModel):
    model_config = ConfigDict(extra="allow")
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    session_status: Optional[str] = None
