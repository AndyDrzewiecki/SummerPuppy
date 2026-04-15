"""Dev bot data models — patch candidates, test results, PRs, and quality records."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from summer_puppy.sandbox.models import FindingSeverity
from summer_puppy.trust.models import ActionClass


class PatchType(StrEnum):
    FIREWALL_RULE = "firewall_rule"
    IAM_POLICY = "iam_policy"
    EDR_CONFIG = "edr_config"
    REMEDIATION_SCRIPT = "remediation_script"
    CONFIGURATION_CHANGE = "configuration_change"
    NETWORK_POLICY = "network_policy"


class PatchStatus(StrEnum):
    PENDING = "pending"
    TESTING = "testing"
    TEST_PASSED = "test_passed"
    TEST_FAILED = "test_failed"
    PR_OPEN = "pr_open"
    PR_MERGED = "pr_merged"
    PR_CLOSED = "pr_closed"
    ABANDONED = "abandoned"


class PROutcome(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"
    PENDING = "pending"
    MERGED = "merged"
    CLOSED = "closed"


class UserStory(BaseModel):
    story_id: str = Field(default_factory=lambda: str(uuid4()))
    finding_id: str
    customer_id: str
    correlation_id: str
    title: str
    description: str
    acceptance_criteria: list[str] = Field(default_factory=list)
    severity: FindingSeverity
    cve_refs: list[str] = Field(default_factory=list)
    affected_files: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    mitre_attack_ids: list[str] = Field(default_factory=list)
    action_class: ActionClass = ActionClass.PATCH_DEPLOYMENT
    recommended_patch_types: list[PatchType] = Field(default_factory=list)
    created_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)


class PatchCandidate(BaseModel):
    patch_id: str = Field(default_factory=lambda: str(uuid4()))
    story_id: str
    customer_id: str
    correlation_id: str
    patch_type: PatchType
    title: str
    description: str
    content: str
    target_files: list[str] = Field(default_factory=list)
    language: str = ""
    status: PatchStatus = PatchStatus.PENDING
    generation_model: str = ""
    confidence_score: float = Field(default=0.0, ge=0, le=1)
    reasoning: str = ""
    rollback_content: str = ""
    created_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)


class PatchTestCheck(BaseModel):
    check_name: str
    passed: bool
    detail: str = ""


class PatchTestResult(BaseModel):
    test_id: str = Field(default_factory=lambda: str(uuid4()))
    patch_id: str
    customer_id: str
    passed: bool
    checks: list[PatchTestCheck] = Field(default_factory=list)
    summary: str = ""
    sandbox_output: dict[str, Any] = Field(default_factory=dict)
    duration_ms: float = 0.0
    tested_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


class DevBotPR(BaseModel):
    pr_id: str = Field(default_factory=lambda: str(uuid4()))
    patch_id: str
    story_id: str
    customer_id: str
    correlation_id: str
    github_pr_number: int | None = None
    github_pr_url: str | None = None
    github_repo: str = ""
    branch_name: str = ""
    pr_title: str = ""
    pr_body: str = ""
    status: PatchStatus = PatchStatus.PR_OPEN
    outcome: PROutcome = PROutcome.PENDING
    opened_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    closed_utc: datetime | None = None
    merged_utc: datetime | None = None
    reviewed_by: str | None = None
    review_notes: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class DevBotQualityRecord(BaseModel):
    record_id: str = Field(default_factory=lambda: str(uuid4()))
    pr_id: str
    patch_id: str
    story_id: str
    customer_id: str
    correlation_id: str
    outcome: PROutcome
    patch_type: PatchType
    pre_submit_test_passed: bool
    merged_without_change: bool = False
    rejection_reason: str = ""
    patch_quality_score: float = Field(default=0.0, ge=0, le=1)
    recorded_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)
