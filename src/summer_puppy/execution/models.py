from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from summer_puppy.events.models import (
    DryRunResult,  # noqa: TC001
    ExecutionResult,  # noqa: TC001
    RollbackRecord,  # noqa: TC001
)
from summer_puppy.trust.models import ActionClass  # noqa: TC001


class ExecutionStep(StrEnum):
    DRY_RUN = "DRY_RUN"
    POLICY_GATE = "POLICY_GATE"
    EXECUTE = "EXECUTE"
    VERIFY = "VERIFY"
    ROLLBACK = "ROLLBACK"


class VerificationCheck(BaseModel):
    check_name: str
    passed: bool
    detail: str = ""


class VerificationReport(BaseModel):
    report_id: str = Field(default_factory=lambda: str(uuid4()))
    execution_id: str
    customer_id: str
    checks: list[VerificationCheck] = Field(default_factory=list)
    overall_success: bool = False
    verified_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


class ExecutionPlan(BaseModel):
    plan_id: str = Field(default_factory=lambda: str(uuid4()))
    customer_id: str
    correlation_id: str
    action_class: ActionClass
    parameters: dict[str, Any] = Field(default_factory=dict)
    current_step: ExecutionStep = ExecutionStep.DRY_RUN
    dry_run_result: DryRunResult | None = None
    policy_gate_passed: bool = False
    policy_gate_reason: str = ""
    execution_result: ExecutionResult | None = None
    verification_report: VerificationReport | None = None
    rollback_record: RollbackRecord | None = None
    created_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    completed_utc: datetime | None = None
