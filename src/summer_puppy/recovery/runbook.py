"""Recovery runbook — structured, executable disaster-recovery procedures (Phase 12).

The runbook captures the step-by-step procedures for recovering from each
failure scenario.  Steps can be either manual (human action required) or
automated (executed by the controller).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Callable
from uuid import uuid4

from pydantic import BaseModel, Field

from summer_puppy.logging.config import get_logger

logger = get_logger(__name__)


class StepType(StrEnum):
    AUTOMATED = "automated"
    MANUAL = "manual"
    VERIFICATION = "verification"


class StepStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class RunbookStatus(StrEnum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"  # some steps completed, not all


@dataclass
class RecoveryStep:
    """A single step in a recovery runbook."""

    name: str
    description: str
    step_type: StepType = StepType.MANUAL
    # Automated steps have an executor function
    executor: Callable[..., Any] | None = None
    # Whether failure of this step should abort the runbook
    critical: bool = True
    # Estimated duration in seconds (for human steps)
    estimated_duration_seconds: int = 60
    status: StepStatus = StepStatus.PENDING
    started_utc: datetime | None = None
    completed_utc: datetime | None = None
    output: str | None = None
    error: str | None = None

    @property
    def duration_seconds(self) -> float | None:
        if self.started_utc and self.completed_utc:
            return (self.completed_utc - self.started_utc).total_seconds()
        return None


class RunbookExecution(BaseModel):
    """Record of a runbook execution."""

    execution_id: str = Field(default_factory=lambda: str(uuid4()))
    runbook_name: str
    scenario: str
    status: RunbookStatus = RunbookStatus.NOT_STARTED
    started_utc: datetime | None = None
    completed_utc: datetime | None = None
    steps_completed: int = 0
    steps_failed: int = 0
    steps_skipped: int = 0
    notes: list[str] = Field(default_factory=list)


class RecoveryRunbook:
    """An ordered collection of steps for a specific failure scenario.

    Usage::

        runbook = RecoveryRunbook("neo4j_primary_failure", "Neo4j primary node failed")
        runbook.add_step(RecoveryStep("verify_failure", "Confirm primary is unreachable", ...))
        runbook.add_step(RecoveryStep("promote_replica", "Promote replica-1", ...))
        runbook.add_step(RecoveryStep("update_config", "Update bolt URI in config", ...))

        execution = await runbook.execute()
    """

    def __init__(self, name: str, scenario: str) -> None:
        self._name = name
        self._scenario = scenario
        self._steps: list[RecoveryStep] = []
        self._executions: list[RunbookExecution] = []

    @property
    def name(self) -> str:
        return self._name

    @property
    def scenario(self) -> str:
        return self._scenario

    @property
    def steps(self) -> list[RecoveryStep]:
        return list(self._steps)

    def add_step(self, step: RecoveryStep) -> None:
        self._steps.append(step)

    def step_count(self) -> int:
        return len(self._steps)

    def automated_step_count(self) -> int:
        return sum(1 for s in self._steps if s.step_type == StepType.AUTOMATED)

    def manual_step_count(self) -> int:
        return sum(1 for s in self._steps if s.step_type == StepType.MANUAL)

    def estimated_total_seconds(self) -> int:
        """Sum of estimated durations for all manual/verification steps."""
        return sum(
            s.estimated_duration_seconds
            for s in self._steps
            if s.step_type != StepType.AUTOMATED
        )

    async def execute(self) -> RunbookExecution:
        """Run all automated steps; skip manual steps with a log entry.

        Returns a RunbookExecution with the final status.
        """
        execution = RunbookExecution(
            runbook_name=self._name,
            scenario=self._scenario,
            status=RunbookStatus.IN_PROGRESS,
            started_utc=datetime.now(tz=UTC),
        )
        self._executions.append(execution)

        logger.info(
            "runbook_started",
            runbook=self._name,
            execution_id=execution.execution_id,
            total_steps=len(self._steps),
        )

        failed = False
        for step in self._steps:
            step.status = StepStatus.IN_PROGRESS
            step.started_utc = datetime.now(tz=UTC)

            if step.step_type == StepType.MANUAL:
                step.status = StepStatus.SKIPPED
                step.completed_utc = datetime.now(tz=UTC)
                execution.steps_skipped += 1
                execution.notes.append(
                    f"MANUAL REQUIRED: {step.name} — {step.description}"
                )
                logger.info(
                    "runbook_manual_step_skipped",
                    step=step.name,
                    description=step.description,
                )
                continue

            if step.executor is None:
                step.status = StepStatus.SKIPPED
                step.completed_utc = datetime.now(tz=UTC)
                execution.steps_skipped += 1
                continue

            try:
                import asyncio
                import inspect

                if inspect.iscoroutinefunction(step.executor):
                    result = await step.executor()
                else:
                    result = await asyncio.to_thread(step.executor)

                step.output = str(result) if result is not None else "ok"
                step.status = StepStatus.COMPLETED
                step.completed_utc = datetime.now(tz=UTC)
                execution.steps_completed += 1
                logger.info(
                    "runbook_step_completed",
                    step=step.name,
                    duration=step.duration_seconds,
                )
            except Exception as exc:  # noqa: BLE001
                step.status = StepStatus.FAILED
                step.error = str(exc)
                step.completed_utc = datetime.now(tz=UTC)
                execution.steps_failed += 1
                logger.error(
                    "runbook_step_failed",
                    step=step.name,
                    error=str(exc),
                )
                if step.critical:
                    failed = True
                    break

        execution.completed_utc = datetime.now(tz=UTC)
        if failed:
            execution.status = RunbookStatus.FAILED
        elif execution.steps_failed > 0:
            execution.status = RunbookStatus.PARTIAL
        elif execution.steps_skipped == len(self._steps):
            execution.status = RunbookStatus.PARTIAL
        else:
            execution.status = RunbookStatus.COMPLETED

        logger.info(
            "runbook_finished",
            execution_id=execution.execution_id,
            status=execution.status,
            completed=execution.steps_completed,
            failed=execution.steps_failed,
            skipped=execution.steps_skipped,
        )
        return execution

    def get_executions(self) -> list[RunbookExecution]:
        return list(self._executions)


# ---------------------------------------------------------------------------
# Pre-built runbooks for common failure scenarios
# ---------------------------------------------------------------------------


def build_neo4j_failover_runbook() -> RecoveryRunbook:
    """Standard runbook for Neo4j primary node failure."""
    rb = RecoveryRunbook(
        name="neo4j_primary_failover",
        scenario="Neo4j primary node is unreachable",
    )
    rb.add_step(RecoveryStep(
        name="verify_primary_failure",
        description=(
            "Confirm the Neo4j primary is unreachable: "
            "try bolt://<primary>:7687 from a bastion host."
        ),
        step_type=StepType.VERIFICATION,
        estimated_duration_seconds=120,
        critical=True,
    ))
    rb.add_step(RecoveryStep(
        name="identify_replica",
        description=(
            "Identify the most up-to-date replica using "
            "SHOW DATABASES and checking the last-commit timestamp."
        ),
        step_type=StepType.MANUAL,
        estimated_duration_seconds=180,
        critical=True,
    ))
    rb.add_step(RecoveryStep(
        name="promote_replica",
        description="Promote the chosen replica to core member.",
        step_type=StepType.MANUAL,
        estimated_duration_seconds=300,
        critical=True,
    ))
    rb.add_step(RecoveryStep(
        name="update_application_config",
        description=(
            "Update NEO4J_URI environment variable (or Kubernetes secret) "
            "to point to the new primary bolt address."
        ),
        step_type=StepType.MANUAL,
        estimated_duration_seconds=120,
        critical=True,
    ))
    rb.add_step(RecoveryStep(
        name="rolling_restart",
        description="Perform a rolling restart of SummerPuppy workers.",
        step_type=StepType.MANUAL,
        estimated_duration_seconds=300,
        critical=True,
    ))
    rb.add_step(RecoveryStep(
        name="verify_recovery",
        description=(
            "Confirm all health checks are green and MTTC is within SLO."
        ),
        step_type=StepType.VERIFICATION,
        estimated_duration_seconds=120,
        critical=False,
    ))
    return rb


def build_redis_failover_runbook() -> RecoveryRunbook:
    """Standard runbook for Redis primary node failure."""
    rb = RecoveryRunbook(
        name="redis_primary_failover",
        scenario="Redis primary node is unreachable",
    )
    rb.add_step(RecoveryStep(
        name="verify_primary_failure",
        description="Confirm Redis primary is unreachable via redis-cli PING.",
        step_type=StepType.VERIFICATION,
        estimated_duration_seconds=60,
        critical=True,
    ))
    rb.add_step(RecoveryStep(
        name="check_sentinel",
        description=(
            "If Sentinel is configured, verify Sentinel has detected "
            "the failure and elected a new primary."
        ),
        step_type=StepType.MANUAL,
        estimated_duration_seconds=120,
        critical=True,
    ))
    rb.add_step(RecoveryStep(
        name="update_application_config",
        description="Update REDIS_HOST to the new primary address.",
        step_type=StepType.MANUAL,
        estimated_duration_seconds=120,
        critical=True,
    ))
    rb.add_step(RecoveryStep(
        name="verify_worker_coordination",
        description=(
            "Confirm distributed locks and worker heartbeats resume "
            "on the new primary."
        ),
        step_type=StepType.VERIFICATION,
        estimated_duration_seconds=120,
        critical=False,
    ))
    return rb


def build_kafka_recovery_runbook() -> RecoveryRunbook:
    """Standard runbook for Kafka broker failure."""
    rb = RecoveryRunbook(
        name="kafka_broker_recovery",
        scenario="Kafka broker is unreachable or a partition leader has failed",
    )
    rb.add_step(RecoveryStep(
        name="identify_failed_broker",
        description="Use kafka-broker-api-versions.sh to identify the failed broker ID.",
        step_type=StepType.MANUAL,
        estimated_duration_seconds=180,
        critical=True,
    ))
    rb.add_step(RecoveryStep(
        name="check_partition_leadership",
        description="Run kafka-topics.sh --describe to check for under-replicated partitions.",
        step_type=StepType.MANUAL,
        estimated_duration_seconds=120,
        critical=True,
    ))
    rb.add_step(RecoveryStep(
        name="restart_or_replace_broker",
        description=(
            "If recoverable, restart the Kafka broker process. "
            "If not, provision a replacement broker with the same broker.id."
        ),
        step_type=StepType.MANUAL,
        estimated_duration_seconds=600,
        critical=True,
    ))
    rb.add_step(RecoveryStep(
        name="verify_replication_factor",
        description=(
            "Run kafka-reassign-partitions.sh if needed to restore "
            "the replication factor to 3."
        ),
        step_type=StepType.MANUAL,
        estimated_duration_seconds=300,
        critical=False,
    ))
    rb.add_step(RecoveryStep(
        name="verify_consumer_lag",
        description=(
            "Run kafka-consumer-groups.sh --describe to confirm "
            "consumer lag is recovering."
        ),
        step_type=StepType.VERIFICATION,
        estimated_duration_seconds=120,
        critical=False,
    ))
    return rb


def build_full_recovery_guide() -> dict[str, RecoveryRunbook]:
    """Return all standard runbooks indexed by scenario name."""
    return {
        "neo4j_primary_failover": build_neo4j_failover_runbook(),
        "redis_primary_failover": build_redis_failover_runbook(),
        "kafka_broker_recovery": build_kafka_recovery_runbook(),
    }
