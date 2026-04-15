"""Unit tests for recovery runbook (Phase 12)."""

from __future__ import annotations

import pytest

from summer_puppy.recovery.runbook import (
    RecoveryRunbook,
    RecoveryStep,
    RunbookExecution,
    RunbookStatus,
    StepStatus,
    StepType,
    build_full_recovery_guide,
    build_kafka_recovery_runbook,
    build_neo4j_failover_runbook,
    build_redis_failover_runbook,
)


# ---------------------------------------------------------------------------
# RecoveryStep
# ---------------------------------------------------------------------------


class TestRecoveryStep:
    def test_defaults(self) -> None:
        step = RecoveryStep(name="test", description="do something")
        assert step.step_type == StepType.MANUAL
        assert step.critical is True
        assert step.status == StepStatus.PENDING
        assert step.executor is None
        assert step.output is None
        assert step.error is None

    def test_automated_step(self) -> None:
        async def my_fn() -> str:
            return "done"

        step = RecoveryStep(
            name="auto",
            description="automated step",
            step_type=StepType.AUTOMATED,
            executor=my_fn,
        )
        assert step.step_type == StepType.AUTOMATED
        assert step.executor is not None

    def test_duration_none_when_not_started(self) -> None:
        step = RecoveryStep(name="s", description="d")
        assert step.duration_seconds is None

    def test_duration_calculated(self) -> None:
        from datetime import UTC, datetime, timedelta

        step = RecoveryStep(name="s", description="d")
        now = datetime.now(tz=UTC)
        step.started_utc = now
        step.completed_utc = now + timedelta(seconds=3)
        assert step.duration_seconds == pytest.approx(3.0, abs=0.01)


# ---------------------------------------------------------------------------
# RecoveryRunbook — structure
# ---------------------------------------------------------------------------


class TestRecoveryRunbookStructure:
    def test_name_and_scenario(self) -> None:
        rb = RecoveryRunbook("my_runbook", "Something failed")
        assert rb.name == "my_runbook"
        assert rb.scenario == "Something failed"

    def test_add_step_increases_count(self) -> None:
        rb = RecoveryRunbook("rb", "scenario")
        rb.add_step(RecoveryStep("s1", "step 1"))
        rb.add_step(RecoveryStep("s2", "step 2"))
        assert rb.step_count() == 2

    def test_automated_step_count(self) -> None:
        rb = RecoveryRunbook("rb", "scenario")
        rb.add_step(RecoveryStep("s1", "manual", step_type=StepType.MANUAL))
        rb.add_step(RecoveryStep("s2", "auto", step_type=StepType.AUTOMATED))
        rb.add_step(RecoveryStep("s3", "verify", step_type=StepType.VERIFICATION))
        assert rb.automated_step_count() == 1
        assert rb.manual_step_count() == 1

    def test_estimated_total_seconds(self) -> None:
        rb = RecoveryRunbook("rb", "scenario")
        rb.add_step(RecoveryStep(
            "s1", "manual", step_type=StepType.MANUAL, estimated_duration_seconds=120
        ))
        rb.add_step(RecoveryStep(
            "s2", "auto", step_type=StepType.AUTOMATED, estimated_duration_seconds=10
        ))
        rb.add_step(RecoveryStep(
            "s3", "verify", step_type=StepType.VERIFICATION, estimated_duration_seconds=60
        ))
        # Only manual + verification steps count
        assert rb.estimated_total_seconds() == 180

    def test_steps_returns_copy(self) -> None:
        rb = RecoveryRunbook("rb", "s")
        rb.add_step(RecoveryStep("s1", "d"))
        steps = rb.steps
        steps.clear()
        assert rb.step_count() == 1  # original not affected


# ---------------------------------------------------------------------------
# RecoveryRunbook — execute
# ---------------------------------------------------------------------------


class TestRecoveryRunbookExecute:
    async def test_execute_automated_step(self) -> None:
        rb = RecoveryRunbook("rb", "scenario")

        async def my_task() -> str:
            return "done"

        rb.add_step(RecoveryStep(
            "auto_step",
            "description",
            step_type=StepType.AUTOMATED,
            executor=my_task,
        ))

        execution = await rb.execute()

        assert execution.status == RunbookStatus.COMPLETED
        assert execution.steps_completed == 1
        assert execution.steps_failed == 0

    async def test_execute_manual_step_is_skipped(self) -> None:
        rb = RecoveryRunbook("rb", "scenario")
        rb.add_step(RecoveryStep("manual_step", "human action", step_type=StepType.MANUAL))

        execution = await rb.execute()

        assert execution.steps_skipped == 1
        assert execution.status == RunbookStatus.PARTIAL
        assert any("manual_step" in n.upper() or "MANUAL" in n for n in execution.notes)

    async def test_execute_failed_critical_step_aborts(self) -> None:
        rb = RecoveryRunbook("rb", "scenario")

        async def failing_task() -> None:
            raise RuntimeError("boom")

        rb.add_step(RecoveryStep(
            "fail_step",
            "will fail",
            step_type=StepType.AUTOMATED,
            executor=failing_task,
            critical=True,
        ))
        rb.add_step(RecoveryStep(
            "next_step",
            "should not run",
            step_type=StepType.AUTOMATED,
            executor=lambda: "ok",
        ))

        execution = await rb.execute()

        assert execution.status == RunbookStatus.FAILED
        assert execution.steps_failed == 1
        # next_step should NOT have been attempted
        rb_steps = rb.steps
        assert rb_steps[1].status == StepStatus.PENDING

    async def test_execute_failed_non_critical_step_continues(self) -> None:
        rb = RecoveryRunbook("rb", "scenario")

        async def failing_task() -> None:
            raise RuntimeError("non-critical failure")

        async def ok_task() -> str:
            return "done"

        rb.add_step(RecoveryStep(
            "fail_step",
            "non-critical failure",
            step_type=StepType.AUTOMATED,
            executor=failing_task,
            critical=False,
        ))
        rb.add_step(RecoveryStep(
            "ok_step",
            "should run",
            step_type=StepType.AUTOMATED,
            executor=ok_task,
        ))

        execution = await rb.execute()

        assert execution.steps_failed == 1
        assert execution.steps_completed == 1
        assert execution.status == RunbookStatus.PARTIAL

    async def test_execute_stores_execution(self) -> None:
        rb = RecoveryRunbook("rb", "scenario")
        execution = await rb.execute()

        assert len(rb.get_executions()) == 1
        assert rb.get_executions()[0].execution_id == execution.execution_id

    async def test_execute_sets_runbook_name(self) -> None:
        rb = RecoveryRunbook("my_runbook", "my_scenario")
        execution = await rb.execute()
        assert execution.runbook_name == "my_runbook"
        assert execution.scenario == "my_scenario"

    async def test_execute_sets_timestamps(self) -> None:
        rb = RecoveryRunbook("rb", "s")
        execution = await rb.execute()
        assert execution.started_utc is not None
        assert execution.completed_utc is not None

    async def test_execute_sync_executor(self) -> None:
        rb = RecoveryRunbook("rb", "scenario")

        def sync_task() -> str:
            return "sync_done"

        rb.add_step(RecoveryStep(
            "sync_step",
            "sync executor",
            step_type=StepType.AUTOMATED,
            executor=sync_task,
        ))

        execution = await rb.execute()
        assert execution.steps_completed == 1


# ---------------------------------------------------------------------------
# Pre-built runbooks
# ---------------------------------------------------------------------------


class TestPreBuiltRunbooks:
    def test_neo4j_failover_runbook(self) -> None:
        rb = build_neo4j_failover_runbook()
        assert rb.name == "neo4j_primary_failover"
        assert rb.step_count() >= 4

    def test_neo4j_failover_runbook_has_verification_steps(self) -> None:
        rb = build_neo4j_failover_runbook()
        verification_steps = [
            s for s in rb.steps if s.step_type == StepType.VERIFICATION
        ]
        assert len(verification_steps) >= 1

    def test_redis_failover_runbook(self) -> None:
        rb = build_redis_failover_runbook()
        assert rb.name == "redis_primary_failover"
        assert rb.step_count() >= 3

    def test_kafka_recovery_runbook(self) -> None:
        rb = build_kafka_recovery_runbook()
        assert rb.name == "kafka_broker_recovery"
        assert rb.step_count() >= 4

    def test_full_recovery_guide_has_all_runbooks(self) -> None:
        guide = build_full_recovery_guide()
        assert "neo4j_primary_failover" in guide
        assert "redis_primary_failover" in guide
        assert "kafka_broker_recovery" in guide

    def test_all_runbooks_have_steps(self) -> None:
        guide = build_full_recovery_guide()
        for name, rb in guide.items():
            assert rb.step_count() > 0, f"{name} has no steps"

    def test_estimated_duration_is_positive(self) -> None:
        for rb in build_full_recovery_guide().values():
            assert rb.estimated_total_seconds() > 0
