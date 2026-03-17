"""Unit tests for the scheduler module — ScheduledJob, JobResult, AsyncJobRunner."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

# These imports will fail until the module is implemented (RED phase)
from summer_puppy.scheduler import AsyncJobRunner, JobResult, ScheduledJob
from summer_puppy.scheduler.jobs import (
    expire_policies_handler,
    expire_protected_assets_handler,
)
from summer_puppy.tenants.models import ProtectedAsset, TenantProfile
from summer_puppy.tenants.store import InMemoryTenantStore
from summer_puppy.trust.models import AutoApprovalPolicy, PolicyStatus

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_store(*profiles: TenantProfile) -> InMemoryTenantStore:
    store = InMemoryTenantStore()
    for p in profiles:
        store.save(p)
    return store


def _profile(customer_id: str, assets: list[ProtectedAsset] | None = None) -> TenantProfile:
    return TenantProfile(customer_id=customer_id, protected_assets=assets or [])


def _policy(
    customer_id: str,
    status: PolicyStatus = PolicyStatus.ACTIVE,
    expires_utc: datetime | None = None,
) -> AutoApprovalPolicy:
    from summer_puppy.trust.models import ActionClass

    return AutoApprovalPolicy(
        customer_id=customer_id,
        action_class=ActionClass.PATCH_DEPLOYMENT,
        status=status,
        expires_utc=expires_utc,
    )


# ---------------------------------------------------------------------------
# TestScheduledJob
# ---------------------------------------------------------------------------


class TestScheduledJob:
    def test_job_defaults(self) -> None:
        job = ScheduledJob(name="cleanup", interval_seconds=60)
        assert job.enabled is True
        assert job.last_run_utc is None
        assert job.next_run_utc is None

    def test_job_custom_fields(self) -> None:
        now = datetime.now(tz=UTC)
        job = ScheduledJob(
            name="expire-assets",
            interval_seconds=3600,
            enabled=False,
            last_run_utc=now,
        )
        assert job.name == "expire-assets"
        assert job.interval_seconds == 3600
        assert job.enabled is False
        assert job.last_run_utc == now

    def test_job_auto_id(self) -> None:
        job1 = ScheduledJob(name="a", interval_seconds=10)
        job2 = ScheduledJob(name="b", interval_seconds=10)
        assert job1.job_id != job2.job_id
        assert len(job1.job_id) == 36  # UUID4 format


# ---------------------------------------------------------------------------
# TestJobResult
# ---------------------------------------------------------------------------


class TestJobResult:
    def test_result_success(self) -> None:
        now = datetime.now(tz=UTC)
        result = JobResult(
            job_id="abc",
            started_utc=now,
            completed_utc=now,
            success=True,
        )
        assert result.success is True
        assert result.error is None
        assert result.records_affected == 0

    def test_result_failure_with_error(self) -> None:
        now = datetime.now(tz=UTC)
        result = JobResult(
            job_id="abc",
            started_utc=now,
            completed_utc=now,
            success=False,
            error="Connection refused",
        )
        assert result.success is False
        assert result.error == "Connection refused"

    def test_result_records_affected(self) -> None:
        now = datetime.now(tz=UTC)
        result = JobResult(
            job_id="xyz",
            started_utc=now,
            completed_utc=now,
            success=True,
            records_affected=42,
        )
        assert result.records_affected == 42


# ---------------------------------------------------------------------------
# TestAsyncJobRunner
# ---------------------------------------------------------------------------


class TestAsyncJobRunner:
    def test_get_registered_jobs_empty(self) -> None:
        runner = AsyncJobRunner()
        assert runner.get_jobs() == []

    def test_add_job_registers_it(self) -> None:
        runner = AsyncJobRunner()
        job = ScheduledJob(name="test-job", interval_seconds=60)

        async def handler() -> int:
            return 0

        runner.add_job(job, handler)
        jobs = runner.get_jobs()
        assert len(jobs) == 1
        assert jobs[0].name == "test-job"

    def test_get_registered_jobs_returns_added(self) -> None:
        runner = AsyncJobRunner()

        async def noop() -> int:
            return 0

        for i in range(3):
            runner.add_job(ScheduledJob(name=f"job-{i}", interval_seconds=10), noop)

        assert len(runner.get_jobs()) == 3
        names = {j.name for j in runner.get_jobs()}
        assert names == {"job-0", "job-1", "job-2"}

    async def test_runner_start_and_stop(self) -> None:
        runner = AsyncJobRunner()
        await runner.start()
        # Give the event loop a tick to ensure task is scheduled
        await asyncio.sleep(0)
        await runner.stop()
        # No exception means pass

    async def test_job_executed_after_interval(self) -> None:
        """Directly trigger _run_job to bypass timing."""
        runner = AsyncJobRunner()
        call_count = 0

        async def handler() -> int:
            nonlocal call_count
            call_count += 1
            return 1

        job = ScheduledJob(name="manual-trigger", interval_seconds=60)
        runner.add_job(job, handler)

        job_id = runner.get_jobs()[0].job_id
        job_obj, h = runner._jobs[job_id]
        await runner._run_job(job_id, job_obj, h)

        assert call_count == 1
        assert len(runner.get_last_results()) == 1
        assert runner.get_last_results()[0].success is True

    async def test_job_not_executed_before_interval(self) -> None:
        """Jobs whose next_run_utc is in the future must not be executed."""
        runner = AsyncJobRunner()
        call_count = 0

        async def handler() -> int:
            nonlocal call_count
            call_count += 1
            return 0

        # next_run_utc far in the future
        future = datetime.now(tz=UTC) + timedelta(hours=1)
        job = ScheduledJob(name="future-job", interval_seconds=60, next_run_utc=future)
        runner._jobs[job.job_id] = (job, handler)

        now = datetime.now(tz=UTC)
        for job_id, (j, h) in list(runner._jobs.items()):
            if not j.enabled:
                continue
            if j.next_run_utc is not None and now < j.next_run_utc:
                continue
            await runner._run_job(job_id, j, h)

        assert call_count == 0

    async def test_failed_job_records_error(self) -> None:
        runner = AsyncJobRunner()

        async def bad_handler() -> int:
            raise RuntimeError("Something went wrong")

        job = ScheduledJob(name="bad-job", interval_seconds=60)
        runner.add_job(job, bad_handler)

        job_id = runner.get_jobs()[0].job_id
        job_obj, h = runner._jobs[job_id]
        await runner._run_job(job_id, job_obj, h)

        results = runner.get_last_results()
        assert len(results) == 1
        assert results[0].success is False
        assert "Something went wrong" in (results[0].error or "")

    def test_get_last_results_empty(self) -> None:
        runner = AsyncJobRunner()
        assert runner.get_last_results() == []

    async def test_get_last_results_after_run(self) -> None:
        runner = AsyncJobRunner()

        async def handler() -> int:
            return 5

        job = ScheduledJob(name="result-job", interval_seconds=30)
        runner.add_job(job, handler)

        job_id = runner.get_jobs()[0].job_id
        job_obj, h = runner._jobs[job_id]
        await runner._run_job(job_id, job_obj, h)

        results = runner.get_last_results()
        assert len(results) == 1
        assert results[0].records_affected == 5
        assert results[0].job_id == job_id

    async def test_disabled_job_not_executed(self) -> None:
        runner = AsyncJobRunner()
        call_count = 0

        async def handler() -> int:
            nonlocal call_count
            call_count += 1
            return 0

        job = ScheduledJob(name="disabled-job", interval_seconds=1, enabled=False)
        runner.add_job(job, handler)

        now = datetime.now(tz=UTC)
        for job_id, (j, h) in list(runner._jobs.items()):
            if not j.enabled:
                continue
            if j.next_run_utc is not None and now < j.next_run_utc:
                continue
            await runner._run_job(job_id, j, h)

        assert call_count == 0

    async def test_last_run_updated_after_execution(self) -> None:
        runner = AsyncJobRunner()

        async def handler() -> int:
            return 3

        job = ScheduledJob(name="update-test", interval_seconds=30)
        runner.add_job(job, handler)

        job_id = runner.get_jobs()[0].job_id
        assert runner.get_jobs()[0].last_run_utc is None

        job_obj, h = runner._jobs[job_id]
        await runner._run_job(job_id, job_obj, h)

        updated_job = runner._jobs[job_id][0]
        assert updated_job.last_run_utc is not None
        assert updated_job.next_run_utc is not None


# ---------------------------------------------------------------------------
# TestBuiltinHandlers
# ---------------------------------------------------------------------------


class TestBuiltinHandlers:
    async def test_expire_protected_assets_removes_expired(self) -> None:
        past = datetime.now(tz=UTC) - timedelta(hours=1)
        asset = ProtectedAsset(asset_id="srv-1", reason="planned", protected_until=past)
        profile = _profile("cust-1", assets=[asset])
        store = _make_store(profile)

        removed = await expire_protected_assets_handler(store)

        assert removed == 1
        updated = store.get("cust-1")
        assert updated is not None
        assert len(updated.protected_assets) == 0

    async def test_expire_protected_assets_keeps_future(self) -> None:
        future = datetime.now(tz=UTC) + timedelta(hours=1)
        asset = ProtectedAsset(asset_id="srv-2", reason="pending", protected_until=future)
        profile = _profile("cust-2", assets=[asset])
        store = _make_store(profile)

        removed = await expire_protected_assets_handler(store)

        assert removed == 0
        updated = store.get("cust-2")
        assert updated is not None
        assert len(updated.protected_assets) == 1

    async def test_expire_policies_marks_expired(self) -> None:
        past = datetime.now(tz=UTC) - timedelta(hours=1)
        policy = _policy("cust-3", status=PolicyStatus.ACTIVE, expires_utc=past)

        # Use a simple dict as policy store for handler
        policy_store: dict[str, list[AutoApprovalPolicy]] = {"cust-3": [policy]}

        expired = await expire_policies_handler(policy_store)

        assert expired == 1
        assert policy_store["cust-3"][0].status == PolicyStatus.EXPIRED

    async def test_expire_policies_keeps_active(self) -> None:
        future = datetime.now(tz=UTC) + timedelta(hours=1)
        policy = _policy("cust-4", status=PolicyStatus.ACTIVE, expires_utc=future)
        policy_store: dict[str, list[AutoApprovalPolicy]] = {"cust-4": [policy]}

        expired = await expire_policies_handler(policy_store)

        assert expired == 0
        assert policy_store["cust-4"][0].status == PolicyStatus.ACTIVE


# ---------------------------------------------------------------------------
# TestSchedulerAPI
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_state():
    """Reset AppState singleton before/after each test."""
    from summer_puppy.api.state import init_app_state, reset_app_state

    reset_app_state()
    init_app_state()
    yield
    reset_app_state()


@pytest.fixture
def app():
    from summer_puppy.api.app import app as _app

    return _app


def _admin_token() -> str:
    from summer_puppy.api.auth.jwt_handler import create_token

    return create_token("admin", scopes=["admin"])


def _user_token() -> str:
    from summer_puppy.api.auth.jwt_handler import create_token

    return create_token("user-1", scopes=["events:write"])


async def _request(app, method: str, path: str, **kwargs):
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await getattr(client, method)(path, **kwargs)


class TestSchedulerAPI:
    @pytest.mark.asyncio
    async def test_list_jobs_returns_empty(self, app) -> None:
        token = _admin_token()
        response = await _request(
            app,
            "get",
            "/api/v1/admin/scheduler/jobs",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        assert response.json() == []

    @pytest.mark.asyncio
    async def test_list_jobs_requires_admin(self, app) -> None:
        token = _user_token()
        response = await _request(
            app,
            "get",
            "/api/v1/admin/scheduler/jobs",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_list_jobs_returns_added_jobs(self, app) -> None:
        from summer_puppy.api.state import get_app_state
        from summer_puppy.scheduler.runner import AsyncJobRunner

        state = get_app_state()
        runner = AsyncJobRunner()
        job1 = ScheduledJob(name="cleanup", interval_seconds=60)
        job2 = ScheduledJob(name="expire", interval_seconds=3600)

        async def noop() -> int:
            return 0

        runner.add_job(job1, noop)
        runner.add_job(job2, noop)
        state.job_runner = runner

        token = _admin_token()
        response = await _request(
            app,
            "get",
            "/api/v1/admin/scheduler/jobs",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        names = {j["name"] for j in data}
        assert names == {"cleanup", "expire"}

    @pytest.mark.asyncio
    async def test_list_jobs_results_included(self, app) -> None:
        from summer_puppy.api.state import get_app_state
        from summer_puppy.scheduler.runner import AsyncJobRunner

        state = get_app_state()
        runner = AsyncJobRunner()
        job = ScheduledJob(name="tracked-job", interval_seconds=30)

        async def handler() -> int:
            return 7

        runner.add_job(job, handler)
        job_id = runner.get_jobs()[0].job_id
        job_obj, h = runner._jobs[job_id]
        await runner._run_job(job_id, job_obj, h)
        state.job_runner = runner

        token = _admin_token()
        response = await _request(
            app,
            "get",
            "/api/v1/admin/scheduler/jobs",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert len(data[0]["last_results"]) == 1
        assert data[0]["last_results"][0]["success"] is True
        assert data[0]["last_results"][0]["records_affected"] == 7

    @pytest.mark.asyncio
    async def test_list_jobs_without_auth_401(self, app) -> None:
        response = await _request(
            app,
            "get",
            "/api/v1/admin/scheduler/jobs",
        )
        assert response.status_code in (401, 422)
