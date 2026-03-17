"""Async background job runner."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import structlog

from summer_puppy.scheduler.models import JobResult, ScheduledJob

logger = structlog.get_logger()

JobHandler = Callable[[], Awaitable[int]]  # returns records_affected


class AsyncJobRunner:
    """Polls registered jobs and executes them when their interval has elapsed."""

    def __init__(self) -> None:
        self._jobs: dict[str, tuple[ScheduledJob, JobHandler]] = {}
        self._results: list[JobResult] = []
        self._task: asyncio.Task[None] | None = None

    def add_job(self, job: ScheduledJob, handler: JobHandler) -> None:
        """Register a job. Sets next_run_utc to now so it runs at first opportunity."""
        now = datetime.now(tz=UTC)
        job = job.model_copy(update={"next_run_utc": now})
        self._jobs[job.job_id] = (job, handler)

    def get_jobs(self) -> list[ScheduledJob]:
        """Return all registered jobs."""
        return [j for j, _ in self._jobs.values()]

    def get_last_results(self) -> list[JobResult]:
        """Return up to the last 50 job results."""
        return list(self._results[-50:])

    async def start(self) -> None:
        """Start the background polling loop."""
        self._task = asyncio.create_task(self._poll_loop())

    async def stop(self) -> None:
        """Cancel the polling loop and wait for it to terminate."""
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def _poll_loop(self) -> None:
        while True:
            await asyncio.sleep(1)
            now = datetime.now(tz=UTC)
            for job_id, (job, handler) in list(self._jobs.items()):
                if not job.enabled:
                    continue
                if job.next_run_utc is not None and now < job.next_run_utc:
                    continue
                await self._run_job(job_id, job, handler)

    async def _run_job(self, job_id: str, job: ScheduledJob, handler: JobHandler) -> None:
        """Execute a single job and record the result."""
        started = datetime.now(tz=UTC)
        try:
            records = await handler()
            completed = datetime.now(tz=UTC)
            result = JobResult(
                job_id=job_id,
                started_utc=started,
                completed_utc=completed,
                success=True,
                records_affected=records,
            )
            logger.info("scheduler_job_completed", job_name=job.name, records=records)
        except Exception as exc:
            completed = datetime.now(tz=UTC)
            result = JobResult(
                job_id=job_id,
                started_utc=started,
                completed_utc=completed,
                success=False,
                error=str(exc),
            )
            logger.error("scheduler_job_failed", job_name=job.name, error=str(exc))
        self._results.append(result)
        next_run = datetime.now(tz=UTC) + timedelta(seconds=job.interval_seconds)
        updated_job = job.model_copy(update={"last_run_utc": started, "next_run_utc": next_run})
        self._jobs[job_id] = (updated_job, handler)
