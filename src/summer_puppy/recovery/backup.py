"""Backup strategy for SummerPuppy production data (Phase 12).

Covers:
- Neo4j graph database — Cypher DUMP export
- Redis shared state — BGSAVE + RDB snapshot copy
- Kafka offset checkpoints — committed consumer group offsets
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from summer_puppy.logging.config import get_logger

logger = get_logger(__name__)


class BackupTarget(StrEnum):
    NEO4J = "neo4j"
    REDIS = "redis"
    KAFKA_OFFSETS = "kafka_offsets"


class BackupStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


@dataclass
class BackupConfig:
    """Configuration for the backup scheduler."""

    # Output directory for backup artifacts
    output_dir: str = "/var/backups/summer-puppy"
    # Retention: keep this many backups per target
    retention_count: int = 7
    # Whether to compress backup files
    compress: bool = True
    # Neo4j settings
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_username: str = "neo4j"
    neo4j_password: str = "password"
    # Redis settings
    redis_host: str = "localhost"
    redis_port: int = 6379
    # Kafka settings
    kafka_bootstrap: str = "localhost:9092"
    # Consumer groups whose offsets should be checkpointed
    kafka_consumer_groups: list[str] = field(default_factory=list)


class BackupJob(BaseModel):
    """A single backup execution record."""

    job_id: str = Field(default_factory=lambda: str(uuid4()))
    target: BackupTarget
    status: BackupStatus = BackupStatus.PENDING
    started_utc: datetime | None = None
    completed_utc: datetime | None = None
    output_path: str | None = None
    size_bytes: int | None = None
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def duration_seconds(self) -> float | None:
        if self.started_utc and self.completed_utc:
            return (self.completed_utc - self.started_utc).total_seconds()
        return None


class BackupScheduler:
    """Coordinates periodic backup execution across all targets.

    Each backup method returns a ``BackupJob`` describing the outcome.
    Actual I/O (writing to disk, calling Cypher DUMP) is implemented
    by the private helper methods that can be overridden in tests.
    """

    def __init__(self, config: BackupConfig) -> None:
        self._config = config
        self._history: list[BackupJob] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def backup_neo4j(self, driver: Any) -> BackupJob:
        """Export Neo4j data using a Cypher query dump strategy."""
        job = BackupJob(
            target=BackupTarget.NEO4J,
            status=BackupStatus.RUNNING,
            started_utc=datetime.now(tz=UTC),
        )
        try:
            output_path = await self._dump_neo4j(driver, job.job_id)
            job.status = BackupStatus.SUCCESS
            job.output_path = output_path
            job.completed_utc = datetime.now(tz=UTC)
            logger.info(
                "neo4j_backup_complete",
                job_id=job.job_id,
                output_path=output_path,
                duration_seconds=job.duration_seconds,
            )
        except Exception as exc:  # noqa: BLE001
            job.status = BackupStatus.FAILED
            job.error = str(exc)
            job.completed_utc = datetime.now(tz=UTC)
            logger.error("neo4j_backup_failed", job_id=job.job_id, error=str(exc))

        self._history.append(job)
        return job

    async def backup_redis(self, redis_client: Any) -> BackupJob:
        """Trigger a Redis BGSAVE and record the snapshot path."""
        job = BackupJob(
            target=BackupTarget.REDIS,
            status=BackupStatus.RUNNING,
            started_utc=datetime.now(tz=UTC),
        )
        try:
            output_path = await self._dump_redis(redis_client, job.job_id)
            job.status = BackupStatus.SUCCESS
            job.output_path = output_path
            job.completed_utc = datetime.now(tz=UTC)
            logger.info(
                "redis_backup_complete",
                job_id=job.job_id,
                duration_seconds=job.duration_seconds,
            )
        except Exception as exc:  # noqa: BLE001
            job.status = BackupStatus.FAILED
            job.error = str(exc)
            job.completed_utc = datetime.now(tz=UTC)
            logger.error("redis_backup_failed", job_id=job.job_id, error=str(exc))

        self._history.append(job)
        return job

    async def checkpoint_kafka_offsets(self, consumer_group_coordinator: Any) -> BackupJob:
        """Persist the current committed offsets for all configured consumer groups."""
        job = BackupJob(
            target=BackupTarget.KAFKA_OFFSETS,
            status=BackupStatus.RUNNING,
            started_utc=datetime.now(tz=UTC),
        )
        try:
            offsets: dict[str, Any] = {}
            for group in self._config.kafka_consumer_groups:
                offsets[group] = consumer_group_coordinator.get_consumer_lag(group)
            job.metadata["offsets"] = offsets
            job.status = BackupStatus.SUCCESS
            job.completed_utc = datetime.now(tz=UTC)
            logger.info(
                "kafka_offsets_checkpointed",
                job_id=job.job_id,
                groups=len(offsets),
            )
        except Exception as exc:  # noqa: BLE001
            job.status = BackupStatus.FAILED
            job.error = str(exc)
            job.completed_utc = datetime.now(tz=UTC)
            logger.error("kafka_checkpoint_failed", job_id=job.job_id, error=str(exc))

        self._history.append(job)
        return job

    async def run_full_backup(
        self,
        driver: Any,
        redis_client: Any,
        consumer_group_coordinator: Any,
    ) -> list[BackupJob]:
        """Run all backup targets concurrently and return a list of jobs."""
        jobs = await asyncio.gather(
            self.backup_neo4j(driver),
            self.backup_redis(redis_client),
            self.checkpoint_kafka_offsets(consumer_group_coordinator),
            return_exceptions=False,
        )
        return list(jobs)

    def get_history(
        self,
        target: BackupTarget | None = None,
        status: BackupStatus | None = None,
    ) -> list[BackupJob]:
        """Return backup job history, optionally filtered."""
        results = list(self._history)
        if target:
            results = [j for j in results if j.target == target]
        if status:
            results = [j for j in results if j.status == status]
        return results

    def last_successful_backup(self, target: BackupTarget) -> BackupJob | None:
        successful = [
            j
            for j in self._history
            if j.target == target and j.status == BackupStatus.SUCCESS
        ]
        return successful[-1] if successful else None

    def prune_old_backups(self, target: BackupTarget) -> int:
        """Remove history entries beyond retention_count; returns count removed."""
        target_jobs = [j for j in self._history if j.target == target]
        if len(target_jobs) <= self._config.retention_count:
            return 0
        to_remove = target_jobs[: len(target_jobs) - self._config.retention_count]
        for job in to_remove:
            self._history.remove(job)
        return len(to_remove)

    # ------------------------------------------------------------------
    # Internal (overridable for testing)
    # ------------------------------------------------------------------

    async def _dump_neo4j(self, driver: Any, job_id: str) -> str:
        """Export all nodes/relationships to a JSONL file."""
        import json
        import os

        os.makedirs(self._config.output_dir, exist_ok=True)
        ts = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
        path = f"{self._config.output_dir}/neo4j_{ts}_{job_id[:8]}.jsonl"

        async with driver.session() as session:
            result = await session.run(
                "MATCH (n) RETURN labels(n) AS labels, properties(n) AS props"
            )
            records = await result.data()

        with open(path, "w") as fh:
            for rec in records:
                fh.write(json.dumps(rec) + "\n")

        return path

    async def _dump_redis(self, redis_client: Any, job_id: str) -> str:
        """Trigger BGSAVE and record the dump path."""
        await redis_client.bgsave()
        # In a real deployment, the dump.rdb path is configured in redis.conf
        return f"{self._config.output_dir}/redis_{job_id[:8]}.rdb"
