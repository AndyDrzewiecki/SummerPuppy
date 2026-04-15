"""Unit tests for backup strategy (Phase 12)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from summer_puppy.recovery.backup import (
    BackupConfig,
    BackupJob,
    BackupScheduler,
    BackupStatus,
    BackupTarget,
)


class TestBackupConfig:
    def test_defaults(self) -> None:
        cfg = BackupConfig()
        assert cfg.output_dir == "/var/backups/summer-puppy"
        assert cfg.retention_count == 7
        assert cfg.compress is True
        assert cfg.neo4j_uri == "bolt://localhost:7687"
        assert cfg.redis_host == "localhost"
        assert cfg.kafka_bootstrap == "localhost:9092"

    def test_custom_values(self) -> None:
        cfg = BackupConfig(
            output_dir="/tmp/backups",
            retention_count=3,
            neo4j_uri="bolt://prod:7687",
        )
        assert cfg.output_dir == "/tmp/backups"
        assert cfg.retention_count == 3
        assert cfg.neo4j_uri == "bolt://prod:7687"


class TestBackupJob:
    def test_defaults(self) -> None:
        job = BackupJob(target=BackupTarget.NEO4J)
        assert job.status == BackupStatus.PENDING
        assert job.started_utc is None
        assert job.completed_utc is None
        assert job.output_path is None
        assert job.error is None

    def test_job_id_auto_generated(self) -> None:
        j1 = BackupJob(target=BackupTarget.NEO4J)
        j2 = BackupJob(target=BackupTarget.NEO4J)
        assert j1.job_id != j2.job_id

    def test_duration_seconds_none_when_not_complete(self) -> None:
        job = BackupJob(target=BackupTarget.NEO4J)
        assert job.duration_seconds is None

    def test_duration_seconds_calculated(self) -> None:
        from datetime import UTC, datetime, timedelta

        job = BackupJob(target=BackupTarget.NEO4J)
        now = datetime.now(tz=UTC)
        job.started_utc = now
        job.completed_utc = now + timedelta(seconds=5)
        assert job.duration_seconds == pytest.approx(5.0, abs=0.01)


class TestBackupScheduler:
    def test_init(self) -> None:
        sched = BackupScheduler(BackupConfig())
        assert sched.get_history() == []

    async def test_backup_neo4j_success(self) -> None:
        sched = BackupScheduler(BackupConfig(output_dir="/tmp/test"))

        mock_driver = AsyncMock()
        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        mock_result = AsyncMock()
        mock_result.data = AsyncMock(return_value=[])
        mock_session.run = AsyncMock(return_value=mock_result)
        mock_driver.session = MagicMock(return_value=mock_session)

        with patch("builtins.open", MagicMock()), patch("os.makedirs"):
            job = await sched.backup_neo4j(mock_driver)

        assert job.status == BackupStatus.SUCCESS
        assert job.target == BackupTarget.NEO4J
        assert job.completed_utc is not None

    async def test_backup_neo4j_failure(self) -> None:
        sched = BackupScheduler(BackupConfig())

        mock_driver = AsyncMock()
        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        mock_session.run = AsyncMock(side_effect=Exception("connection_refused"))
        mock_driver.session = MagicMock(return_value=mock_session)

        job = await sched.backup_neo4j(mock_driver)

        assert job.status == BackupStatus.FAILED
        assert job.error is not None

    async def test_backup_redis_success(self) -> None:
        sched = BackupScheduler(BackupConfig(output_dir="/tmp/test"))
        mock_redis = AsyncMock()
        mock_redis.bgsave = AsyncMock()

        job = await sched.backup_redis(mock_redis)

        assert job.status == BackupStatus.SUCCESS
        assert job.target == BackupTarget.REDIS
        mock_redis.bgsave.assert_called_once()

    async def test_backup_redis_failure(self) -> None:
        sched = BackupScheduler(BackupConfig())
        mock_redis = AsyncMock()
        mock_redis.bgsave = AsyncMock(side_effect=Exception("redis_unavailable"))

        job = await sched.backup_redis(mock_redis)

        assert job.status == BackupStatus.FAILED
        assert "redis_unavailable" in (job.error or "")

    async def test_checkpoint_kafka_offsets_success(self) -> None:
        sched = BackupScheduler(BackupConfig(kafka_consumer_groups=["grp-1", "grp-2"]))
        mock_coord = MagicMock()
        mock_coord.get_consumer_lag.return_value = {"SECURITY_EVENTS:0": 100}

        job = await sched.checkpoint_kafka_offsets(mock_coord)

        assert job.status == BackupStatus.SUCCESS
        assert job.target == BackupTarget.KAFKA_OFFSETS
        assert "offsets" in job.metadata
        assert "grp-1" in job.metadata["offsets"]

    async def test_checkpoint_kafka_offsets_failure(self) -> None:
        sched = BackupScheduler(BackupConfig(kafka_consumer_groups=["grp-1"]))
        mock_coord = MagicMock()
        mock_coord.get_consumer_lag.side_effect = Exception("broker_unreachable")

        job = await sched.checkpoint_kafka_offsets(mock_coord)

        assert job.status == BackupStatus.FAILED

    def test_get_history_returns_all(self) -> None:
        sched = BackupScheduler(BackupConfig())
        job1 = BackupJob(target=BackupTarget.NEO4J, status=BackupStatus.SUCCESS)
        job2 = BackupJob(target=BackupTarget.REDIS, status=BackupStatus.FAILED)
        sched._history.extend([job1, job2])

        assert len(sched.get_history()) == 2

    def test_get_history_filtered_by_target(self) -> None:
        sched = BackupScheduler(BackupConfig())
        j1 = BackupJob(target=BackupTarget.NEO4J, status=BackupStatus.SUCCESS)
        j2 = BackupJob(target=BackupTarget.REDIS, status=BackupStatus.SUCCESS)
        sched._history.extend([j1, j2])

        neo4j_history = sched.get_history(target=BackupTarget.NEO4J)
        assert len(neo4j_history) == 1
        assert neo4j_history[0].target == BackupTarget.NEO4J

    def test_get_history_filtered_by_status(self) -> None:
        sched = BackupScheduler(BackupConfig())
        j1 = BackupJob(target=BackupTarget.NEO4J, status=BackupStatus.SUCCESS)
        j2 = BackupJob(target=BackupTarget.NEO4J, status=BackupStatus.FAILED)
        sched._history.extend([j1, j2])

        successful = sched.get_history(status=BackupStatus.SUCCESS)
        assert len(successful) == 1

    def test_last_successful_backup_returns_latest(self) -> None:
        from datetime import UTC, datetime, timedelta

        sched = BackupScheduler(BackupConfig())
        j1 = BackupJob(
            target=BackupTarget.NEO4J,
            status=BackupStatus.SUCCESS,
            completed_utc=datetime.now(tz=UTC) - timedelta(hours=1),
        )
        j2 = BackupJob(
            target=BackupTarget.NEO4J,
            status=BackupStatus.SUCCESS,
            completed_utc=datetime.now(tz=UTC),
        )
        sched._history.extend([j1, j2])

        last = sched.last_successful_backup(BackupTarget.NEO4J)
        assert last is j2

    def test_last_successful_backup_returns_none_when_no_success(self) -> None:
        sched = BackupScheduler(BackupConfig())
        assert sched.last_successful_backup(BackupTarget.NEO4J) is None

    def test_prune_old_backups_removes_excess(self) -> None:
        cfg = BackupConfig(retention_count=3)
        sched = BackupScheduler(cfg)
        for _ in range(5):
            sched._history.append(BackupJob(target=BackupTarget.NEO4J, status=BackupStatus.SUCCESS))

        removed = sched.prune_old_backups(BackupTarget.NEO4J)

        assert removed == 2
        assert len(sched.get_history(target=BackupTarget.NEO4J)) == 3

    def test_prune_old_backups_noop_when_under_limit(self) -> None:
        cfg = BackupConfig(retention_count=10)
        sched = BackupScheduler(cfg)
        sched._history.append(BackupJob(target=BackupTarget.NEO4J, status=BackupStatus.SUCCESS))

        removed = sched.prune_old_backups(BackupTarget.NEO4J)

        assert removed == 0
