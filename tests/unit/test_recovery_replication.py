"""Unit tests for replication configuration (Phase 12)."""

from __future__ import annotations

import pytest

from summer_puppy.recovery.replication import (
    ConsistencyLevel,
    KafkaReplicationConfig,
    Neo4jReplicationConfig,
    RedisReplicationConfig,
    ReplicaConfig,
    ReplicationConfig,
    ReplicationMode,
)


class TestReplicationMode:
    def test_values(self) -> None:
        assert ReplicationMode.SYNCHRONOUS == "synchronous"
        assert ReplicationMode.ASYNCHRONOUS == "asynchronous"
        assert ReplicationMode.SEMI_SYNCHRONOUS == "semi_synchronous"


class TestConsistencyLevel:
    def test_values(self) -> None:
        assert ConsistencyLevel.STRONG == "strong"
        assert ConsistencyLevel.EVENTUAL == "eventual"
        assert ConsistencyLevel.BOUNDED_STALENESS == "bounded_staleness"


class TestReplicaConfig:
    def test_defaults(self) -> None:
        r = ReplicaConfig(host="replica-1", port=7687)
        assert r.region == "us-east-1"
        assert r.is_read_replica is True
        assert r.replication_lag_max_ms == 1000

    def test_custom_values(self) -> None:
        r = ReplicaConfig(host="replica-eu", port=7687, region="eu-west-1")
        assert r.region == "eu-west-1"


class TestNeo4jReplicationConfig:
    def test_defaults(self) -> None:
        cfg = Neo4jReplicationConfig()
        assert cfg.core_cluster_size == 3
        assert cfg.causal_consistency is True
        assert cfg.mode == ReplicationMode.SYNCHRONOUS
        assert cfg.consistency == ConsistencyLevel.STRONG

    def test_valid_cluster_size_3(self) -> None:
        cfg = Neo4jReplicationConfig(core_cluster_size=3)
        assert cfg.validate() == []

    def test_valid_cluster_size_5(self) -> None:
        cfg = Neo4jReplicationConfig(core_cluster_size=5)
        assert cfg.validate() == []

    def test_even_cluster_size_invalid(self) -> None:
        cfg = Neo4jReplicationConfig(core_cluster_size=4)
        errors = cfg.validate()
        assert any("odd" in e for e in errors)

    def test_cluster_size_2_invalid(self) -> None:
        cfg = Neo4jReplicationConfig(core_cluster_size=2)
        errors = cfg.validate()
        # Both odd (2 is even actually — but let's test size < 3)
        assert len(errors) >= 1

    def test_cluster_size_1_invalid(self) -> None:
        cfg = Neo4jReplicationConfig(core_cluster_size=1)
        errors = cfg.validate()
        assert any("fault tolerance" in e or "odd" in e or ">= 3" in e for e in errors)


class TestRedisReplicationConfig:
    def test_defaults(self) -> None:
        cfg = RedisReplicationConfig()
        assert cfg.replica_count == 2
        assert cfg.mode == ReplicationMode.ASYNCHRONOUS
        assert cfg.use_sentinel is True
        assert cfg.sentinel_quorum == 2

    def test_valid_config(self) -> None:
        cfg = RedisReplicationConfig(replica_count=2, sentinel_quorum=2)
        assert cfg.validate() == []

    def test_zero_replicas_invalid(self) -> None:
        cfg = RedisReplicationConfig(replica_count=0)
        errors = cfg.validate()
        assert any("replica_count" in e for e in errors)

    def test_sentinel_quorum_too_high(self) -> None:
        cfg = RedisReplicationConfig(replica_count=1, sentinel_quorum=5)
        errors = cfg.validate()
        assert any("quorum" in e for e in errors)


class TestKafkaReplicationConfig:
    def test_defaults(self) -> None:
        cfg = KafkaReplicationConfig()
        assert cfg.default_replication_factor == 3
        assert cfg.min_insync_replicas == 2
        assert cfg.unclean_leader_election is False
        assert cfg.default_retention_ms == 604_800_000
        assert cfg.audit_retention_ms == 2_592_000_000

    def test_valid_config(self) -> None:
        cfg = KafkaReplicationConfig(
            default_replication_factor=3, min_insync_replicas=2
        )
        assert cfg.validate() == []

    def test_min_insync_replicas_equals_factor_invalid(self) -> None:
        cfg = KafkaReplicationConfig(
            default_replication_factor=3, min_insync_replicas=3
        )
        errors = cfg.validate()
        assert any("min_insync" in e for e in errors)

    def test_single_replica_invalid(self) -> None:
        cfg = KafkaReplicationConfig(default_replication_factor=1)
        errors = cfg.validate()
        assert any("fault tolerance" in e for e in errors)

    def test_audit_retention_longer_than_default(self) -> None:
        cfg = KafkaReplicationConfig()
        assert cfg.audit_retention_ms > cfg.default_retention_ms


class TestReplicationConfig:
    def test_all_valid_by_default(self) -> None:
        cfg = ReplicationConfig()
        assert cfg.is_valid() is True

    def test_validate_all_returns_per_store_errors(self) -> None:
        cfg = ReplicationConfig()
        errors = cfg.validate_all()
        assert "neo4j" in errors
        assert "redis" in errors
        assert "kafka" in errors

    def test_invalid_config_fails_is_valid(self) -> None:
        cfg = ReplicationConfig(
            neo4j=Neo4jReplicationConfig(core_cluster_size=2)  # invalid (even)
        )
        assert cfg.is_valid() is False

    def test_validate_all_empty_when_valid(self) -> None:
        cfg = ReplicationConfig()
        errors = cfg.validate_all()
        for store, errs in errors.items():
            assert errs == [], f"{store} has unexpected errors: {errs}"
