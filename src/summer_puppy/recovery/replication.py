"""Data replication configuration for SummerPuppy (Phase 12).

Documents and validates the replication topology for each data store.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class ReplicationMode(StrEnum):
    SYNCHRONOUS = "synchronous"
    ASYNCHRONOUS = "asynchronous"
    SEMI_SYNCHRONOUS = "semi_synchronous"


class ConsistencyLevel(StrEnum):
    """CAP-theorem consistency guarantees."""

    STRONG = "strong"          # All replicas must acknowledge
    EVENTUAL = "eventual"      # Asynchronous replication; reads may be stale
    BOUNDED_STALENESS = "bounded_staleness"  # Reads are stale by at most N ms


@dataclass
class ReplicaConfig:
    """Configuration for a single replica node."""

    host: str
    port: int
    region: str = "us-east-1"
    is_read_replica: bool = True
    replication_lag_max_ms: int = 1000


@dataclass
class Neo4jReplicationConfig:
    """Neo4j causal clustering / read replica configuration."""

    # Core cluster size (must be odd: 3 or 5)
    core_cluster_size: int = 3
    # Read replicas for scaling reads
    read_replicas: list[ReplicaConfig] = field(default_factory=list)
    # Causal consistency: routes read transactions to up-to-date replicas
    causal_consistency: bool = True
    mode: ReplicationMode = ReplicationMode.SYNCHRONOUS
    consistency: ConsistencyLevel = ConsistencyLevel.STRONG

    def validate(self) -> list[str]:
        """Return a list of validation errors (empty = valid)."""
        errors: list[str] = []
        if self.core_cluster_size % 2 == 0:
            errors.append(
                f"core_cluster_size must be odd, got {self.core_cluster_size}"
            )
        if self.core_cluster_size < 3:
            errors.append(
                f"core_cluster_size must be >= 3 for fault tolerance, got {self.core_cluster_size}"
            )
        return errors


@dataclass
class RedisReplicationConfig:
    """Redis replication configuration (replica-of pattern)."""

    # Number of replica nodes
    replica_count: int = 2
    replicas: list[ReplicaConfig] = field(default_factory=list)
    mode: ReplicationMode = ReplicationMode.ASYNCHRONOUS
    # Minimum number of replicas that must acknowledge a write
    min_replicas_to_write: int = 1
    # Maximum replication lag before write is rejected (ms)
    min_replicas_max_lag_ms: int = 10000
    # Sentinel for automatic failover
    use_sentinel: bool = True
    sentinel_quorum: int = 2

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.replica_count < 1:
            errors.append("replica_count must be >= 1")
        if self.use_sentinel and self.sentinel_quorum > self.replica_count + 1:
            errors.append(
                f"sentinel_quorum ({self.sentinel_quorum}) exceeds available nodes "
                f"({self.replica_count + 1})"
            )
        return errors


@dataclass
class KafkaReplicationConfig:
    """Kafka topic replication configuration."""

    # Default replication factor for all topics
    default_replication_factor: int = 3
    # Minimum in-sync replicas (messages must be written to this many before ACK)
    min_insync_replicas: int = 2
    # Whether to enable unclean leader election (false = safer, may lose availability)
    unclean_leader_election: bool = False
    # Retention settings
    default_retention_ms: int = 604_800_000  # 7 days
    audit_retention_ms: int = 2_592_000_000  # 30 days

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.min_insync_replicas >= self.default_replication_factor:
            errors.append(
                f"min_insync_replicas ({self.min_insync_replicas}) must be "
                f"< replication_factor ({self.default_replication_factor})"
            )
        if self.default_replication_factor < 2:
            errors.append("default_replication_factor must be >= 2 for fault tolerance")
        return errors


@dataclass
class ReplicationConfig:
    """Aggregated replication configuration for all data stores."""

    neo4j: Neo4jReplicationConfig = field(default_factory=Neo4jReplicationConfig)
    redis: RedisReplicationConfig = field(default_factory=RedisReplicationConfig)
    kafka: KafkaReplicationConfig = field(default_factory=KafkaReplicationConfig)

    def validate_all(self) -> dict[str, list[str]]:
        """Return {store: [errors]} for each data store with validation errors."""
        return {
            "neo4j": self.neo4j.validate(),
            "redis": self.redis.validate(),
            "kafka": self.kafka.validate(),
        }

    def is_valid(self) -> bool:
        """Return True if all stores pass validation."""
        return all(not errs for errs in self.validate_all().values())
