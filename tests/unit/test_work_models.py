from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from summer_puppy.work.models import (
    Artifact,
    ArtifactType,
    Decision,
    DecisionType,
    Reasoning,
    ValidationStatus,
    WorkItem,
    WorkItemPriority,
    WorkItemStatus,
    WorkItemType,
)

# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------


class TestWorkItemType:
    def test_enum_values(self) -> None:
        assert WorkItemType.THREAT_REPORT == "THREAT_REPORT"
        assert WorkItemType.PATCH_REQUEST == "PATCH_REQUEST"
        assert WorkItemType.DETECTION_RULE == "DETECTION_RULE"
        assert WorkItemType.INCIDENT_REPORT == "INCIDENT_REPORT"
        assert WorkItemType.VULNERABILITY_ASSESSMENT == "VULNERABILITY_ASSESSMENT"
        assert WorkItemType.SECURITY_ADVISORY == "SECURITY_ADVISORY"

    def test_member_count(self) -> None:
        assert len(WorkItemType) == 6


class TestWorkItemStatus:
    def test_enum_values(self) -> None:
        assert WorkItemStatus.DRAFT == "DRAFT"
        assert WorkItemStatus.SUBMITTED == "SUBMITTED"
        assert WorkItemStatus.ACCEPTED == "ACCEPTED"
        assert WorkItemStatus.IN_PROGRESS == "IN_PROGRESS"
        assert WorkItemStatus.REVIEW == "REVIEW"
        assert WorkItemStatus.COMPLETED == "COMPLETED"
        assert WorkItemStatus.REJECTED == "REJECTED"

    def test_member_count(self) -> None:
        assert len(WorkItemStatus) == 7


class TestWorkItemPriority:
    def test_enum_values(self) -> None:
        assert WorkItemPriority.P0_CRITICAL == "P0_CRITICAL"
        assert WorkItemPriority.P1_HIGH == "P1_HIGH"
        assert WorkItemPriority.P2_MEDIUM == "P2_MEDIUM"
        assert WorkItemPriority.P3_LOW == "P3_LOW"

    def test_member_count(self) -> None:
        assert len(WorkItemPriority) == 4


class TestArtifactType:
    def test_enum_values(self) -> None:
        assert ArtifactType.CODE_PATCH == "CODE_PATCH"
        assert ArtifactType.DETECTION_RULE == "DETECTION_RULE"
        assert ArtifactType.THREAT_REPORT == "THREAT_REPORT"
        assert ArtifactType.INCIDENT_REPORT == "INCIDENT_REPORT"
        assert ArtifactType.CONFIGURATION_CHANGE == "CONFIGURATION_CHANGE"
        assert ArtifactType.RUNBOOK == "RUNBOOK"

    def test_member_count(self) -> None:
        assert len(ArtifactType) == 6


class TestValidationStatus:
    def test_enum_values(self) -> None:
        assert ValidationStatus.PENDING == "PENDING"
        assert ValidationStatus.VALIDATED == "VALIDATED"
        assert ValidationStatus.FAILED == "FAILED"

    def test_member_count(self) -> None:
        assert len(ValidationStatus) == 3


class TestDecisionType:
    def test_enum_values(self) -> None:
        assert DecisionType.CREATED == "CREATED"
        assert DecisionType.PRIORITIZED == "PRIORITIZED"
        assert DecisionType.ASSIGNED == "ASSIGNED"
        assert DecisionType.ESCALATED == "ESCALATED"
        assert DecisionType.APPROVED == "APPROVED"
        assert DecisionType.REJECTED == "REJECTED"
        assert DecisionType.COMPLETED == "COMPLETED"

    def test_member_count(self) -> None:
        assert len(DecisionType) == 7


# ---------------------------------------------------------------------------
# Reasoning tests
# ---------------------------------------------------------------------------


class TestReasoning:
    def test_defaults(self) -> None:
        r = Reasoning()
        assert r.evidence == []
        assert r.alternatives_considered == []
        assert r.confidence == 0.5

    def test_custom_values(self) -> None:
        r = Reasoning(
            evidence=["log entry A", "alert B"],
            alternatives_considered=["ignore", "escalate"],
            confidence=0.95,
        )
        assert r.evidence == ["log entry A", "alert B"]
        assert r.alternatives_considered == ["ignore", "escalate"]
        assert r.confidence == 0.95

    def test_confidence_too_high(self) -> None:
        with pytest.raises(ValidationError):
            Reasoning(confidence=1.1)

    def test_confidence_too_low(self) -> None:
        with pytest.raises(ValidationError):
            Reasoning(confidence=-0.1)

    def test_confidence_boundary_zero(self) -> None:
        r = Reasoning(confidence=0.0)
        assert r.confidence == 0.0

    def test_confidence_boundary_one(self) -> None:
        r = Reasoning(confidence=1.0)
        assert r.confidence == 1.0


# ---------------------------------------------------------------------------
# Decision tests
# ---------------------------------------------------------------------------


class TestDecision:
    def test_minimal_creation(self) -> None:
        d = Decision(
            work_item_id="wi-1",
            pool_id="pool-triage",
            agent_id="agent-01",
            decision_type=DecisionType.CREATED,
        )
        assert d.work_item_id == "wi-1"
        assert d.pool_id == "pool-triage"
        assert d.agent_id == "agent-01"
        assert d.decision_type == DecisionType.CREATED
        # defaults
        assert d.decision_id  # auto-generated uuid
        assert isinstance(d.reasoning, Reasoning)
        assert d.outcome == ""
        assert isinstance(d.timestamp_utc, datetime)

    def test_all_fields(self) -> None:
        now = datetime(2026, 3, 16, 10, 0, 0, tzinfo=UTC)
        reasoning = Reasoning(
            evidence=["finding-1"],
            alternatives_considered=["alt-a"],
            confidence=0.8,
        )
        d = Decision(
            decision_id="dec-custom",
            work_item_id="wi-2",
            pool_id="pool-analysis",
            agent_id="agent-02",
            decision_type=DecisionType.ESCALATED,
            reasoning=reasoning,
            outcome="Escalated to senior analyst",
            timestamp_utc=now,
        )
        assert d.decision_id == "dec-custom"
        assert d.reasoning.confidence == 0.8
        assert d.outcome == "Escalated to senior analyst"
        assert d.timestamp_utc == now

    def test_unique_ids(self) -> None:
        kwargs: dict[str, Any] = {
            "work_item_id": "wi-1",
            "pool_id": "p",
            "agent_id": "a",
            "decision_type": DecisionType.APPROVED,
        }
        d1 = Decision(**kwargs)
        d2 = Decision(**kwargs)
        assert d1.decision_id != d2.decision_id

    def test_serialization_round_trip(self) -> None:
        d = Decision(
            work_item_id="wi-1",
            pool_id="pool-triage",
            agent_id="agent-01",
            decision_type=DecisionType.PRIORITIZED,
        )
        data = d.model_dump()
        restored = Decision.model_validate(data)
        assert restored.decision_id == d.decision_id
        assert restored.decision_type == d.decision_type
        assert restored.reasoning.confidence == d.reasoning.confidence


# ---------------------------------------------------------------------------
# Artifact tests
# ---------------------------------------------------------------------------


class TestArtifact:
    def test_minimal_creation(self) -> None:
        a = Artifact(
            work_item_id="wi-1",
            artifact_type=ArtifactType.CODE_PATCH,
        )
        assert a.work_item_id == "wi-1"
        assert a.artifact_type == ArtifactType.CODE_PATCH
        # defaults
        assert a.artifact_id  # auto-generated uuid
        assert a.content == ""
        assert a.format == "text"
        assert a.validation_status == ValidationStatus.PENDING
        assert isinstance(a.created_utc, datetime)

    def test_all_fields(self) -> None:
        now = datetime(2026, 3, 16, 10, 0, 0, tzinfo=UTC)
        a = Artifact(
            artifact_id="art-custom",
            work_item_id="wi-2",
            artifact_type=ArtifactType.DETECTION_RULE,
            content="rule suspicious_dns { ... }",
            format="yara",
            validation_status=ValidationStatus.VALIDATED,
            created_utc=now,
        )
        assert a.artifact_id == "art-custom"
        assert a.content == "rule suspicious_dns { ... }"
        assert a.format == "yara"
        assert a.validation_status == ValidationStatus.VALIDATED
        assert a.created_utc == now

    def test_unique_ids(self) -> None:
        kwargs: dict[str, Any] = {
            "work_item_id": "wi-1",
            "artifact_type": ArtifactType.RUNBOOK,
        }
        a1 = Artifact(**kwargs)
        a2 = Artifact(**kwargs)
        assert a1.artifact_id != a2.artifact_id

    def test_serialization_round_trip(self) -> None:
        a = Artifact(
            work_item_id="wi-1",
            artifact_type=ArtifactType.THREAT_REPORT,
            content="APT-29 campaign analysis",
        )
        data = a.model_dump()
        restored = Artifact.model_validate(data)
        assert restored.artifact_id == a.artifact_id
        assert restored.artifact_type == a.artifact_type
        assert restored.content == a.content


# ---------------------------------------------------------------------------
# WorkItem tests
# ---------------------------------------------------------------------------


class TestWorkItem:
    def test_minimal_creation(self) -> None:
        wi = WorkItem(
            title="Investigate suspicious DNS queries",
            item_type=WorkItemType.THREAT_REPORT,
        )
        assert wi.title == "Investigate suspicious DNS queries"
        assert wi.item_type == WorkItemType.THREAT_REPORT
        # defaults
        assert wi.work_item_id  # auto-generated uuid
        assert wi.parent_id is None
        assert wi.correlation_id is None
        assert wi.status == WorkItemStatus.DRAFT
        assert wi.priority == WorkItemPriority.P2_MEDIUM
        assert wi.producer_pool == ""
        assert wi.consumer_pool == ""
        assert wi.description == ""
        assert wi.acceptance_criteria == []
        assert wi.artifacts == []
        assert wi.decisions == []
        assert wi.context == {}
        assert isinstance(wi.created_utc, datetime)
        assert isinstance(wi.updated_utc, datetime)
        assert wi.due_utc is None

    def test_all_fields(self) -> None:
        now = datetime(2026, 3, 16, 10, 0, 0, tzinfo=UTC)
        due = datetime(2026, 3, 17, 10, 0, 0, tzinfo=UTC)
        artifact = Artifact(
            work_item_id="wi-full",
            artifact_type=ArtifactType.INCIDENT_REPORT,
            content="Incident details...",
        )
        decision = Decision(
            work_item_id="wi-full",
            pool_id="pool-triage",
            agent_id="agent-01",
            decision_type=DecisionType.CREATED,
        )
        wi = WorkItem(
            work_item_id="wi-full",
            parent_id="wi-parent",
            correlation_id="corr-99",
            item_type=WorkItemType.INCIDENT_REPORT,
            status=WorkItemStatus.IN_PROGRESS,
            priority=WorkItemPriority.P0_CRITICAL,
            producer_pool="pool-triage",
            consumer_pool="pool-analysis",
            title="Major incident response",
            description="Full investigation required",
            acceptance_criteria=["Root cause identified", "Remediation plan created"],
            artifacts=[artifact],
            decisions=[decision],
            context={"source_event_id": "evt-42", "severity": "CRITICAL"},
            created_utc=now,
            updated_utc=now,
            due_utc=due,
        )
        assert wi.work_item_id == "wi-full"
        assert wi.parent_id == "wi-parent"
        assert wi.correlation_id == "corr-99"
        assert wi.item_type == WorkItemType.INCIDENT_REPORT
        assert wi.status == WorkItemStatus.IN_PROGRESS
        assert wi.priority == WorkItemPriority.P0_CRITICAL
        assert wi.producer_pool == "pool-triage"
        assert wi.consumer_pool == "pool-analysis"
        assert wi.description == "Full investigation required"
        assert wi.acceptance_criteria == ["Root cause identified", "Remediation plan created"]
        assert len(wi.artifacts) == 1
        assert wi.artifacts[0].content == "Incident details..."
        assert len(wi.decisions) == 1
        assert wi.decisions[0].decision_type == DecisionType.CREATED
        assert wi.context == {"source_event_id": "evt-42", "severity": "CRITICAL"}
        assert wi.created_utc == now
        assert wi.updated_utc == now
        assert wi.due_utc == due

    def test_default_status_is_draft(self) -> None:
        wi = WorkItem(title="t", item_type=WorkItemType.PATCH_REQUEST)
        assert wi.status == WorkItemStatus.DRAFT

    def test_default_priority_is_p2_medium(self) -> None:
        wi = WorkItem(title="t", item_type=WorkItemType.PATCH_REQUEST)
        assert wi.priority == WorkItemPriority.P2_MEDIUM

    def test_parent_id_for_decomposition(self) -> None:
        parent = WorkItem(
            title="Parent task",
            item_type=WorkItemType.INCIDENT_REPORT,
        )
        child = WorkItem(
            title="Sub-task: gather logs",
            item_type=WorkItemType.THREAT_REPORT,
            parent_id=parent.work_item_id,
        )
        assert child.parent_id == parent.work_item_id

    def test_artifacts_can_be_embedded(self) -> None:
        a1 = Artifact(work_item_id="wi-x", artifact_type=ArtifactType.CODE_PATCH)
        a2 = Artifact(work_item_id="wi-x", artifact_type=ArtifactType.RUNBOOK)
        wi = WorkItem(
            title="Patch and document",
            item_type=WorkItemType.PATCH_REQUEST,
            artifacts=[a1, a2],
        )
        assert len(wi.artifacts) == 2
        assert wi.artifacts[0].artifact_type == ArtifactType.CODE_PATCH
        assert wi.artifacts[1].artifact_type == ArtifactType.RUNBOOK

    def test_decisions_can_be_embedded(self) -> None:
        d1 = Decision(
            work_item_id="wi-y",
            pool_id="p",
            agent_id="a",
            decision_type=DecisionType.CREATED,
        )
        d2 = Decision(
            work_item_id="wi-y",
            pool_id="p",
            agent_id="a",
            decision_type=DecisionType.APPROVED,
        )
        wi = WorkItem(
            title="Review and approve",
            item_type=WorkItemType.DETECTION_RULE,
            decisions=[d1, d2],
        )
        assert len(wi.decisions) == 2
        assert wi.decisions[0].decision_type == DecisionType.CREATED
        assert wi.decisions[1].decision_type == DecisionType.APPROVED

    def test_serialization_round_trip(self) -> None:
        artifact = Artifact(
            work_item_id="wi-rt",
            artifact_type=ArtifactType.THREAT_REPORT,
            content="report content",
        )
        decision = Decision(
            work_item_id="wi-rt",
            pool_id="pool-1",
            agent_id="agent-1",
            decision_type=DecisionType.PRIORITIZED,
        )
        wi = WorkItem(
            title="Round-trip test",
            item_type=WorkItemType.VULNERABILITY_ASSESSMENT,
            priority=WorkItemPriority.P1_HIGH,
            artifacts=[artifact],
            decisions=[decision],
            context={"key": "value"},
        )
        data = wi.model_dump()
        restored = WorkItem.model_validate(data)
        assert restored.work_item_id == wi.work_item_id
        assert restored.title == wi.title
        assert restored.item_type == wi.item_type
        assert restored.priority == wi.priority
        assert len(restored.artifacts) == 1
        assert restored.artifacts[0].artifact_id == artifact.artifact_id
        assert len(restored.decisions) == 1
        assert restored.decisions[0].decision_id == decision.decision_id
        assert restored.context == {"key": "value"}

    def test_unique_work_item_ids(self) -> None:
        wi1 = WorkItem(title="t", item_type=WorkItemType.SECURITY_ADVISORY)
        wi2 = WorkItem(title="t", item_type=WorkItemType.SECURITY_ADVISORY)
        assert wi1.work_item_id != wi2.work_item_id
