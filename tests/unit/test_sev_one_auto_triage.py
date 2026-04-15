"""Unit tests for SEV-1 auto-triage bypass in TrustApprovalHandler."""

from __future__ import annotations

import pytest

from summer_puppy.audit.logger import InMemoryAuditLogger
from summer_puppy.audit.models import AuditEntryType
from summer_puppy.channel.bus import InMemoryEventBus
from summer_puppy.events.models import (
    EventSource,
    QAStatus,
    Recommendation,
    SecurityEvent,
    Severity,
)
from summer_puppy.pipeline.handlers import TrustApprovalHandler
from summer_puppy.pipeline.models import PipelineContext, PipelineStage, PipelineStatus
from summer_puppy.trust.models import (
    ActionClass,
    SevOneAutoTriageConfig,
    TrustPhase,
    TrustProfile,
)


def make_critical_event(customer_id: str = "cust-1") -> SecurityEvent:
    return SecurityEvent(
        customer_id=customer_id,
        source=EventSource.EDR,
        severity=Severity.CRITICAL,
        title="Ransomware detected",
        description="Ransomware process actively encrypting files",
    )


def make_high_event(customer_id: str = "cust-1") -> SecurityEvent:
    return SecurityEvent(
        customer_id=customer_id,
        source=EventSource.SIEM,
        severity=Severity.HIGH,
        title="Suspicious login",
        description="Multiple failed login attempts",
    )


def make_recommendation(
    action_class: ActionClass = ActionClass.PROCESS_TERMINATION,
    confidence: float = 0.9,
    has_rollback: bool = True,
) -> Recommendation:
    return Recommendation(
        event_id="evt-1",
        customer_id="cust-1",
        action_class=action_class,
        description="Kill malicious process",
        reasoning="Process is actively encrypting files",
        confidence_score=confidence,
        estimated_risk=Severity.HIGH,
        qa_status=QAStatus.PASSED,
        rollback_plan="Re-enable process if false positive" if has_rollback else None,
    )


def make_trust_profile(
    sev_one_enabled: bool = True,
    trust_phase: TrustPhase = TrustPhase.SUPERVISED,
    allowed_classes: list[ActionClass] | None = None,
    min_confidence: float = 0.7,
    require_rollback: bool = True,
) -> TrustProfile:
    config = SevOneAutoTriageConfig(
        enabled=sev_one_enabled,
        allowed_action_classes=allowed_classes or [
            ActionClass.NETWORK_ISOLATION,
            ActionClass.PROCESS_TERMINATION,
            ActionClass.ACCOUNT_LOCKOUT,
            ActionClass.BLOCK_IP,
            ActionClass.DISABLE_ACCOUNT,
        ],
        require_rollback_plan=require_rollback,
        min_confidence_score=min_confidence,
    )
    return TrustProfile(
        customer_id="cust-1",
        trust_phase=trust_phase,
        sev_one_config=config,
    )


def make_ctx(
    event: SecurityEvent | None = None,
    recommendation: Recommendation | None = None,
    trust_profile: TrustProfile | None = None,
) -> PipelineContext:
    return PipelineContext(
        event=event or make_critical_event(),
        customer_id="cust-1",
        correlation_id="corr-1",
        current_stage=PipelineStage.APPROVE,
        recommendation=recommendation or make_recommendation(),
        trust_profile=trust_profile or make_trust_profile(),
    )


class TestSevOneBypassCheck:
    def test_bypasses_when_all_conditions_met(self) -> None:
        handler = TrustApprovalHandler(
            audit_logger=InMemoryAuditLogger(),
            event_bus=InMemoryEventBus(),
        )
        ctx = make_ctx()
        assert handler._check_sev_one_bypass(ctx) is True

    def test_no_bypass_when_disabled(self) -> None:
        handler = TrustApprovalHandler(
            audit_logger=InMemoryAuditLogger(),
            event_bus=InMemoryEventBus(),
        )
        ctx = make_ctx(trust_profile=make_trust_profile(sev_one_enabled=False))
        assert handler._check_sev_one_bypass(ctx) is False

    def test_no_bypass_for_high_severity(self) -> None:
        handler = TrustApprovalHandler(
            audit_logger=InMemoryAuditLogger(),
            event_bus=InMemoryEventBus(),
        )
        ctx = make_ctx(event=make_high_event())
        assert handler._check_sev_one_bypass(ctx) is False

    def test_no_bypass_for_disallowed_action_class(self) -> None:
        handler = TrustApprovalHandler(
            audit_logger=InMemoryAuditLogger(),
            event_bus=InMemoryEventBus(),
        )
        ctx = make_ctx(
            recommendation=make_recommendation(action_class=ActionClass.PATCH_DEPLOYMENT),
            trust_profile=make_trust_profile(
                allowed_classes=[ActionClass.NETWORK_ISOLATION]
            ),
        )
        assert handler._check_sev_one_bypass(ctx) is False

    def test_no_bypass_when_confidence_below_threshold(self) -> None:
        handler = TrustApprovalHandler(
            audit_logger=InMemoryAuditLogger(),
            event_bus=InMemoryEventBus(),
        )
        ctx = make_ctx(
            recommendation=make_recommendation(confidence=0.5),
            trust_profile=make_trust_profile(min_confidence=0.8),
        )
        assert handler._check_sev_one_bypass(ctx) is False

    def test_no_bypass_when_rollback_required_but_missing(self) -> None:
        handler = TrustApprovalHandler(
            audit_logger=InMemoryAuditLogger(),
            event_bus=InMemoryEventBus(),
        )
        ctx = make_ctx(
            recommendation=make_recommendation(has_rollback=False),
            trust_profile=make_trust_profile(require_rollback=True),
        )
        assert handler._check_sev_one_bypass(ctx) is False

    def test_bypass_when_rollback_not_required(self) -> None:
        handler = TrustApprovalHandler(
            audit_logger=InMemoryAuditLogger(),
            event_bus=InMemoryEventBus(),
        )
        ctx = make_ctx(
            recommendation=make_recommendation(has_rollback=False),
            trust_profile=make_trust_profile(require_rollback=False),
        )
        assert handler._check_sev_one_bypass(ctx) is True


class TestTrustApprovalHandlerSevOne:
    @pytest.mark.asyncio
    async def test_sev_one_bypasses_to_execute(self) -> None:
        handler = TrustApprovalHandler(
            audit_logger=InMemoryAuditLogger(),
            event_bus=InMemoryEventBus(),
        )
        ctx = make_ctx()
        result = await handler.handle(ctx)
        assert result.current_stage == PipelineStage.EXECUTE
        assert result.action_request is not None
        assert result.action_request.approved_by == "sev_one_auto_triage"

    @pytest.mark.asyncio
    async def test_sev_one_writes_audit_entry(self) -> None:
        audit_logger = InMemoryAuditLogger()
        handler = TrustApprovalHandler(
            audit_logger=audit_logger,
            event_bus=InMemoryEventBus(),
        )
        ctx = make_ctx()
        await handler.handle(ctx)
        entries = audit_logger._entries
        sev_one_entries = [
            e for e in entries
            if e.entry_type == AuditEntryType.AUTO_APPROVED
            and "SEV-1" in str(e.details.get("reason", ""))
        ]
        assert len(sev_one_entries) == 1

    @pytest.mark.asyncio
    async def test_sev_one_does_not_pause_for_approval(self) -> None:
        """Even in MANUAL trust phase, SEV-1 bypass skips human approval."""
        handler = TrustApprovalHandler(
            audit_logger=InMemoryAuditLogger(),
            event_bus=InMemoryEventBus(),
        )
        ctx = make_ctx(trust_profile=make_trust_profile(
            sev_one_enabled=True,
            trust_phase=TrustPhase.MANUAL,
        ))
        result = await handler.handle(ctx)
        assert result.status != PipelineStatus.PAUSED_FOR_APPROVAL
        assert result.current_stage == PipelineStage.EXECUTE

    @pytest.mark.asyncio
    async def test_non_sev_one_still_pauses_in_manual_phase(self) -> None:
        """HIGH severity events still go through normal approval in MANUAL phase."""
        handler = TrustApprovalHandler(
            audit_logger=InMemoryAuditLogger(),
            event_bus=InMemoryEventBus(),
        )
        ctx = make_ctx(
            event=make_high_event(),
            trust_profile=make_trust_profile(
                sev_one_enabled=True,
                trust_phase=TrustPhase.MANUAL,
            ),
        )
        result = await handler.handle(ctx)
        assert result.status == PipelineStatus.PAUSED_FOR_APPROVAL


class TestSevOneAutoTriageConfig:
    def test_default_config_is_disabled(self) -> None:
        config = SevOneAutoTriageConfig()
        assert config.enabled is False

    def test_default_allowed_classes_contains_containment_actions(self) -> None:
        config = SevOneAutoTriageConfig()
        assert ActionClass.NETWORK_ISOLATION in config.allowed_action_classes
        assert ActionClass.PROCESS_TERMINATION in config.allowed_action_classes
        assert ActionClass.ACCOUNT_LOCKOUT in config.allowed_action_classes
        assert ActionClass.BLOCK_IP in config.allowed_action_classes

    def test_trust_profile_default_sev_one_disabled(self) -> None:
        profile = TrustProfile(customer_id="test")
        assert profile.sev_one_config.enabled is False
