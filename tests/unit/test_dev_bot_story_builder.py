"""Unit tests for StoryBuilder."""

from __future__ import annotations

import pytest

from summer_puppy.dev_bot.models import PatchType
from summer_puppy.dev_bot.story_builder import StoryBuilder
from summer_puppy.sandbox.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    IndicatorOfCompromise,
    IoCType,
)


def make_finding(
    category: FindingCategory = FindingCategory.VULNERABILITY,
    severity: FindingSeverity = FindingSeverity.HIGH,
    title: str = "Test Finding",
    description: str = "A security issue",
    mitre_attack_ids: list[str] | None = None,
    ioc_indicators: list[IndicatorOfCompromise] | None = None,
    affected_assets: list[str] | None = None,
) -> Finding:
    return Finding(
        category=category,
        severity=severity,
        title=title,
        description=description,
        mitre_attack_ids=mitre_attack_ids or [],
        ioc_indicators=ioc_indicators or [],
        affected_assets=affected_assets or [],
        confidence=0.9,
    )


class TestStoryBuilderBuildCategories:
    @pytest.mark.parametrize(
        "category, expected_patch_types",
        [
            (
                FindingCategory.VULNERABILITY,
                [PatchType.REMEDIATION_SCRIPT, PatchType.CONFIGURATION_CHANGE],
            ),
            (
                FindingCategory.COMMAND_AND_CONTROL,
                [PatchType.FIREWALL_RULE, PatchType.EDR_CONFIG],
            ),
            (
                FindingCategory.DATA_EXFILTRATION,
                [PatchType.FIREWALL_RULE, PatchType.IAM_POLICY],
            ),
            (
                FindingCategory.PRIVILEGE_ESCALATION,
                [PatchType.IAM_POLICY, PatchType.EDR_CONFIG],
            ),
            (
                FindingCategory.LATERAL_MOVEMENT,
                [PatchType.FIREWALL_RULE, PatchType.NETWORK_POLICY],
            ),
            (
                FindingCategory.CREDENTIAL_ACCESS,
                [PatchType.IAM_POLICY, PatchType.EDR_CONFIG],
            ),
            (
                FindingCategory.PERSISTENCE,
                [PatchType.EDR_CONFIG, PatchType.REMEDIATION_SCRIPT],
            ),
            (
                FindingCategory.DEFENSE_EVASION,
                [PatchType.EDR_CONFIG, PatchType.REMEDIATION_SCRIPT],
            ),
            (FindingCategory.DISCOVERY, [PatchType.EDR_CONFIG]),
            (
                FindingCategory.EXECUTION,
                [PatchType.EDR_CONFIG, PatchType.REMEDIATION_SCRIPT],
            ),
            (
                FindingCategory.IMPACT,
                [PatchType.REMEDIATION_SCRIPT, PatchType.FIREWALL_RULE],
            ),
            (
                FindingCategory.POLICY_VIOLATION,
                [PatchType.IAM_POLICY, PatchType.CONFIGURATION_CHANGE],
            ),
        ],
    )
    def test_category_maps_to_correct_patch_types(
        self,
        category: FindingCategory,
        expected_patch_types: list[PatchType],
    ) -> None:
        builder = StoryBuilder()
        finding = make_finding(category=category)
        story = builder.build(finding, customer_id="cust-1", correlation_id="corr-1")
        assert story.recommended_patch_types == expected_patch_types


class TestStoryBuilderCveExtraction:
    def test_extracts_cve_refs_from_iocs(self) -> None:
        iocs = [
            IndicatorOfCompromise(
                ioc_type=IoCType.CVE, value="CVE-2024-1234", confidence=0.9
            ),
            IndicatorOfCompromise(
                ioc_type=IoCType.CVE, value="CVE-2024-5678", confidence=0.8
            ),
        ]
        builder = StoryBuilder()
        finding = make_finding(ioc_indicators=iocs)
        story = builder.build(finding, "cust-1", "corr-1")
        assert "CVE-2024-1234" in story.cve_refs
        assert "CVE-2024-5678" in story.cve_refs

    def test_ignores_non_cve_iocs(self) -> None:
        iocs = [
            IndicatorOfCompromise(ioc_type=IoCType.IP_ADDRESS, value="10.0.0.1", confidence=0.9),
            IndicatorOfCompromise(ioc_type=IoCType.DOMAIN, value="evil.com", confidence=0.8),
        ]
        builder = StoryBuilder()
        finding = make_finding(ioc_indicators=iocs)
        story = builder.build(finding, "cust-1", "corr-1")
        assert story.cve_refs == []

    def test_no_iocs_gives_empty_cve_refs(self) -> None:
        builder = StoryBuilder()
        finding = make_finding(ioc_indicators=[])
        story = builder.build(finding, "cust-1", "corr-1")
        assert story.cve_refs == []

    def test_mixed_iocs_extracts_only_cves(self) -> None:
        iocs = [
            IndicatorOfCompromise(ioc_type=IoCType.IP_ADDRESS, value="1.2.3.4", confidence=0.9),
            IndicatorOfCompromise(ioc_type=IoCType.CVE, value="CVE-2023-9999", confidence=0.95),
            IndicatorOfCompromise(ioc_type=IoCType.DOMAIN, value="bad.net", confidence=0.7),
        ]
        builder = StoryBuilder()
        finding = make_finding(ioc_indicators=iocs)
        story = builder.build(finding, "cust-1", "corr-1")
        assert story.cve_refs == ["CVE-2023-9999"]


class TestStoryBuilderDescription:
    def test_description_starts_with_as_a(self) -> None:
        builder = StoryBuilder()
        finding = make_finding()
        story = builder.build(finding, "cust-1", "corr-1")
        assert story.description.startswith("As a security engineer")

    def test_description_contains_category(self) -> None:
        builder = StoryBuilder()
        finding = make_finding(category=FindingCategory.COMMAND_AND_CONTROL)
        story = builder.build(finding, "cust-1", "corr-1")
        assert "command_and_control" in story.description

    def test_description_contains_severity(self) -> None:
        builder = StoryBuilder()
        finding = make_finding(severity=FindingSeverity.CRITICAL)
        story = builder.build(finding, "cust-1", "corr-1")
        assert "critical" in story.description

    def test_description_contains_finding_description(self) -> None:
        builder = StoryBuilder()
        finding = make_finding(description="Backdoor detected in system32")
        story = builder.build(finding, "cust-1", "corr-1")
        assert "Backdoor detected in system32" in story.description


class TestStoryBuilderAcceptanceCriteria:
    def test_generates_acceptance_criteria(self) -> None:
        builder = StoryBuilder()
        finding = make_finding()
        story = builder.build(finding, "cust-1", "corr-1")
        assert len(story.acceptance_criteria) > 0

    def test_criteria_includes_rollback(self) -> None:
        builder = StoryBuilder()
        finding = make_finding()
        story = builder.build(finding, "cust-1", "corr-1")
        combined = " ".join(story.acceptance_criteria).lower()
        assert "rollback" in combined

    def test_criteria_includes_affected_assets_when_present(self) -> None:
        builder = StoryBuilder()
        finding = make_finding(affected_assets=["server-prod-1", "db-01"])
        story = builder.build(finding, "cust-1", "corr-1")
        combined = " ".join(story.acceptance_criteria)
        assert "server-prod-1" in combined

    def test_criteria_includes_mitre_when_present(self) -> None:
        builder = StoryBuilder()
        finding = make_finding(mitre_attack_ids=["T1059", "T1078"])
        story = builder.build(finding, "cust-1", "corr-1")
        combined = " ".join(story.acceptance_criteria)
        assert "T1059" in combined


class TestStoryBuilderMitreIds:
    def test_mitre_ids_copied_to_story(self) -> None:
        builder = StoryBuilder()
        finding = make_finding(mitre_attack_ids=["T1059", "T1078", "T1003"])
        story = builder.build(finding, "cust-1", "corr-1")
        assert story.mitre_attack_ids == ["T1059", "T1078", "T1003"]

    def test_no_mitre_ids_gives_empty_list(self) -> None:
        builder = StoryBuilder()
        finding = make_finding(mitre_attack_ids=[])
        story = builder.build(finding, "cust-1", "corr-1")
        assert story.mitre_attack_ids == []


class TestStoryBuilderFields:
    def test_finding_id_linked(self) -> None:
        builder = StoryBuilder()
        finding = make_finding()
        story = builder.build(finding, "cust-1", "corr-1")
        assert story.finding_id == finding.finding_id

    def test_customer_and_correlation_id(self) -> None:
        builder = StoryBuilder()
        finding = make_finding()
        story = builder.build(finding, "cust-abc", "corr-xyz")
        assert story.customer_id == "cust-abc"
        assert story.correlation_id == "corr-xyz"

    def test_severity_copied(self) -> None:
        builder = StoryBuilder()
        finding = make_finding(severity=FindingSeverity.CRITICAL)
        story = builder.build(finding, "cust-1", "corr-1")
        assert story.severity == FindingSeverity.CRITICAL

    def test_affected_assets_copied(self) -> None:
        builder = StoryBuilder()
        finding = make_finding(affected_assets=["asset-1", "asset-2"])
        story = builder.build(finding, "cust-1", "corr-1")
        assert story.affected_assets == ["asset-1", "asset-2"]
