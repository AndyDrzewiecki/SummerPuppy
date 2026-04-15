"""StoryBuilder — converts sandbox Findings into UserStory objects."""

from __future__ import annotations

from summer_puppy.dev_bot.models import PatchType, UserStory
from summer_puppy.sandbox.models import Finding, FindingCategory, IoCType

_CATEGORY_TO_PATCH_TYPES: dict[FindingCategory, list[PatchType]] = {
    FindingCategory.VULNERABILITY: [PatchType.REMEDIATION_SCRIPT, PatchType.CONFIGURATION_CHANGE],
    FindingCategory.COMMAND_AND_CONTROL: [PatchType.FIREWALL_RULE, PatchType.EDR_CONFIG],
    FindingCategory.DATA_EXFILTRATION: [PatchType.FIREWALL_RULE, PatchType.IAM_POLICY],
    FindingCategory.PRIVILEGE_ESCALATION: [PatchType.IAM_POLICY, PatchType.EDR_CONFIG],
    FindingCategory.LATERAL_MOVEMENT: [PatchType.FIREWALL_RULE, PatchType.NETWORK_POLICY],
    FindingCategory.CREDENTIAL_ACCESS: [PatchType.IAM_POLICY, PatchType.EDR_CONFIG],
    FindingCategory.PERSISTENCE: [PatchType.EDR_CONFIG, PatchType.REMEDIATION_SCRIPT],
    FindingCategory.DEFENSE_EVASION: [PatchType.EDR_CONFIG, PatchType.REMEDIATION_SCRIPT],
    FindingCategory.DISCOVERY: [PatchType.EDR_CONFIG],
    FindingCategory.EXECUTION: [PatchType.EDR_CONFIG, PatchType.REMEDIATION_SCRIPT],
    FindingCategory.IMPACT: [PatchType.REMEDIATION_SCRIPT, PatchType.FIREWALL_RULE],
    FindingCategory.POLICY_VIOLATION: [PatchType.IAM_POLICY, PatchType.CONFIGURATION_CHANGE],
}


def _build_description(finding: Finding) -> str:
    return (
        f"As a security engineer, I need to remediate a {finding.category} finding "
        f"({finding.severity} severity) so that the affected systems are protected. "
        f"Finding: {finding.description}"
    )


def _build_acceptance_criteria(finding: Finding) -> list[str]:
    criteria = [
        f"The {finding.category} threat is fully remediated.",
        "All recommended actions have been applied.",
        "Rollback procedure is documented and tested.",
        "No regression in existing security controls.",
    ]
    if finding.affected_assets:
        asset_list = ", ".join(finding.affected_assets[:3])
        criteria.append(f"Affected assets are secured: {asset_list}.")
    if finding.mitre_attack_ids:
        mitre_list = ", ".join(finding.mitre_attack_ids[:3])
        criteria.append(f"MITRE ATT&CK techniques addressed: {mitre_list}.")
    return criteria


class StoryBuilder:
    """Converts sandbox Findings into UserStory objects."""

    def build(self, finding: Finding, customer_id: str, correlation_id: str) -> UserStory:
        """Build a UserStory from a Finding."""
        patch_types = list(_CATEGORY_TO_PATCH_TYPES.get(finding.category, []))
        cve_refs = [
            ioc.value
            for ioc in finding.ioc_indicators
            if ioc.ioc_type == IoCType.CVE
        ]
        description = _build_description(finding)
        acceptance_criteria = _build_acceptance_criteria(finding)

        return UserStory(
            finding_id=finding.finding_id,
            customer_id=customer_id,
            correlation_id=correlation_id,
            title=f"[{finding.severity.upper()}] Remediate: {finding.title}",
            description=description,
            acceptance_criteria=acceptance_criteria,
            severity=finding.severity,
            cve_refs=cve_refs,
            affected_files=[],
            affected_assets=list(finding.affected_assets),
            mitre_attack_ids=list(finding.mitre_attack_ids),
            recommended_patch_types=patch_types,
        )
