"""Unit tests for security sandbox models."""

from __future__ import annotations

import pytest

from summer_puppy.sandbox.models import (
    AnalysisReport,
    Finding,
    FindingCategory,
    FindingSeverity,
    IndicatorOfCompromise,
    IoCType,
    SampleSubmission,
    SampleType,
    SandboxVerdict,
)


def make_finding(
    severity: FindingSeverity = FindingSeverity.HIGH,
    category: FindingCategory = FindingCategory.COMMAND_AND_CONTROL,
    title: str = "Test finding",
) -> Finding:
    return Finding(
        category=category,
        severity=severity,
        title=title,
        description="Test description",
        confidence=0.9,
    )


def make_report(
    verdict: SandboxVerdict = SandboxVerdict.MALICIOUS,
    findings: list[Finding] | None = None,
) -> AnalysisReport:
    return AnalysisReport(
        submission_id="sub-1",
        customer_id="cust-1",
        sample_type=SampleType.MALWARE_BINARY,
        verdict=verdict,
        overall_severity=FindingSeverity.HIGH,
        findings=findings or [],
        summary="Test report",
    )


class TestFinding:
    def test_finding_with_iocs(self) -> None:
        ioc = IndicatorOfCompromise(
            ioc_type=IoCType.IP_ADDRESS,
            value="192.168.1.100",
            confidence=0.95,
            context="Observed in C2 traffic",
        )
        finding = Finding(
            category=FindingCategory.COMMAND_AND_CONTROL,
            severity=FindingSeverity.CRITICAL,
            title="C2 Communication Detected",
            description="Malware communicating with known C2 server",
            mitre_attack_ids=["T1071.001", "T1095"],
            ioc_indicators=[ioc],
            confidence=0.9,
        )
        assert finding.category == FindingCategory.COMMAND_AND_CONTROL
        assert finding.severity == FindingSeverity.CRITICAL
        assert len(finding.ioc_indicators) == 1
        assert finding.ioc_indicators[0].value == "192.168.1.100"
        assert "T1071.001" in finding.mitre_attack_ids

    def test_finding_defaults(self) -> None:
        finding = make_finding()
        assert finding.ioc_indicators == []
        assert finding.mitre_attack_ids == []
        assert finding.affected_assets == []
        assert finding.evidence == []
        assert finding.recommended_actions == []


class TestAnalysisReport:
    def test_critical_findings_property(self) -> None:
        findings = [
            make_finding(severity=FindingSeverity.CRITICAL, title="crit1"),
            make_finding(severity=FindingSeverity.HIGH, title="high1"),
            make_finding(severity=FindingSeverity.CRITICAL, title="crit2"),
            make_finding(severity=FindingSeverity.LOW, title="low1"),
        ]
        report = make_report(findings=findings)
        assert len(report.critical_findings) == 2
        assert all(f.severity == FindingSeverity.CRITICAL for f in report.critical_findings)

    def test_high_findings_property(self) -> None:
        findings = [
            make_finding(severity=FindingSeverity.CRITICAL),
            make_finding(severity=FindingSeverity.HIGH),
            make_finding(severity=FindingSeverity.MEDIUM),
        ]
        report = make_report(findings=findings)
        assert len(report.high_findings) == 1

    def test_all_iocs(self) -> None:
        ioc1 = IndicatorOfCompromise(
            ioc_type=IoCType.IP_ADDRESS, value="1.2.3.4", confidence=0.9
        )
        ioc2 = IndicatorOfCompromise(
            ioc_type=IoCType.DOMAIN, value="evil.com", confidence=0.8
        )
        f1 = Finding(
            category=FindingCategory.COMMAND_AND_CONTROL,
            severity=FindingSeverity.HIGH,
            title="f1",
            description="d",
            ioc_indicators=[ioc1],
            confidence=0.9,
        )
        f2 = Finding(
            category=FindingCategory.DATA_EXFILTRATION,
            severity=FindingSeverity.HIGH,
            title="f2",
            description="d",
            ioc_indicators=[ioc2],
            confidence=0.9,
        )
        report = make_report(findings=[f1, f2])
        ioc_values = {ioc.value for ioc in report.all_iocs}
        assert "1.2.3.4" in ioc_values
        assert "evil.com" in ioc_values

    def test_all_mitre_ids_deduplication(self) -> None:
        f1 = Finding(
            category=FindingCategory.EXECUTION,
            severity=FindingSeverity.HIGH,
            title="f1",
            description="d",
            mitre_attack_ids=["T1059", "T1071"],
            confidence=0.9,
        )
        f2 = Finding(
            category=FindingCategory.PERSISTENCE,
            severity=FindingSeverity.MEDIUM,
            title="f2",
            description="d",
            mitre_attack_ids=["T1059", "T1547"],  # T1059 is duplicate
            confidence=0.8,
        )
        report = make_report(findings=[f1, f2])
        mitre_ids = report.all_mitre_ids
        assert mitre_ids.count("T1059") == 1
        assert "T1071" in mitre_ids
        assert "T1547" in mitre_ids

    def test_empty_report(self) -> None:
        report = make_report(verdict=SandboxVerdict.CLEAN, findings=[])
        assert report.critical_findings == []
        assert report.high_findings == []
        assert report.all_iocs == []
        assert report.all_mitre_ids == []


class TestSampleSubmission:
    def test_submission_defaults(self) -> None:
        sub = SampleSubmission(
            customer_id="cust-1",
            sample_type=SampleType.SCRIPT,
            content="echo hello",
        )
        assert sub.customer_id == "cust-1"
        assert sub.filename is None
        assert sub.metadata == {}
        assert sub.submitted_by == "api"
        assert sub.submission_id != ""

    def test_submission_with_metadata(self) -> None:
        sub = SampleSubmission(
            customer_id="cust-1",
            sample_type=SampleType.VULNERABILITY_REPORT,
            content='{"cve": "CVE-2024-1234"}',
            filename="report.json",
            metadata={"source": "qualys", "scan_id": "scan-123"},
        )
        assert sub.filename == "report.json"
        assert sub.metadata["source"] == "qualys"
