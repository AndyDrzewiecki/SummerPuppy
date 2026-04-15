"""Unit tests for findings_to_events conversion."""

from __future__ import annotations

import pytest

from summer_puppy.events.models import Severity
from summer_puppy.sandbox.findings_to_events import report_to_events, summary_event
from summer_puppy.sandbox.models import (
    AnalysisReport,
    Finding,
    FindingCategory,
    FindingSeverity,
    IndicatorOfCompromise,
    IoCType,
    SampleType,
    SandboxVerdict,
)


def make_report(
    verdict: SandboxVerdict = SandboxVerdict.MALICIOUS,
    findings: list[Finding] | None = None,
    overall_severity: FindingSeverity = FindingSeverity.HIGH,
) -> AnalysisReport:
    return AnalysisReport(
        submission_id="sub-1",
        customer_id="cust-1",
        sample_type=SampleType.SCRIPT,
        verdict=verdict,
        overall_severity=overall_severity,
        findings=findings or [],
        summary="Test analysis",
    )


def make_finding(
    severity: FindingSeverity = FindingSeverity.HIGH,
    category: FindingCategory = FindingCategory.EXECUTION,
    title: str = "Test Finding",
    with_ioc: bool = False,
    mitre_ids: list[str] | None = None,
    assets: list[str] | None = None,
) -> Finding:
    iocs = []
    if with_ioc:
        iocs = [IndicatorOfCompromise(
            ioc_type=IoCType.IP_ADDRESS,
            value="192.168.1.1",
            confidence=0.9,
        )]
    return Finding(
        category=category,
        severity=severity,
        title=title,
        description="Test description",
        ioc_indicators=iocs,
        mitre_attack_ids=mitre_ids or [],
        affected_assets=assets or [],
        confidence=0.9,
    )


class TestReportToEvents:
    def test_informational_findings_skipped(self) -> None:
        report = make_report(findings=[
            make_finding(severity=FindingSeverity.INFORMATIONAL),
        ])
        events = report_to_events(report)
        assert events == []

    def test_one_event_per_significant_finding(self) -> None:
        report = make_report(findings=[
            make_finding(severity=FindingSeverity.LOW, title="low"),
            make_finding(severity=FindingSeverity.MEDIUM, title="medium"),
            make_finding(severity=FindingSeverity.HIGH, title="high"),
            make_finding(severity=FindingSeverity.CRITICAL, title="crit"),
            make_finding(severity=FindingSeverity.INFORMATIONAL, title="info"),
        ])
        events = report_to_events(report)
        assert len(events) == 4  # informational skipped

    def test_severity_mapping(self) -> None:
        report = make_report(findings=[
            make_finding(severity=FindingSeverity.CRITICAL, title="crit"),
            make_finding(severity=FindingSeverity.HIGH, title="high"),
            make_finding(severity=FindingSeverity.MEDIUM, title="med"),
            make_finding(severity=FindingSeverity.LOW, title="low"),
        ])
        events = report_to_events(report)
        severities = {e.severity for e in events}
        assert Severity.CRITICAL in severities
        assert Severity.HIGH in severities
        assert Severity.MEDIUM in severities
        assert Severity.LOW in severities

    def test_event_has_sandbox_prefix(self) -> None:
        report = make_report(findings=[make_finding(title="Malware Detected")])
        events = report_to_events(report)
        assert events[0].title.startswith("[Sandbox]")

    def test_ioc_tags_included(self) -> None:
        report = make_report(findings=[make_finding(with_ioc=True)])
        events = report_to_events(report)
        event = events[0]
        ioc_tags = [t for t in event.tags if t.startswith("ioc:")]
        assert len(ioc_tags) == 1
        assert "ip_address" in ioc_tags[0]
        assert "192.168.1.1" in ioc_tags[0]

    def test_mitre_tags_included(self) -> None:
        report = make_report(findings=[
            make_finding(mitre_ids=["T1059", "T1071"])
        ])
        events = report_to_events(report)
        mitre_tags = [t for t in events[0].tags if t.startswith("mitre:")]
        assert "mitre:T1059" in mitre_tags
        assert "mitre:T1071" in mitre_tags

    def test_category_tag_included(self) -> None:
        report = make_report(findings=[
            make_finding(category=FindingCategory.LATERAL_MOVEMENT)
        ])
        events = report_to_events(report)
        assert "category:lateral_movement" in events[0].tags

    def test_raw_payload_contains_finding_details(self) -> None:
        report = make_report(findings=[
            make_finding(mitre_ids=["T1234"], with_ioc=True, assets=["server-1"])
        ])
        events = report_to_events(report)
        payload = events[0].raw_payload
        assert payload["report_id"] == report.report_id
        assert "T1234" in payload["mitre_attack_ids"]
        assert len(payload["ioc_indicators"]) == 1

    def test_affected_assets_carried_over(self) -> None:
        report = make_report(findings=[
            make_finding(assets=["db-server", "web-server"])
        ])
        events = report_to_events(report)
        assert "db-server" in events[0].affected_assets
        assert "web-server" in events[0].affected_assets

    def test_customer_id_preserved(self) -> None:
        report = make_report(findings=[make_finding()])
        events = report_to_events(report)
        assert all(e.customer_id == "cust-1" for e in events)

    def test_empty_findings(self) -> None:
        report = make_report(findings=[])
        assert report_to_events(report) == []


class TestSummaryEvent:
    def test_clean_report_returns_none(self) -> None:
        report = make_report(
            verdict=SandboxVerdict.CLEAN,
            findings=[],
            overall_severity=FindingSeverity.INFORMATIONAL,
        )
        assert summary_event(report) is None

    def test_malicious_report_returns_event(self) -> None:
        report = make_report(
            verdict=SandboxVerdict.MALICIOUS,
            findings=[make_finding(severity=FindingSeverity.HIGH)],
        )
        event = summary_event(report)
        assert event is not None
        assert event.severity == Severity.HIGH

    def test_summary_event_title_contains_verdict(self) -> None:
        report = make_report(verdict=SandboxVerdict.MALICIOUS)
        event = summary_event(report)
        assert event is not None
        assert "MALICIOUS" in event.title

    def test_summary_event_has_verdict_tag(self) -> None:
        report = make_report(verdict=SandboxVerdict.SUSPICIOUS)
        event = summary_event(report)
        assert event is not None
        assert "verdict:suspicious" in event.tags

    def test_summary_event_payload_has_counts(self) -> None:
        findings = [
            make_finding(severity=FindingSeverity.CRITICAL, title="c1"),
            make_finding(severity=FindingSeverity.HIGH, title="h1"),
        ]
        report = make_report(verdict=SandboxVerdict.MALICIOUS, findings=findings)
        event = summary_event(report)
        assert event is not None
        assert event.raw_payload["finding_count"] == 2
        assert event.raw_payload["critical_count"] == 1
