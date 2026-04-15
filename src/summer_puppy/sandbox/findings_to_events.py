"""Convert sandbox AnalysisReport findings into SecurityEvent objects for pipeline ingestion."""

from __future__ import annotations

from summer_puppy.events.models import EventSource, SecurityEvent, Severity
from summer_puppy.sandbox.models import AnalysisReport, FindingSeverity

_FINDING_TO_SEVERITY: dict[FindingSeverity, Severity] = {
    FindingSeverity.INFORMATIONAL: Severity.LOW,
    FindingSeverity.LOW: Severity.LOW,
    FindingSeverity.MEDIUM: Severity.MEDIUM,
    FindingSeverity.HIGH: Severity.HIGH,
    FindingSeverity.CRITICAL: Severity.CRITICAL,
}


def report_to_events(report: AnalysisReport) -> list[SecurityEvent]:
    """Convert an AnalysisReport into one SecurityEvent per significant finding.

    Rules:
    - INFORMATIONAL findings are skipped (not worth a pipeline run).
    - Each LOW/MEDIUM/HIGH/CRITICAL finding becomes one SecurityEvent.
    - The event's raw_payload carries full finding detail for downstream analysis.
    - IOCs are packed into the event's tags for quick filtering.
    - The report's MITRE IDs are rolled up onto the event.
    """
    events: list[SecurityEvent] = []

    for finding in report.findings:
        if finding.severity == FindingSeverity.INFORMATIONAL:
            continue

        severity = _FINDING_TO_SEVERITY[finding.severity]
        ioc_tags = [f"ioc:{ioc.ioc_type}:{ioc.value}" for ioc in finding.ioc_indicators]
        mitre_tags = [f"mitre:{mid}" for mid in finding.mitre_attack_ids]
        category_tag = f"category:{finding.category}"

        event = SecurityEvent(
            customer_id=report.customer_id,
            source=EventSource.AGENT,
            severity=severity,
            title=f"[Sandbox] {finding.title}",
            description=finding.description,
            raw_payload={
                "report_id": report.report_id,
                "submission_id": report.submission_id,
                "finding_id": finding.finding_id,
                "category": finding.category,
                "finding_severity": finding.severity,
                "verdict": report.verdict,
                "mitre_attack_ids": finding.mitre_attack_ids,
                "ioc_indicators": [
                    {
                        "ioc_type": ioc.ioc_type,
                        "value": ioc.value,
                        "confidence": ioc.confidence,
                        "context": ioc.context,
                    }
                    for ioc in finding.ioc_indicators
                ],
                "evidence": finding.evidence,
                "recommended_actions": finding.recommended_actions,
                "confidence": finding.confidence,
                "sample_type": report.sample_type,
            },
            affected_assets=finding.affected_assets,
            tags=[category_tag] + ioc_tags + mitre_tags,
        )
        events.append(event)

    return events


def summary_event(report: AnalysisReport) -> SecurityEvent | None:
    """Return a single summary SecurityEvent for the full report, or None if clean/unknown.

    Use this when you want one event per report rather than one per finding.
    """
    if report.verdict in ("clean", "unknown") and not report.critical_findings:
        return None

    severity = _FINDING_TO_SEVERITY[report.overall_severity]
    all_ioc_tags = [f"ioc:{ioc.ioc_type}:{ioc.value}" for ioc in report.all_iocs]
    mitre_tags = [f"mitre:{mid}" for mid in report.all_mitre_ids]
    finding_summary = "; ".join(f.title for f in report.findings[:5])
    if len(report.findings) > 5:
        finding_summary += f" (+{len(report.findings) - 5} more)"

    return SecurityEvent(
        customer_id=report.customer_id,
        source=EventSource.AGENT,
        severity=severity,
        title=f"[Sandbox Report] {report.verdict.upper()}: {report.sample_type}",
        description=f"{report.summary}\n\nFindings: {finding_summary}",
        raw_payload={
            "report_id": report.report_id,
            "submission_id": report.submission_id,
            "verdict": report.verdict,
            "overall_severity": report.overall_severity,
            "finding_count": len(report.findings),
            "critical_count": len(report.critical_findings),
            "high_count": len(report.high_findings),
            "mitre_attack_ids": report.all_mitre_ids,
            "sample_type": report.sample_type,
        },
        affected_assets=list({
            asset for finding in report.findings for asset in finding.affected_assets
        }),
        tags=all_ioc_tags + mitre_tags + [f"verdict:{report.verdict}"],
    )
