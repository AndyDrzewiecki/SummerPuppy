"""Security sandbox analyzer — LLM-powered malware and vulnerability analysis pipeline."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

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

if TYPE_CHECKING:
    from summer_puppy.llm.client import LLMClient

_SYSTEM_PROMPT = (
    "You are a senior malware analyst and threat researcher at a cybersecurity firm. "
    "You analyze code, binaries, documents, and network artifacts to identify threats. "
    "You provide precise, structured findings with MITRE ATT&CK mappings and actionable "
    "remediation steps. Be thorough but concise. Never hallucinate IOCs — only report "
    "what is directly evidenced in the sample."
)

_ANALYSIS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["clean", "suspicious", "malicious", "unknown"],
        },
        "overall_severity": {
            "type": "string",
            "enum": ["informational", "low", "medium", "high", "critical"],
        },
        "summary": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "enum": [
                            "command_and_control",
                            "data_exfiltration",
                            "lateral_movement",
                            "privilege_escalation",
                            "persistence",
                            "defense_evasion",
                            "credential_access",
                            "discovery",
                            "execution",
                            "impact",
                            "vulnerability",
                            "policy_violation",
                        ],
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["informational", "low", "medium", "high", "critical"],
                    },
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "mitre_attack_ids": {"type": "array", "items": {"type": "string"}},
                    "ioc_indicators": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "ioc_type": {
                                    "type": "string",
                                    "enum": [
                                        "ip_address",
                                        "domain",
                                        "url",
                                        "file_hash_md5",
                                        "file_hash_sha256",
                                        "email",
                                        "registry_key",
                                        "process_name",
                                        "cve",
                                    ],
                                },
                                "value": {"type": "string"},
                                "confidence": {
                                    "type": "number",
                                    "minimum": 0,
                                    "maximum": 1,
                                },
                                "context": {"type": "string"},
                            },
                            "required": ["ioc_type", "value", "confidence"],
                        },
                    },
                    "affected_assets": {"type": "array", "items": {"type": "string"}},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                    "recommended_actions": {"type": "array", "items": {"type": "string"}},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                },
                "required": [
                    "category",
                    "severity",
                    "title",
                    "description",
                    "confidence",
                ],
            },
        },
    },
    "required": ["verdict", "overall_severity", "summary", "findings"],
}


def _build_analysis_prompt(submission: SampleSubmission) -> str:
    metadata_str = (
        "\n".join(f"  {k}: {v}" for k, v in submission.metadata.items())
        if submission.metadata
        else "  (none)"
    )
    filename_str = submission.filename or "(unnamed)"
    # Truncate very large content for LLM context limits
    content = submission.content
    if len(content) > 8000:
        content = content[:8000] + "\n... [truncated for analysis]"

    return (
        f"Analyze the following security sample and produce a structured findings report.\n\n"
        f"Sample Type: {submission.sample_type}\n"
        f"Filename: {filename_str}\n"
        f"Customer ID: {submission.customer_id}\n"
        f"Metadata:\n{metadata_str}\n\n"
        f"Sample Content:\n```\n{content}\n```\n\n"
        f"Perform a thorough analysis covering:\n"
        f"1. Static characteristics (file type, strings, imports, structure)\n"
        f"2. Behavioral indicators (what would this do when executed/opened?)\n"
        f"3. Network indicators (C2 communication, data exfiltration patterns)\n"
        f"4. Persistence mechanisms\n"
        f"5. Evasion techniques\n"
        f"6. CVE references if this is a vulnerability report\n\n"
        f"Map all findings to MITRE ATT&CK technique IDs where applicable.\n"
        f"List concrete IOCs with high confidence only."
    )


def _parse_findings(raw_findings: list[dict[str, Any]]) -> list[Finding]:
    findings = []
    for raw in raw_findings:
        iocs = []
        for raw_ioc in raw.get("ioc_indicators", []):
            try:
                iocs.append(
                    IndicatorOfCompromise(
                        ioc_type=IoCType(raw_ioc["ioc_type"]),
                        value=raw_ioc["value"],
                        confidence=float(raw_ioc.get("confidence", 0.5)),
                        context=raw_ioc.get("context", ""),
                    )
                )
            except (ValueError, KeyError):
                pass

        try:
            findings.append(
                Finding(
                    category=FindingCategory(raw["category"]),
                    severity=FindingSeverity(raw["severity"]),
                    title=raw["title"],
                    description=raw["description"],
                    mitre_attack_ids=raw.get("mitre_attack_ids", []),
                    ioc_indicators=iocs,
                    affected_assets=raw.get("affected_assets", []),
                    evidence=raw.get("evidence", []),
                    recommended_actions=raw.get("recommended_actions", []),
                    confidence=float(raw.get("confidence", 0.5)),
                )
            )
        except (ValueError, KeyError):
            pass
    return findings


class SandboxAnalyzer:
    """Analyzes security samples using an LLM to produce structured AnalysisReports."""

    def __init__(self, llm_client: LLMClient) -> None:
        self._llm_client = llm_client

    async def analyze(self, submission: SampleSubmission) -> AnalysisReport:
        """Run the full analysis pipeline on a sample submission."""
        start = time.monotonic()

        prompt = _build_analysis_prompt(submission)
        response = await self._llm_client.generate_structured(
            prompt=prompt,
            output_schema=_ANALYSIS_SCHEMA,
            system=_SYSTEM_PROMPT,
        )

        duration_ms = (time.monotonic() - start) * 1000
        structured = response.structured_output or {}

        verdict = SandboxVerdict(structured.get("verdict", SandboxVerdict.UNKNOWN))
        severity = FindingSeverity(
            structured.get("overall_severity", FindingSeverity.INFORMATIONAL)
        )
        summary = structured.get("summary", "Analysis completed.")
        raw_findings: list[dict[str, Any]] = structured.get("findings", [])
        findings = _parse_findings(raw_findings)

        return AnalysisReport(
            submission_id=submission.submission_id,
            customer_id=submission.customer_id,
            sample_type=submission.sample_type,
            verdict=verdict,
            overall_severity=severity,
            findings=findings,
            summary=summary,
            analysis_depth="llm_structured",
            analysis_duration_ms=duration_ms,
            raw_analysis=structured,
        )


class StubSandboxAnalyzer:
    """Deterministic stub for testing — returns a configurable canned report."""

    def __init__(
        self,
        verdict: SandboxVerdict = SandboxVerdict.CLEAN,
        severity: FindingSeverity = FindingSeverity.INFORMATIONAL,
        findings: list[Finding] | None = None,
        summary: str = "Stub analysis: no threats detected.",
    ) -> None:
        self._verdict = verdict
        self._severity = severity
        self._findings = findings or []
        self._summary = summary
        self.calls: list[SampleSubmission] = []

    async def analyze(self, submission: SampleSubmission) -> AnalysisReport:
        self.calls.append(submission)
        return AnalysisReport(
            submission_id=submission.submission_id,
            customer_id=submission.customer_id,
            sample_type=submission.sample_type,
            verdict=self._verdict,
            overall_severity=self._severity,
            findings=self._findings,
            summary=self._summary,
            analysis_depth="stub",
        )


# Protocol for type-checking both real and stub analyzers
class AnalyzerProtocol:
    async def analyze(self, submission: SampleSubmission) -> AnalysisReport: ...
