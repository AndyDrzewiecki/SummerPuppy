"""Security sandbox data models — sample submissions, findings, and analysis reports."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class SampleType(StrEnum):
    MALWARE_BINARY = "malware_binary"
    SCRIPT = "script"
    DOCUMENT = "document"
    NETWORK_CAPTURE = "network_capture"
    MEMORY_DUMP = "memory_dump"
    VULNERABILITY_REPORT = "vulnerability_report"
    LOG_ARTIFACT = "log_artifact"


class SandboxVerdict(StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class FindingSeverity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(StrEnum):
    COMMAND_AND_CONTROL = "command_and_control"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    EXECUTION = "execution"
    IMPACT = "impact"
    VULNERABILITY = "vulnerability"
    POLICY_VIOLATION = "policy_violation"


class IoCType(StrEnum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA256 = "file_hash_sha256"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"
    PROCESS_NAME = "process_name"
    CVE = "cve"


class IndicatorOfCompromise(BaseModel):
    ioc_id: str = Field(default_factory=lambda: str(uuid4()))
    ioc_type: IoCType
    value: str
    confidence: float = Field(ge=0, le=1)
    context: str = ""


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    category: FindingCategory
    severity: FindingSeverity
    title: str
    description: str
    mitre_attack_ids: list[str] = Field(default_factory=list)
    ioc_indicators: list[IndicatorOfCompromise] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)


class SampleSubmission(BaseModel):
    submission_id: str = Field(default_factory=lambda: str(uuid4()))
    customer_id: str
    sample_type: SampleType
    content: str  # base64-encoded binary or raw text depending on type
    filename: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    submitted_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    submitted_by: str = "api"


class AnalysisReport(BaseModel):
    report_id: str = Field(default_factory=lambda: str(uuid4()))
    submission_id: str
    customer_id: str
    sample_type: SampleType
    verdict: SandboxVerdict
    overall_severity: FindingSeverity
    findings: list[Finding] = Field(default_factory=list)
    summary: str
    analysis_depth: str = "standard"
    analyzed_utc: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    analysis_duration_ms: float = 0.0
    raw_analysis: dict[str, Any] = Field(default_factory=dict)

    @property
    def critical_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == FindingSeverity.CRITICAL]

    @property
    def high_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == FindingSeverity.HIGH]

    @property
    def all_iocs(self) -> list[IndicatorOfCompromise]:
        return [ioc for finding in self.findings for ioc in finding.ioc_indicators]

    @property
    def all_mitre_ids(self) -> list[str]:
        seen: set[str] = set()
        result = []
        for finding in self.findings:
            for mid in finding.mitre_attack_ids:
                if mid not in seen:
                    seen.add(mid)
                    result.append(mid)
        return result


class SandboxSubmitRequest(BaseModel):
    sample_type: SampleType
    content: str
    filename: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class SandboxSubmitResponse(BaseModel):
    submission_id: str
    report_id: str
    verdict: SandboxVerdict
    overall_severity: FindingSeverity
    finding_count: int
    events_generated: int
    summary: str
