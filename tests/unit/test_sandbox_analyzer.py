"""Unit tests for the security sandbox analyzer."""

from __future__ import annotations

import pytest

from summer_puppy.sandbox.analyzer import StubSandboxAnalyzer, _build_analysis_prompt, _parse_findings
from summer_puppy.sandbox.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    SampleSubmission,
    SampleType,
    SandboxVerdict,
)


def make_submission(
    content: str = "malicious code",
    sample_type: SampleType = SampleType.SCRIPT,
) -> SampleSubmission:
    return SampleSubmission(
        customer_id="cust-test",
        sample_type=sample_type,
        content=content,
        filename="test.py",
    )


def make_finding_dict(
    category: str = "execution",
    severity: str = "high",
    title: str = "Test",
) -> dict[str, object]:
    return {
        "category": category,
        "severity": severity,
        "title": title,
        "description": "Test description",
        "confidence": 0.85,
        "mitre_attack_ids": ["T1059"],
        "ioc_indicators": [
            {"ioc_type": "ip_address", "value": "10.0.0.1", "confidence": 0.9}
        ],
        "affected_assets": ["server-1"],
        "evidence": ["line 42: os.system(cmd)"],
        "recommended_actions": ["Terminate process"],
    }


class TestBuildAnalysisPrompt:
    def test_includes_sample_type(self) -> None:
        sub = make_submission(sample_type=SampleType.MALWARE_BINARY)
        prompt = _build_analysis_prompt(sub)
        assert "malware_binary" in prompt

    def test_includes_customer_id(self) -> None:
        sub = make_submission()
        prompt = _build_analysis_prompt(sub)
        assert "cust-test" in prompt

    def test_truncates_large_content(self) -> None:
        large_content = "A" * 10_000
        sub = make_submission(content=large_content)
        prompt = _build_analysis_prompt(sub)
        assert "truncated" in prompt
        assert len(prompt) < 15_000

    def test_includes_filename(self) -> None:
        sub = make_submission()
        prompt = _build_analysis_prompt(sub)
        assert "test.py" in prompt

    def test_includes_mitre_instruction(self) -> None:
        sub = make_submission()
        prompt = _build_analysis_prompt(sub)
        assert "MITRE ATT&CK" in prompt


class TestParseFindings:
    def test_parses_valid_finding(self) -> None:
        raw = [make_finding_dict()]
        findings = _parse_findings(raw)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.EXECUTION
        assert findings[0].severity == FindingSeverity.HIGH
        assert findings[0].title == "Test"
        assert findings[0].confidence == 0.85
        assert len(findings[0].ioc_indicators) == 1
        assert findings[0].ioc_indicators[0].value == "10.0.0.1"

    def test_skips_invalid_category(self) -> None:
        raw = [make_finding_dict(category="not_a_real_category")]
        findings = _parse_findings(raw)
        assert findings == []

    def test_skips_invalid_severity(self) -> None:
        raw = [make_finding_dict(severity="ultra_mega_bad")]
        findings = _parse_findings(raw)
        assert findings == []

    def test_skips_invalid_ioc_type(self) -> None:
        raw = [{
            **make_finding_dict(),
            "ioc_indicators": [{"ioc_type": "not_a_type", "value": "x", "confidence": 0.9}],
        }]
        findings = _parse_findings(raw)
        assert len(findings) == 1
        assert findings[0].ioc_indicators == []

    def test_parses_multiple_findings(self) -> None:
        raw = [
            make_finding_dict(category="execution", title="Finding 1"),
            make_finding_dict(category="persistence", title="Finding 2"),
            make_finding_dict(category="discovery", title="Finding 3"),
        ]
        findings = _parse_findings(raw)
        assert len(findings) == 3

    def test_empty_list(self) -> None:
        assert _parse_findings([]) == []


class TestStubSandboxAnalyzer:
    @pytest.mark.asyncio
    async def test_returns_configured_verdict(self) -> None:
        analyzer = StubSandboxAnalyzer(
            verdict=SandboxVerdict.MALICIOUS,
            severity=FindingSeverity.CRITICAL,
        )
        sub = make_submission()
        report = await analyzer.analyze(sub)
        assert report.verdict == SandboxVerdict.MALICIOUS
        assert report.overall_severity == FindingSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_records_calls(self) -> None:
        analyzer = StubSandboxAnalyzer()
        sub1 = make_submission()
        sub2 = make_submission()
        await analyzer.analyze(sub1)
        await analyzer.analyze(sub2)
        assert len(analyzer.calls) == 2
        assert analyzer.calls[0].submission_id == sub1.submission_id

    @pytest.mark.asyncio
    async def test_returns_configured_findings(self) -> None:
        finding = Finding(
            category=FindingCategory.LATERAL_MOVEMENT,
            severity=FindingSeverity.HIGH,
            title="Lateral movement detected",
            description="Test",
            confidence=0.9,
        )
        analyzer = StubSandboxAnalyzer(findings=[finding])
        sub = make_submission()
        report = await analyzer.analyze(sub)
        assert len(report.findings) == 1
        assert report.findings[0].title == "Lateral movement detected"

    @pytest.mark.asyncio
    async def test_report_links_to_submission(self) -> None:
        analyzer = StubSandboxAnalyzer()
        sub = make_submission()
        report = await analyzer.analyze(sub)
        assert report.submission_id == sub.submission_id
        assert report.customer_id == sub.customer_id
