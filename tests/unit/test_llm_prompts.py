from __future__ import annotations

import pytest

from summer_puppy.llm.prompts import ANALYZE_EVENT, GENERATE_RECOMMENDATION


class TestAnalyzeEventPrompt:
    def test_renders_with_all_variables(self) -> None:
        rendered = ANALYZE_EVENT.render(
            title="Suspicious Login",
            source="SIEM",
            severity="HIGH",
            description="Multiple failed login attempts",
            affected_assets="server-01, server-02",
            raw_payload='{"ip": "10.0.0.1"}',
            knowledge_context="Previous incidents from same IP range",
        )
        assert "Suspicious Login" in rendered
        assert "SIEM" in rendered
        assert "HIGH" in rendered
        assert "Multiple failed login attempts" in rendered
        assert "server-01, server-02" in rendered
        assert '{"ip": "10.0.0.1"}' in rendered
        assert "Previous incidents from same IP range" in rendered

    def test_contains_expected_placeholders(self) -> None:
        expected = {
            "title",
            "source",
            "severity",
            "description",
            "affected_assets",
            "raw_payload",
            "knowledge_context",
        }
        for var in expected:
            assert "{" + var + "}" in ANALYZE_EVENT.template

    def test_missing_variable_raises(self) -> None:
        with pytest.raises(KeyError):
            ANALYZE_EVENT.render(title="only title")

    def test_contains_analyst_instruction(self) -> None:
        assert "security analyst" in ANALYZE_EVENT.template.lower()


class TestGenerateRecommendationPrompt:
    def test_renders_with_all_variables(self) -> None:
        rendered = GENERATE_RECOMMENDATION.render(
            analysis_summary="Ransomware detected on endpoint",
            title="Ransomware Alert",
            severity="CRITICAL",
            affected_assets="workstation-42",
            customer_id="cust-abc",
            trust_phase="supervised",
            positive_outcome_rate="0.85",
            action_classes="network_isolation, process_termination",
        )
        assert "Ransomware detected on endpoint" in rendered
        assert "Ransomware Alert" in rendered
        assert "CRITICAL" in rendered
        assert "workstation-42" in rendered
        assert "cust-abc" in rendered
        assert "supervised" in rendered
        assert "0.85" in rendered
        assert "network_isolation, process_termination" in rendered

    def test_contains_expected_placeholders(self) -> None:
        expected = {
            "analysis_summary",
            "title",
            "severity",
            "affected_assets",
            "customer_id",
            "trust_phase",
            "positive_outcome_rate",
            "action_classes",
        }
        for var in expected:
            assert "{" + var + "}" in GENERATE_RECOMMENDATION.template

    def test_missing_variable_raises(self) -> None:
        with pytest.raises(KeyError):
            GENERATE_RECOMMENDATION.render(analysis_summary="only summary")

    def test_contains_remediation_instruction(self) -> None:
        assert "remediation" in GENERATE_RECOMMENDATION.template.lower()
