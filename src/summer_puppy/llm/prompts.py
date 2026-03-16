from __future__ import annotations

from summer_puppy.llm.models import PromptTemplate

ANALYZE_EVENT = PromptTemplate(
    template=(
        "You are a senior security analyst. Analyze this security event:\n"
        "\n"
        "Title: {title}\n"
        "Source: {source}\n"
        "Severity: {severity}\n"
        "Description: {description}\n"
        "Affected Assets: {affected_assets}\n"
        "Raw Payload: {raw_payload}\n"
        "\n"
        "Historical Context:\n"
        "{knowledge_context}\n"
        "\n"
        "Provide a structured threat assessment including threat type, attack vector,"
        " affected systems, IOC indicators, severity assessment, confidence level,"
        " reasoning, recommended actions, and MITRE ATT&CK technique IDs."
    )
)

GENERATE_RECOMMENDATION = PromptTemplate(
    template=(
        "You are a security operations automation system generating"
        " remediation recommendations.\n"
        "\n"
        "Analysis Summary:\n"
        "{analysis_summary}\n"
        "\n"
        "Security Event:\n"
        "- Title: {title}\n"
        "- Severity: {severity}\n"
        "- Affected Assets: {affected_assets}\n"
        "\n"
        "Trust Profile:\n"
        "- Customer: {customer_id}\n"
        "- Trust Phase: {trust_phase}\n"
        "- Success Rate: {positive_outcome_rate}\n"
        "\n"
        "Available Action Classes: {action_classes}\n"
        "\n"
        "Generate a specific remediation recommendation with: action_class,"
        " description, reasoning, confidence_score (0-1), estimated_risk,"
        " rollback_plan, and affected_asset_classes."
    )
)
