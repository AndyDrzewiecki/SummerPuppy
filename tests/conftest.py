"""Shared test fixtures and factory functions for SummerPuppy."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from summer_puppy.trust.models import (
    ActionClass,
    AutoApprovalPolicy,
    TrustPhase,
    TrustProfile,
)

if TYPE_CHECKING:
    from collections.abc import Callable


@pytest.fixture()
def security_event_factory() -> Callable[..., dict[str, Any]]:
    """Factory for SecurityEvent dicts.

    Returns a callable that produces security event dictionaries.
    This is a stub returning dicts until the events module is implemented (Story 1).
    """

    def _make(**overrides: Any) -> dict[str, Any]:
        defaults: dict[str, Any] = {
            "event_id": "evt-001",
            "source": "siem",
            "severity": "MEDIUM",
            "action_class": "patch_deployment",
            "confidence_score": 0.9,
            "qa_passed": True,
            "rollback_available": True,
            "estimated_risk": "LOW",
            "affected_asset_classes": [],
        }
        defaults.update(overrides)
        return defaults

    return _make


@pytest.fixture()
def trust_profile_factory() -> Callable[..., TrustProfile]:
    """Factory for TrustProfile instances."""

    def _make(**overrides: Any) -> TrustProfile:
        defaults: dict[str, Any] = {
            "customer_id": "cust-test",
            "trust_phase": TrustPhase.MANUAL,
            "total_recommendations": 0,
            "total_approvals": 0,
            "total_rejections": 0,
            "positive_outcome_rate": 0.0,
        }
        defaults.update(overrides)
        return TrustProfile(**defaults)

    return _make


@pytest.fixture()
def auto_approval_policy_factory() -> Callable[..., AutoApprovalPolicy]:
    """Factory for AutoApprovalPolicy instances."""

    def _make(**overrides: Any) -> AutoApprovalPolicy:
        defaults: dict[str, Any] = {
            "customer_id": "cust-test",
            "action_class": ActionClass.PATCH_DEPLOYMENT,
        }
        defaults.update(overrides)
        return AutoApprovalPolicy(**defaults)

    return _make
