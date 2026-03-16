"""Execution models and mock adapters for security operations."""

from __future__ import annotations

from summer_puppy.execution.adapters.base import BaseAdapter
from summer_puppy.execution.adapters.mock_edr import MockEDRAdapter
from summer_puppy.execution.adapters.mock_firewall import MockFirewallAdapter
from summer_puppy.execution.adapters.mock_iam import MockIAMAdapter
from summer_puppy.execution.adapters.mock_patch import MockPatchAdapter
from summer_puppy.execution.models import (
    ExecutionPlan,
    ExecutionStep,
    VerificationCheck,
    VerificationReport,
)
from summer_puppy.execution.policy_gate import PolicyGate
from summer_puppy.execution.sandbox import ExecutionSandbox
from summer_puppy.execution.verifier import ExecutionVerifier

__all__ = [
    "BaseAdapter",
    "ExecutionPlan",
    "ExecutionSandbox",
    "ExecutionStep",
    "ExecutionVerifier",
    "MockEDRAdapter",
    "MockFirewallAdapter",
    "MockIAMAdapter",
    "MockPatchAdapter",
    "PolicyGate",
    "VerificationCheck",
    "VerificationReport",
]
