"""Integration test configuration.

Integration tests require Docker for testcontainers.
Tests in this directory are automatically skipped when Docker is not available.
"""

from __future__ import annotations

import shutil

import pytest

pytestmark = pytest.mark.skipif(
    not shutil.which("docker"),
    reason="Docker not available — skipping integration tests",
)
