"""Tests for DevBot API endpoints — Phase 11, Sprint 11."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from summer_puppy.dev_bot.models import (
    DevBotPR,
    DevBotQualityRecord,
    PatchCandidate,
    PatchStatus,
    PatchType,
    PROutcome,
    UserStory,
)
from summer_puppy.sandbox.models import FindingSeverity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _request(app, method: str, path: str, **kwargs):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await getattr(client, method)(path, **kwargs)


def _make_story(customer_id: str = "cust-1") -> UserStory:
    return UserStory(
        story_id="story-001",
        finding_id="finding-001",
        customer_id=customer_id,
        correlation_id="corr-1",
        title="Test story",
        description="Fix this",
        severity=FindingSeverity.HIGH,
    )


def _make_patch(
    customer_id: str = "cust-1",
    patch_id: str = "patch-001",
) -> PatchCandidate:
    return PatchCandidate(
        patch_id=patch_id,
        story_id="story-001",
        customer_id=customer_id,
        correlation_id="corr-1",
        patch_type=PatchType.FIREWALL_RULE,
        title="Block malicious IP",
        description="Add firewall rule",
        content="iptables -A INPUT -s 1.2.3.4 -j DROP",
        rollback_content="iptables -D INPUT -s 1.2.3.4 -j DROP",
        confidence_score=0.9,
    )


def _make_pr(
    pr_id: str = "pr-001",
    customer_id: str = "cust-1",
    patch_id: str = "patch-001",
    outcome: PROutcome = PROutcome.PENDING,
) -> DevBotPR:
    return DevBotPR(
        pr_id=pr_id,
        patch_id=patch_id,
        story_id="story-001",
        customer_id=customer_id,
        correlation_id="corr-1",
        status=PatchStatus.PR_OPEN,
        outcome=outcome,
    )


def _make_quality_record(
    pr_id: str = "pr-001",
    customer_id: str = "cust-1",
) -> DevBotQualityRecord:
    return DevBotQualityRecord(
        record_id="rec-001",
        pr_id=pr_id,
        patch_id="patch-001",
        story_id="story-001",
        customer_id=customer_id,
        correlation_id="corr-1",
        outcome=PROutcome.MERGED,
        patch_type=PatchType.FIREWALL_RULE,
        pre_submit_test_passed=True,
        merged_without_change=True,
        patch_quality_score=1.0,
    )


def _make_mock_handler(
    customer_id: str = "cust-1",
    pr_id: str = "pr-001",
    patch_id: str = "patch-001",
) -> MagicMock:
    handler = MagicMock()
    story = _make_story(customer_id=customer_id)
    patch = _make_patch(customer_id=customer_id, patch_id=patch_id)
    pr = _make_pr(pr_id=pr_id, customer_id=customer_id, patch_id=patch_id)

    handler.get_stories = MagicMock(return_value=[story])
    handler.get_patches = MagicMock(return_value=[patch])
    handler.get_prs = MagicMock(return_value=[pr])
    handler.get_pr_by_id = MagicMock(return_value=pr)
    handler.update_pr = MagicMock()

    # Quality tracker
    qt = MagicMock()
    record = _make_quality_record(pr_id=pr_id, customer_id=customer_id)
    qt.record_outcome = MagicMock(return_value=record)
    qt.get_records = MagicMock(return_value=[record])
    qt.approval_rate = MagicMock(return_value=1.0)
    handler._quality_tracker = qt

    return handler


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_state():
    from summer_puppy.api.state import init_app_state, reset_app_state

    reset_app_state()
    state = init_app_state()
    yield state
    reset_app_state()


@pytest.fixture
def app():
    from summer_puppy.api.app import app as _app

    return _app


@pytest.fixture
def state(reset_state):
    return reset_state


@pytest.fixture
def token():
    from summer_puppy.api.auth.jwt_handler import create_token

    return create_token("cust-1", scopes=["events:write"])


@pytest.fixture
def headers(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def mock_handler(state) -> MagicMock:
    handler = _make_mock_handler()
    state.dev_bot_handler = handler
    return handler


# ---------------------------------------------------------------------------
# Stories endpoint
# ---------------------------------------------------------------------------


class TestDevBotStoriesEndpoint:
    async def test_get_stories_returns_200(self, app, headers, mock_handler) -> None:
        resp = await _request(app, "get", "/api/v1/customers/cust-1/dev-bot/stories",
                               headers=headers)
        assert resp.status_code == 200

    async def test_get_stories_returns_list(self, app, headers, mock_handler) -> None:
        resp = await _request(app, "get", "/api/v1/customers/cust-1/dev-bot/stories",
                               headers=headers)
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 1

    async def test_get_stories_no_handler_503(self, app, headers, state) -> None:
        # No handler set on state
        resp = await _request(app, "get", "/api/v1/customers/cust-1/dev-bot/stories",
                               headers=headers)
        assert resp.status_code == 503

    async def test_get_stories_wrong_customer_403(self, app, mock_handler) -> None:
        from summer_puppy.api.auth.jwt_handler import create_token

        token = create_token("cust-2", scopes=["events:write"])
        headers_cust2 = {"Authorization": f"Bearer {token}"}
        resp = await _request(app, "get", "/api/v1/customers/cust-1/dev-bot/stories",
                               headers=headers_cust2)
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Patches endpoint
# ---------------------------------------------------------------------------


class TestDevBotPatchesEndpoint:
    async def test_get_patches_returns_200(self, app, headers, mock_handler) -> None:
        resp = await _request(app, "get", "/api/v1/customers/cust-1/dev-bot/patches",
                               headers=headers)
        assert resp.status_code == 200

    async def test_get_patches_returns_list(self, app, headers, mock_handler) -> None:
        resp = await _request(app, "get", "/api/v1/customers/cust-1/dev-bot/patches",
                               headers=headers)
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 1


# ---------------------------------------------------------------------------
# PRs endpoint
# ---------------------------------------------------------------------------


class TestDevBotPRsEndpoint:
    async def test_get_prs_returns_200(self, app, headers, mock_handler) -> None:
        resp = await _request(app, "get", "/api/v1/customers/cust-1/dev-bot/prs",
                               headers=headers)
        assert resp.status_code == 200

    async def test_get_prs_returns_list(self, app, headers, mock_handler) -> None:
        resp = await _request(app, "get", "/api/v1/customers/cust-1/dev-bot/prs",
                               headers=headers)
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["pr_id"] == "pr-001"


# ---------------------------------------------------------------------------
# POST outcome endpoint
# ---------------------------------------------------------------------------


class TestDevBotOutcomeEndpoint:
    async def test_post_outcome_records_quality(self, app, headers, mock_handler) -> None:
        body = {"outcome": "merged", "merged_without_change": True, "rejection_reason": ""}
        resp = await _request(
            app, "post",
            "/api/v1/customers/cust-1/dev-bot/prs/pr-001/outcome",
            json=body, headers=headers,
        )
        assert resp.status_code == 200

    async def test_post_outcome_calls_quality_tracker(
        self, app, headers, mock_handler
    ) -> None:
        body = {"outcome": "merged", "merged_without_change": True, "rejection_reason": ""}
        await _request(
            app, "post",
            "/api/v1/customers/cust-1/dev-bot/prs/pr-001/outcome",
            json=body, headers=headers,
        )
        mock_handler._quality_tracker.record_outcome.assert_called_once()

    async def test_post_outcome_returns_quality_record(
        self, app, headers, mock_handler
    ) -> None:
        body = {"outcome": "merged", "merged_without_change": True, "rejection_reason": ""}
        resp = await _request(
            app, "post",
            "/api/v1/customers/cust-1/dev-bot/prs/pr-001/outcome",
            json=body, headers=headers,
        )
        data = resp.json()
        assert "record_id" in data
        assert data["outcome"] == "merged"

    async def test_post_outcome_pr_not_found_404(self, app, headers, mock_handler) -> None:
        mock_handler.get_pr_by_id = MagicMock(return_value=None)
        body = {"outcome": "rejected", "merged_without_change": False, "rejection_reason": "Bad"}
        resp = await _request(
            app, "post",
            "/api/v1/customers/cust-1/dev-bot/prs/no-such-pr/outcome",
            json=body, headers=headers,
        )
        assert resp.status_code == 404

    async def test_post_outcome_customer_mismatch_403(self, app, headers, mock_handler) -> None:
        # PR belongs to cust-2, but we're authenticating as cust-1 and accessing cust-1's path
        wrong_pr = _make_pr(pr_id="pr-001", customer_id="cust-2", patch_id="patch-001")
        mock_handler.get_pr_by_id = MagicMock(return_value=wrong_pr)
        body = {"outcome": "merged", "merged_without_change": True, "rejection_reason": ""}
        resp = await _request(
            app, "post",
            "/api/v1/customers/cust-1/dev-bot/prs/pr-001/outcome",
            json=body, headers=headers,
        )
        assert resp.status_code == 403

    async def test_post_outcome_rejected_with_reason(self, app, headers, mock_handler) -> None:
        body = {
            "outcome": "rejected",
            "merged_without_change": False,
            "rejection_reason": "Breaks tests",
        }
        resp = await _request(
            app, "post",
            "/api/v1/customers/cust-1/dev-bot/prs/pr-001/outcome",
            json=body, headers=headers,
        )
        assert resp.status_code == 200
        call_kwargs = mock_handler._quality_tracker.record_outcome.call_args
        assert call_kwargs.kwargs.get("rejection_reason") == "Breaks tests" or \
               "Breaks tests" in str(call_kwargs)


# ---------------------------------------------------------------------------
# Quality endpoint
# ---------------------------------------------------------------------------


class TestDevBotQualityEndpoint:
    async def test_get_quality_returns_200(self, app, headers, mock_handler) -> None:
        resp = await _request(app, "get", "/api/v1/customers/cust-1/dev-bot/quality",
                               headers=headers)
        assert resp.status_code == 200

    async def test_get_quality_has_approval_rate(self, app, headers, mock_handler) -> None:
        resp = await _request(app, "get", "/api/v1/customers/cust-1/dev-bot/quality",
                               headers=headers)
        data = resp.json()
        assert "approval_rate" in data
        assert data["approval_rate"] == 1.0

    async def test_get_quality_has_total_records(self, app, headers, mock_handler) -> None:
        resp = await _request(app, "get", "/api/v1/customers/cust-1/dev-bot/quality",
                               headers=headers)
        data = resp.json()
        assert "total_records" in data
        assert data["total_records"] == 1

    async def test_get_quality_has_records_list(self, app, headers, mock_handler) -> None:
        resp = await _request(app, "get", "/api/v1/customers/cust-1/dev-bot/quality",
                               headers=headers)
        data = resp.json()
        assert "records" in data
        assert isinstance(data["records"], list)

    async def test_get_quality_no_handler_503(self, app, headers, state) -> None:
        resp = await _request(app, "get", "/api/v1/customers/cust-1/dev-bot/quality",
                               headers=headers)
        assert resp.status_code == 503
