"""Unit tests for GitHub client implementations."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from summer_puppy.dev_bot.github_client import HttpGitHubClient, StubGitHubClient


class TestStubGitHubClient:
    @pytest.mark.asyncio
    async def test_create_branch_records_call(self) -> None:
        stub = StubGitHubClient()
        result = await stub.create_branch("org/repo", "feature-branch", "main")
        assert result == "feature-branch"
        assert len(stub.branches_created) == 1
        assert stub.branches_created[0]["repo"] == "org/repo"
        assert stub.branches_created[0]["branch"] == "feature-branch"
        assert stub.branches_created[0]["base_branch"] == "main"

    @pytest.mark.asyncio
    async def test_create_branch_multiple_calls(self) -> None:
        stub = StubGitHubClient()
        await stub.create_branch("org/repo", "branch-1", "main")
        await stub.create_branch("org/repo", "branch-2", "main")
        assert len(stub.branches_created) == 2

    @pytest.mark.asyncio
    async def test_create_file_records_call(self) -> None:
        stub = StubGitHubClient()
        url = await stub.create_file(
            "org/repo", "my-branch", "security/patch.sh", "#!/bin/bash", "Add patch"
        )
        assert len(stub.files_created) == 1
        assert stub.files_created[0]["path"] == "security/patch.sh"
        assert stub.files_created[0]["content"] == "#!/bin/bash"
        assert "org/repo" in url

    @pytest.mark.asyncio
    async def test_create_pull_request_returns_incrementing_pr_numbers(self) -> None:
        stub = StubGitHubClient()
        pr1_num, pr1_url = await stub.create_pull_request(
            "org/repo", "branch-1", "PR 1", "Body 1", "main"
        )
        pr2_num, pr2_url = await stub.create_pull_request(
            "org/repo", "branch-2", "PR 2", "Body 2", "main"
        )
        assert pr1_num == 1
        assert pr2_num == 2
        assert "1" in pr1_url
        assert "2" in pr2_url

    @pytest.mark.asyncio
    async def test_create_pull_request_records_pr(self) -> None:
        stub = StubGitHubClient()
        await stub.create_pull_request("org/repo", "branch-1", "My PR", "PR body", "main")
        assert len(stub.prs_created) == 1
        assert stub.prs_created[0]["title"] == "My PR"
        assert stub.prs_created[0]["body"] == "PR body"

    @pytest.mark.asyncio
    async def test_get_pr_status_returns_expected_structure(self) -> None:
        stub = StubGitHubClient()
        pr_num, _ = await stub.create_pull_request(
            "org/repo", "branch-1", "Test PR", "body", "main"
        )
        status = await stub.get_pr_status("org/repo", pr_num)
        assert status["number"] == pr_num
        assert status["state"] == "open"
        assert status["merged"] is False
        assert "html_url" in status
        assert "title" in status

    @pytest.mark.asyncio
    async def test_get_pr_status_for_unknown_pr(self) -> None:
        stub = StubGitHubClient()
        status = await stub.get_pr_status("org/repo", 9999)
        assert status["number"] == 9999
        assert "state" in status

    @pytest.mark.asyncio
    async def test_close_pull_request_updates_state(self) -> None:
        stub = StubGitHubClient()
        pr_num, _ = await stub.create_pull_request(
            "org/repo", "branch-1", "PR", "body", "main"
        )
        await stub.close_pull_request("org/repo", pr_num)
        status = await stub.get_pr_status("org/repo", pr_num)
        assert status["state"] == "closed"

    @pytest.mark.asyncio
    async def test_pr_counter_starts_at_one(self) -> None:
        stub = StubGitHubClient()
        assert stub.pr_counter == 1

    @pytest.mark.asyncio
    async def test_pr_url_contains_repo_and_number(self) -> None:
        stub = StubGitHubClient()
        pr_num, url = await stub.create_pull_request(
            "myorg/myrepo", "br", "title", "body", "main"
        )
        assert "myorg/myrepo" in url
        assert str(pr_num) in url


class TestHttpGitHubClient:
    def test_sets_authorization_header(self) -> None:
        client = HttpGitHubClient(token="ghp_test123")
        assert client._headers["Authorization"] == "Bearer ghp_test123"

    def test_sets_accept_header(self) -> None:
        client = HttpGitHubClient(token="tok")
        assert "application/vnd.github" in client._headers["Accept"]

    def test_custom_base_url(self) -> None:
        client = HttpGitHubClient(token="tok", base_url="https://github.example.com/api/v3")
        assert client._base_url == "https://github.example.com/api/v3"

    def test_default_base_url(self) -> None:
        client = HttpGitHubClient(token="tok")
        assert "api.github.com" in client._base_url

    @pytest.mark.asyncio
    async def test_create_branch_sends_authorization_header(self) -> None:
        client = HttpGitHubClient(token="ghp_secret")

        mock_response_ref = MagicMock()
        mock_response_ref.raise_for_status = MagicMock()
        mock_response_ref.json = MagicMock(return_value={"object": {"sha": "abc123"}})

        mock_response_create = MagicMock()
        mock_response_create.raise_for_status = MagicMock()
        mock_response_create.json = MagicMock(return_value={})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response_ref)
        mock_client.post = AsyncMock(return_value=mock_response_create)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("summer_puppy.dev_bot.github_client.httpx.AsyncClient", return_value=mock_client):
            result = await client.create_branch("org/repo", "new-branch", "main")

        assert result == "new-branch"
        call_kwargs = mock_client.get.call_args
        headers_used = call_kwargs[1].get("headers", call_kwargs[0][1] if len(call_kwargs[0]) > 1 else {})
        assert "Authorization" in headers_used
        assert "ghp_secret" in headers_used["Authorization"]

    @pytest.mark.asyncio
    async def test_create_pull_request_sends_authorization_header(self) -> None:
        client = HttpGitHubClient(token="ghp_mytoken")

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = MagicMock(
            return_value={"number": 5, "html_url": "https://github.com/org/repo/pull/5"}
        )

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("summer_puppy.dev_bot.github_client.httpx.AsyncClient", return_value=mock_client):
            num, url = await client.create_pull_request("org/repo", "br", "title", "body", "main")

        assert num == 5
        call_kwargs = mock_client.post.call_args
        headers_used = call_kwargs[1].get("headers", {})
        assert "Authorization" in headers_used
        assert "ghp_mytoken" in headers_used["Authorization"]
