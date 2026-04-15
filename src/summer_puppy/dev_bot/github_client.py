"""GitHub API client — Protocol, HTTP implementation, and stub for testing."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

import httpx


@runtime_checkable
class GitHubClient(Protocol):
    async def create_branch(self, repo: str, branch: str, base_branch: str) -> str: ...

    async def create_file(
        self, repo: str, branch: str, path: str, content: str, message: str
    ) -> str: ...

    async def create_pull_request(
        self, repo: str, branch: str, title: str, body: str, base_branch: str
    ) -> tuple[int, str]: ...

    async def get_pr_status(self, repo: str, pr_number: int) -> dict[str, Any]: ...

    async def close_pull_request(self, repo: str, pr_number: int) -> None: ...


class HttpGitHubClient:
    """Real GitHub client using GitHub REST API via httpx."""

    def __init__(self, token: str, base_url: str = "https://api.github.com") -> None:
        self._token = token
        self._base_url = base_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def create_branch(self, repo: str, branch: str, base_branch: str) -> str:
        """Create a new branch from base_branch. Returns the new branch name."""
        async with httpx.AsyncClient() as client:
            # Get base branch SHA
            ref_resp = await client.get(
                f"{self._base_url}/repos/{repo}/git/ref/heads/{base_branch}",
                headers=self._headers,
            )
            ref_resp.raise_for_status()
            sha = ref_resp.json()["object"]["sha"]

            # Create new branch
            create_resp = await client.post(
                f"{self._base_url}/repos/{repo}/git/refs",
                headers=self._headers,
                json={"ref": f"refs/heads/{branch}", "sha": sha},
            )
            create_resp.raise_for_status()
        return branch

    async def create_file(
        self, repo: str, branch: str, path: str, content: str, message: str
    ) -> str:
        """Create or update a file in the repository. Returns the file URL."""
        import base64

        encoded_content = base64.b64encode(content.encode()).decode()
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self._base_url}/repos/{repo}/contents/{path}",
                headers=self._headers,
                json={
                    "message": message,
                    "content": encoded_content,
                    "branch": branch,
                },
            )
            resp.raise_for_status()
            return resp.json().get("content", {}).get("html_url", "")

    async def create_pull_request(
        self, repo: str, branch: str, title: str, body: str, base_branch: str
    ) -> tuple[int, str]:
        """Create a pull request. Returns (pr_number, pr_url)."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._base_url}/repos/{repo}/pulls",
                headers=self._headers,
                json={
                    "title": title,
                    "body": body,
                    "head": branch,
                    "base": base_branch,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data["number"], data["html_url"]

    async def get_pr_status(self, repo: str, pr_number: int) -> dict[str, Any]:
        """Fetch pull request status."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self._base_url}/repos/{repo}/pulls/{pr_number}",
                headers=self._headers,
            )
            resp.raise_for_status()
            data = resp.json()
            return {
                "number": data["number"],
                "state": data["state"],
                "merged": data.get("merged", False),
                "title": data["title"],
                "html_url": data["html_url"],
            }

    async def close_pull_request(self, repo: str, pr_number: int) -> None:
        """Close a pull request without merging."""
        async with httpx.AsyncClient() as client:
            resp = await client.patch(
                f"{self._base_url}/repos/{repo}/pulls/{pr_number}",
                headers=self._headers,
                json={"state": "closed"},
            )
            resp.raise_for_status()


class StubGitHubClient:
    """Deterministic stub for testing. Tracks all calls."""

    def __init__(self) -> None:
        self.branches_created: list[dict[str, Any]] = []
        self.files_created: list[dict[str, Any]] = []
        self.prs_created: list[dict[str, Any]] = []
        self.pr_counter: int = 1
        self._pr_statuses: dict[int, dict[str, Any]] = {}

    async def create_branch(self, repo: str, branch: str, base_branch: str) -> str:
        self.branches_created.append(
            {"repo": repo, "branch": branch, "base_branch": base_branch}
        )
        return branch

    async def create_file(
        self, repo: str, branch: str, path: str, content: str, message: str
    ) -> str:
        self.files_created.append(
            {"repo": repo, "branch": branch, "path": path, "content": content, "message": message}
        )
        return f"https://github.com/{repo}/blob/{branch}/{path}"

    async def create_pull_request(
        self, repo: str, branch: str, title: str, body: str, base_branch: str
    ) -> tuple[int, str]:
        pr_number = self.pr_counter
        self.pr_counter += 1
        pr_url = f"https://github.com/{repo}/pull/{pr_number}"
        self.prs_created.append(
            {
                "repo": repo,
                "branch": branch,
                "title": title,
                "body": body,
                "base_branch": base_branch,
                "pr_number": pr_number,
                "pr_url": pr_url,
            }
        )
        self._pr_statuses[pr_number] = {
            "number": pr_number,
            "state": "open",
            "merged": False,
            "title": title,
            "html_url": pr_url,
        }
        return pr_number, pr_url

    async def get_pr_status(self, repo: str, pr_number: int) -> dict[str, Any]:
        if pr_number in self._pr_statuses:
            return dict(self._pr_statuses[pr_number])
        return {
            "number": pr_number,
            "state": "open",
            "merged": False,
            "title": "",
            "html_url": f"https://github.com/{repo}/pull/{pr_number}",
        }

    async def close_pull_request(self, repo: str, pr_number: int) -> None:
        if pr_number in self._pr_statuses:
            self._pr_statuses[pr_number]["state"] = "closed"
