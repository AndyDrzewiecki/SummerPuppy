"""Dev bot module — automated patch generation and PR submission for security findings."""

from __future__ import annotations

from summer_puppy.dev_bot.github_client import GitHubClient, HttpGitHubClient, StubGitHubClient
from summer_puppy.dev_bot.models import (
    DevBotPR,
    DevBotQualityRecord,
    PatchCandidate,
    PatchStatus,
    PatchTestCheck,
    PatchTestResult,
    PatchType,
    PROutcome,
    UserStory,
)
from summer_puppy.dev_bot.patch_generator import PatchGenerator
from summer_puppy.dev_bot.patch_tester import PatchTester
from summer_puppy.dev_bot.pr_submitter import PRSubmitter
from summer_puppy.dev_bot.story_builder import StoryBuilder

__all__ = [
    "DevBotPR",
    "DevBotQualityRecord",
    "GitHubClient",
    "HttpGitHubClient",
    "PatchCandidate",
    "PatchGenerator",
    "PatchStatus",
    "PatchTestCheck",
    "PatchTestResult",
    "PatchTester",
    "PatchType",
    "PROutcome",
    "PRSubmitter",
    "StoryBuilder",
    "StubGitHubClient",
    "UserStory",
]
