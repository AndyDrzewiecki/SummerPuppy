"""Skill registry protocol and in-memory implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from summer_puppy.skills.models import ClusterSkillProfile, SkillProfile


@runtime_checkable
class SkillRegistry(Protocol):
    """Protocol for skill profile storage backends."""

    def get_agent_profile(self, agent_id: str) -> SkillProfile | None: ...

    def update_agent_profile(self, profile: SkillProfile) -> None: ...

    def get_cluster_profile(self, cluster_id: str) -> ClusterSkillProfile | None: ...

    def update_cluster_profile(self, profile: ClusterSkillProfile) -> None: ...


class InMemorySkillRegistry:
    """In-memory implementation of SkillRegistry for testing and development."""

    def __init__(self) -> None:
        self._agent_profiles: dict[str, SkillProfile] = {}
        self._cluster_profiles: dict[str, ClusterSkillProfile] = {}

    def get_agent_profile(self, agent_id: str) -> SkillProfile | None:
        return self._agent_profiles.get(agent_id)

    def update_agent_profile(self, profile: SkillProfile) -> None:
        self._agent_profiles[profile.agent_id] = profile

    def get_cluster_profile(self, cluster_id: str) -> ClusterSkillProfile | None:
        return self._cluster_profiles.get(cluster_id)

    def update_cluster_profile(self, profile: ClusterSkillProfile) -> None:
        self._cluster_profiles[profile.cluster_id] = profile
