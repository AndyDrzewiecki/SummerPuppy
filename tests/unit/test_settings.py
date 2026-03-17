from __future__ import annotations

import pytest

from summer_puppy.api.settings import Settings, get_settings


@pytest.fixture(autouse=True)
def clear_settings_cache():
    yield
    get_settings.cache_clear()


def test_settings_defaults():
    s = Settings()
    assert s.app_secret_key == "dev-secret-change-in-prod"


def test_llm_enabled_defaults_false():
    s = Settings()
    assert s.llm_enabled is False


def test_get_settings_cache_identity():
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2
