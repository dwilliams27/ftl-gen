"""Dependency injection for FastAPI routes."""

from functools import lru_cache

from ftl_gen.config import Settings, get_settings
from ftl_gen.core.slipstream import SlipstreamManager


@lru_cache
def get_slipstream() -> SlipstreamManager:
    """Get a cached SlipstreamManager instance."""
    return SlipstreamManager(get_settings())


def get_mods_dir():
    """Get the mods output directory, creating it if needed."""
    settings = get_settings()
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    return settings.output_dir
