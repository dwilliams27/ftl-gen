"""Configuration and status endpoints."""

from fastapi import APIRouter

from ftl_gen.api.deps import get_slipstream
from ftl_gen.api.models import ConfigStatus
from ftl_gen.config import get_settings

router = APIRouter()


@router.get("/config", response_model=ConfigStatus)
def get_config():
    """Get current configuration status."""
    settings = get_settings()
    slipstream = get_slipstream()

    # Check for API keys without exposing them
    llm_key_ok = False
    try:
        settings.get_llm_api_key()
        llm_key_ok = True
    except ValueError:
        pass

    return ConfigStatus(
        llm_provider=settings.llm_provider,
        llm_model=settings.llm_model,
        llm_key_configured=llm_key_ok,
        image_model=settings.image_model,
        image_key_configured=bool(settings.google_ai_api_key),
        slipstream_available=slipstream.is_available(),
        slipstream_path=str(slipstream.path) if slipstream.path else None,
        output_dir=str(settings.output_dir),
    )
