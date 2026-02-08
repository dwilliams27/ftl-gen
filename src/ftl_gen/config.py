"""Configuration and environment loading."""

import os
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings

load_dotenv()


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # LLM Provider
    llm_provider: Literal["claude", "openai"] = Field(
        default="claude", alias="LLM_PROVIDER"
    )
    anthropic_api_key: str | None = Field(default=None, alias="ANTHROPIC_API_KEY")
    openai_api_key: str | None = Field(default=None, alias="OPENAI_API_KEY")
    llm_model: str = Field(
        default="claude-sonnet-4-5-20251101", alias="LLM_MODEL"
    )

    # Image Generation
    google_ai_api_key: str | None = Field(default=None, alias="GOOGLE_AI_API_KEY")
    image_model: str = Field(default="gemini-2.5-flash-image", alias="IMAGE_MODEL")

    # Paths
    slipstream_path: Path | None = Field(default=None, alias="SLIPSTREAM_PATH")
    output_dir: Path = Field(default=Path("./mods"), alias="OUTPUT_DIR")

    model_config = {"env_file": ".env", "extra": "ignore"}

    def get_llm_api_key(self) -> str:
        """Get the API key for the configured LLM provider."""
        if self.llm_provider == "claude":
            if not self.anthropic_api_key:
                raise ValueError("ANTHROPIC_API_KEY is required when using Claude")
            return self.anthropic_api_key
        else:
            if not self.openai_api_key:
                raise ValueError("OPENAI_API_KEY is required when using OpenAI")
            return self.openai_api_key

    @property
    def ftl_log_path(self) -> Path:
        """Path to FTL's log file."""
        return Path.home() / "Library" / "Application Support" / "FasterThanLight" / "FTL.log"

    def find_ftl_executable(self) -> Path | None:
        """Auto-detect FTL executable on macOS."""
        search_paths = [
            # Steam install
            Path.home() / "Library" / "Application Support" / "Steam"
            / "steamapps" / "common" / "FTL Faster Than Light"
            / "FTL.app" / "Contents" / "MacOS" / "FTL",
            # Direct /Applications install
            Path("/Applications/FTL.app/Contents/MacOS/FTL"),
        ]
        for path in search_paths:
            if path.exists():
                return path
        return None

    def find_slipstream(self) -> Path | None:
        """Auto-detect Slipstream installation path."""
        if self.slipstream_path and self.slipstream_path.exists():
            return self.slipstream_path

        # Common locations to check
        search_paths = [
            Path.home() / "Documents" / "SlipstreamModManager",
            Path.home() / "Documents" / "Slipstream Mod Manager",
            Path("/Applications/SlipstreamModManager"),
        ]

        # Also check for versioned directories
        docs_dir = Path.home() / "Documents"
        if docs_dir.exists():
            for item in docs_dir.iterdir():
                if item.is_dir() and "slipstream" in item.name.lower():
                    search_paths.append(item)

        for path in search_paths:
            if path.exists():
                cli_script = path / "modman-cli.sh"
                if cli_script.exists():
                    return path

        return None


_settings_instance: Settings | None = None


def get_settings() -> Settings:
    """Get application settings singleton."""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = Settings()
    return _settings_instance
