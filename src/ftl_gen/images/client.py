"""Gemini image generation client for FTL sprites."""

import base64
from dataclasses import dataclass, field
from io import BytesIO

from PIL import Image

from ftl_gen.config import Settings
from ftl_gen.images.prompts import drone_sprite_prompt, weapon_sprite_prompt


@dataclass
class ImageUsage:
    """Track image generation usage and costs."""

    images_generated: int = 0
    cost_per_image: float = 0.039  # Gemini 2.0 Flash image pricing

    @property
    def total_cost(self) -> float:
        return self.images_generated * self.cost_per_image

    def record_generation(self):
        self.images_generated += 1


class GeminiImageClient:
    """Client for generating images using Google Gemini (Nano Banana)."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or Settings()
        self._client = None
        self._types = None
        self.usage = ImageUsage()

    def _get_client(self):
        """Lazily initialize the Gemini client."""
        if self._client is None:
            try:
                from google import genai
                from google.genai import types

                self._client = genai.Client(api_key=self.settings.google_ai_api_key)
                self._types = types
            except ImportError:
                raise ImportError(
                    "google-genai package required for image generation. "
                    "Install with: pip install google-genai"
                )
        return self._client

    def generate_image(self, prompt: str) -> bytes:
        """Generate an image from a text prompt.

        Args:
            prompt: Text description of the image to generate

        Returns:
            PNG image data as bytes
        """
        client = self._get_client()
        types = self._types

        response = client.models.generate_content(
            model=self.settings.image_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_modalities=["IMAGE"],
            )
        )

        # Extract image from response
        for part in response.candidates[0].content.parts:
            if hasattr(part, "inline_data") and part.inline_data:
                # Track usage
                self.usage.record_generation()

                # Handle both base64 string and raw bytes
                data = part.inline_data.data
                if isinstance(data, str):
                    return base64.b64decode(data)
                return data

        raise ValueError("No image generated in response")

    def generate_weapon_sprite(
        self,
        weapon_name: str,
        weapon_type: str,
        description: str,
        visual_description: str | None = None,
    ) -> bytes:
        """Generate a weapon sprite image.

        Args:
            weapon_name: Name of the weapon
            weapon_type: Type (LASER, BEAM, etc.)
            description: Weapon description
            visual_description: Optional visual description override

        Returns:
            PNG image data as bytes
        """
        prompt = weapon_sprite_prompt(
            weapon_name=weapon_name,
            weapon_type=weapon_type,
            description=description,
            visual_description=visual_description,
        )

        return self.generate_image(prompt)

    def generate_drone_sprite(
        self,
        drone_name: str,
        drone_type: str,
        description: str,
    ) -> bytes:
        """Generate a drone sprite image.

        Args:
            drone_name: Name of the drone
            drone_type: Type (COMBAT, DEFENSE, etc.)
            description: Drone description

        Returns:
            PNG image data as bytes
        """
        prompt = drone_sprite_prompt(
            drone_name=drone_name,
            drone_type=drone_type,
            description=description,
        )

        return self.generate_image(prompt)

    def is_available(self) -> bool:
        """Check if image generation is configured."""
        return bool(self.settings.google_ai_api_key)


class MockImageClient:
    """Mock image client for testing without API calls."""

    def __init__(self):
        self.usage = ImageUsage(cost_per_image=0.0)  # Free for mock

    def generate_image(self, prompt: str) -> bytes:
        """Generate a placeholder image."""
        return self._create_placeholder(64, 240)

    def generate_weapon_sprite(
        self,
        weapon_name: str,
        weapon_type: str,
        description: str,
        visual_description: str | None = None,
    ) -> bytes:
        """Generate a placeholder weapon sprite."""
        return self._create_placeholder(64, 240)

    def generate_drone_sprite(
        self,
        drone_name: str,
        drone_type: str,
        description: str,
    ) -> bytes:
        """Generate a placeholder drone sprite."""
        return self._create_placeholder(200, 80)

    def _create_placeholder(self, width: int, height: int) -> bytes:
        """Create a simple placeholder image."""
        # Create a simple gradient placeholder
        img = Image.new("RGBA", (width, height), (0, 0, 0, 0))
        pixels = img.load()

        # Draw a simple shape
        for x in range(width):
            for y in range(height):
                # Create a simple weapon-like silhouette
                if height // 4 < y < 3 * height // 4:
                    if width // 4 < x < 3 * width // 4:
                        pixels[x, y] = (100, 100, 120, 255)
                    elif x >= 3 * width // 4:
                        # Barrel
                        if height // 3 < y < 2 * height // 3:
                            pixels[x, y] = (80, 80, 100, 255)

        buffer = BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    def is_available(self) -> bool:
        return True


def get_image_client(settings: Settings | None = None) -> GeminiImageClient | MockImageClient:
    """Get an image client, falling back to mock if not configured."""
    settings = settings or Settings()

    if settings.google_ai_api_key:
        return GeminiImageClient(settings)
    else:
        return MockImageClient()
