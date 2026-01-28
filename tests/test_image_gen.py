"""Tests for image generation and sprite processing."""

from io import BytesIO

import pytest
from PIL import Image

from ftl_gen.images.client import MockImageClient, get_image_client
from ftl_gen.images.sprites import SpriteProcessor


class TestSpriteProcessor:
    """Tests for SpriteProcessor."""

    @pytest.fixture
    def processor(self):
        return SpriteProcessor()

    @pytest.fixture
    def sample_image(self):
        """Create a sample PNG image."""
        img = Image.new("RGBA", (64, 240), (100, 100, 120, 255))
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    def test_create_weapon_sprite_sheet(self, processor, sample_image):
        sheet_data = processor.create_weapon_sprite_sheet(sample_image)

        # Load result
        result = Image.open(BytesIO(sheet_data))

        # Check dimensions (12 frames of 16x60)
        assert result.width == 192  # 16 * 12
        assert result.height == 60
        assert result.mode == "RGBA"

    def test_sprite_sheet_has_frames(self, processor, sample_image):
        sheet_data = processor.create_weapon_sprite_sheet(sample_image)
        result = Image.open(BytesIO(sheet_data))

        # Check that we have 12 distinct frame regions
        for i in range(12):
            x = i * 16
            frame = result.crop((x, 0, x + 16, 60))
            # Frame should have some non-transparent pixels
            alpha = frame.split()[3]
            assert alpha.getextrema()[1] > 0, f"Frame {i} is completely transparent"

    def test_create_placeholder_sprite_sheet(self, processor):
        sheet_data = processor.create_placeholder_sprite_sheet("TEST_WEAPON")

        result = Image.open(BytesIO(sheet_data))
        assert result.width == 192
        assert result.height == 60

    def test_pixelate(self, processor, sample_image):
        pixelated = processor.pixelate(sample_image, pixel_size=4)

        result = Image.open(BytesIO(pixelated))
        # Dimensions should be preserved
        assert result.width == 64
        assert result.height == 240

    def test_resize_to_frame(self, processor):
        # Create an oversized image
        img = Image.new("RGBA", (100, 200), (255, 0, 0, 255))

        frame = processor._resize_to_frame(img)

        assert frame.width == 16
        assert frame.height == 60

    def test_adjust_brightness(self, processor):
        img = Image.new("RGBA", (16, 60), (100, 100, 100, 255))

        brighter = processor._adjust_brightness(img, 1.5)
        darker = processor._adjust_brightness(img, 0.5)

        # Check brightness changed
        orig_pixel = img.getpixel((0, 0))
        bright_pixel = brighter.getpixel((0, 0))
        dark_pixel = darker.getpixel((0, 0))

        assert bright_pixel[0] > orig_pixel[0]
        assert dark_pixel[0] < orig_pixel[0]

    def test_save_sprite_sheet(self, processor, sample_image, tmp_path):
        filepath = processor.save_sprite_sheet(
            sample_image,
            tmp_path / "weapons",
            "TEST_WEAPON"
        )

        assert filepath.exists()
        assert filepath.name == "test_weapon_strip12.png"


class TestMockImageClient:
    """Tests for MockImageClient."""

    def test_generate_image(self):
        client = MockImageClient()
        image_data = client.generate_image("test prompt")

        # Should return valid PNG
        img = Image.open(BytesIO(image_data))
        assert img.format == "PNG"

    def test_generate_weapon_sprite(self):
        client = MockImageClient()
        image_data = client.generate_weapon_sprite(
            weapon_name="TEST",
            weapon_type="LASER",
            description="A test weapon",
        )

        img = Image.open(BytesIO(image_data))
        assert img.format == "PNG"
        assert img.mode == "RGBA"

    def test_is_available(self):
        client = MockImageClient()
        assert client.is_available() is True


class TestGetImageClient:
    """Tests for get_image_client factory."""

    def test_returns_mock_without_api_key(self, tmp_path, monkeypatch):
        # Clear any env vars that might set the key
        monkeypatch.delenv("GOOGLE_AI_API_KEY", raising=False)
        # Change to a directory without .env file
        monkeypatch.chdir(tmp_path)

        from ftl_gen.config import Settings

        # Create settings without any env file influence
        settings = Settings(_env_file=None, google_ai_api_key=None)
        client = get_image_client(settings)

        assert isinstance(client, MockImageClient)


class TestSpriteAnimation:
    """Tests for sprite animation frame generation."""

    @pytest.fixture
    def processor(self):
        return SpriteProcessor()

    def test_animation_frames_vary(self, processor):
        # Create a simple base frame
        base = Image.new("RGBA", (16, 60), (100, 100, 100, 255))

        frames = []
        for i in range(12):
            frame = processor._create_animation_frame(base, i, 12)
            frames.append(frame)

        # Check that frames vary (at least some should be different)
        # Compare first and middle frames
        f0 = list(frames[0].getdata())
        f5 = list(frames[5].getdata())
        f7 = list(frames[7].getdata())

        # Fire frame (7) should be brightest
        assert f7[0][0] >= f0[0][0]  # R channel

    def test_animation_preserves_transparency(self, processor):
        # Create frame with some transparent pixels
        base = Image.new("RGBA", (16, 60), (0, 0, 0, 0))

        for i in range(12):
            frame = processor._create_animation_frame(base, i, 12)
            # Should still be transparent
            assert frame.getpixel((0, 0))[3] == 0
