"""Sprite mutation transforms for chaos mode.

Applies visual chaos to game sprites using FREE local Pillow transforms.

Note: Vanilla sprite extraction (VanillaSpriteExtractor) was removed because the
sprite file mappings were fabricated and incorrect.  Re-implement by deriving
mappings from animations.xml at extraction time when needed.
"""

import colorsys
from io import BytesIO
from random import Random

from PIL import Image, ImageEnhance, ImageOps


class SpriteMutator:
    """Applies chaos mutations to sprite images."""

    def __init__(self, chaos_level: float, seed: int | None = None):
        """Initialize mutator.

        Args:
            chaos_level: 0.0 to 1.0 chaos intensity
            seed: Random seed for reproducibility
        """
        self.chaos_level = max(0.0, min(1.0, chaos_level))
        self.rng = Random(seed)

    def mutate_sprite(self, image_data: bytes) -> bytes:
        """Apply chaos mutations to a sprite.

        Randomly applies various transforms based on chaos level:
        - Brightness adjustment
        - Contrast adjustment
        - Hue shift
        - Saturation adjustment
        - Color invert (rare)
        - Posterize (at high chaos)

        Args:
            image_data: PNG image data

        Returns:
            Mutated PNG image data
        """
        if self.chaos_level < 0.1:
            return image_data

        image = Image.open(BytesIO(image_data)).convert("RGBA")

        # Apply transforms based on chaos level and random rolls
        image = self._maybe_adjust_brightness(image)
        image = self._maybe_adjust_contrast(image)
        image = self._maybe_shift_hue(image)
        image = self._maybe_adjust_saturation(image)
        image = self._maybe_invert_colors(image)
        image = self._maybe_posterize(image)
        image = self._maybe_add_noise(image)

        # Save back to bytes
        buffer = BytesIO()
        image.save(buffer, format="PNG")
        return buffer.getvalue()

    def _maybe_adjust_brightness(self, image: Image.Image) -> Image.Image:
        if self.rng.random() > 0.7:
            return image
        max_adjustment = 0.3 * self.chaos_level
        factor = 1.0 + self.rng.uniform(-max_adjustment, max_adjustment)
        rgb = image.convert("RGB")
        enhancer = ImageEnhance.Brightness(rgb)
        rgb = enhancer.enhance(factor)
        result = rgb.convert("RGBA")
        result.putalpha(image.split()[3])
        return result

    def _maybe_adjust_contrast(self, image: Image.Image) -> Image.Image:
        if self.rng.random() > 0.6:
            return image
        max_adjustment = 0.2 * self.chaos_level
        factor = 1.0 + self.rng.uniform(-max_adjustment, max_adjustment)
        rgb = image.convert("RGB")
        enhancer = ImageEnhance.Contrast(rgb)
        rgb = enhancer.enhance(factor)
        result = rgb.convert("RGBA")
        result.putalpha(image.split()[3])
        return result

    def _maybe_shift_hue(self, image: Image.Image) -> Image.Image:
        if self.rng.random() > 0.5:
            return image
        max_shift = 360 * self.chaos_level
        hue_shift = self.rng.uniform(0, max_shift)
        return self._shift_hue(image, hue_shift / 360.0)

    def _shift_hue(self, image: Image.Image, shift: float) -> Image.Image:
        pixels = image.load()
        width, height = image.size
        result = Image.new("RGBA", (width, height))
        result_pixels = result.load()
        for y in range(height):
            for x in range(width):
                r, g, b, a = pixels[x, y]
                if a == 0:
                    result_pixels[x, y] = (0, 0, 0, 0)
                    continue
                h, s, v = colorsys.rgb_to_hsv(r / 255.0, g / 255.0, b / 255.0)
                h = (h + shift) % 1.0
                r2, g2, b2 = colorsys.hsv_to_rgb(h, s, v)
                result_pixels[x, y] = (int(r2 * 255), int(g2 * 255), int(b2 * 255), a)
        return result

    def _maybe_adjust_saturation(self, image: Image.Image) -> Image.Image:
        if self.rng.random() > 0.5:
            return image
        max_adjustment = 0.4 * self.chaos_level
        factor = 1.0 + self.rng.uniform(-max_adjustment, max_adjustment)
        rgb = image.convert("RGB")
        enhancer = ImageEnhance.Color(rgb)
        rgb = enhancer.enhance(factor)
        result = rgb.convert("RGBA")
        result.putalpha(image.split()[3])
        return result

    def _maybe_invert_colors(self, image: Image.Image) -> Image.Image:
        if self.chaos_level < 0.7:
            return image
        if self.rng.random() > (self.chaos_level - 0.7) * 0.33:
            return image
        rgb = image.convert("RGB")
        rgb = ImageOps.invert(rgb)
        result = rgb.convert("RGBA")
        result.putalpha(image.split()[3])
        return result

    def _maybe_posterize(self, image: Image.Image) -> Image.Image:
        if self.chaos_level < 0.5:
            return image
        if self.rng.random() > (self.chaos_level - 0.5) * 0.4:
            return image
        bits = int(8 - (self.chaos_level * 4))
        bits = max(2, min(8, bits))
        rgb = image.convert("RGB")
        rgb = ImageOps.posterize(rgb, bits)
        result = rgb.convert("RGBA")
        result.putalpha(image.split()[3])
        return result

    def _maybe_add_noise(self, image: Image.Image) -> Image.Image:
        if self.chaos_level < 0.8:
            return image
        if self.rng.random() > (self.chaos_level - 0.8) * 0.5:
            return image
        pixels = image.load()
        width, height = image.size
        noise_intensity = int((self.chaos_level - 0.8) * 100)
        for y in range(height):
            for x in range(width):
                r, g, b, a = pixels[x, y]
                if a > 0:
                    r = max(0, min(255, r + self.rng.randint(-noise_intensity, noise_intensity)))
                    g = max(0, min(255, g + self.rng.randint(-noise_intensity, noise_intensity)))
                    b = max(0, min(255, b + self.rng.randint(-noise_intensity, noise_intensity)))
                    pixels[x, y] = (r, g, b, a)
        return image
