"""Sprite mutation transforms for chaos mode.

Applies visual chaos to game sprites using FREE local Pillow transforms.
"""

import colorsys
from io import BytesIO
from pathlib import Path
from random import Random

from PIL import Image, ImageEnhance, ImageFilter, ImageOps


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
        """Adjust brightness with chaos-scaled randomness."""
        if self.rng.random() > 0.7:  # 70% chance
            return image

        # Range: ±30% at chaos=1.0
        max_adjustment = 0.3 * self.chaos_level
        factor = 1.0 + self.rng.uniform(-max_adjustment, max_adjustment)

        # Apply to RGB only, preserve alpha
        rgb = image.convert("RGB")
        enhancer = ImageEnhance.Brightness(rgb)
        rgb = enhancer.enhance(factor)

        # Restore alpha
        result = rgb.convert("RGBA")
        result.putalpha(image.split()[3])
        return result

    def _maybe_adjust_contrast(self, image: Image.Image) -> Image.Image:
        """Adjust contrast with chaos-scaled randomness."""
        if self.rng.random() > 0.6:  # 60% chance
            return image

        # Range: ±20% at chaos=1.0
        max_adjustment = 0.2 * self.chaos_level
        factor = 1.0 + self.rng.uniform(-max_adjustment, max_adjustment)

        rgb = image.convert("RGB")
        enhancer = ImageEnhance.Contrast(rgb)
        rgb = enhancer.enhance(factor)

        result = rgb.convert("RGBA")
        result.putalpha(image.split()[3])
        return result

    def _maybe_shift_hue(self, image: Image.Image) -> Image.Image:
        """Shift hue with chaos-scaled randomness."""
        if self.rng.random() > 0.5:  # 50% chance
            return image

        # Range: 0-360° shift scaled by chaos
        max_shift = 360 * self.chaos_level
        hue_shift = self.rng.uniform(0, max_shift)

        return self._shift_hue(image, hue_shift / 360.0)

    def _shift_hue(self, image: Image.Image, shift: float) -> Image.Image:
        """Shift hue of an image while preserving alpha.

        Args:
            image: Source RGBA image
            shift: Hue shift amount (0.0 to 1.0 = 0 to 360 degrees)

        Returns:
            Hue-shifted image
        """
        # Get pixel data
        pixels = image.load()
        width, height = image.size

        # Create new image
        result = Image.new("RGBA", (width, height))
        result_pixels = result.load()

        for y in range(height):
            for x in range(width):
                r, g, b, a = pixels[x, y]

                if a == 0:
                    result_pixels[x, y] = (0, 0, 0, 0)
                    continue

                # Convert to HSV
                h, s, v = colorsys.rgb_to_hsv(r / 255.0, g / 255.0, b / 255.0)

                # Shift hue
                h = (h + shift) % 1.0

                # Convert back to RGB
                r2, g2, b2 = colorsys.hsv_to_rgb(h, s, v)
                result_pixels[x, y] = (
                    int(r2 * 255),
                    int(g2 * 255),
                    int(b2 * 255),
                    a,
                )

        return result

    def _maybe_adjust_saturation(self, image: Image.Image) -> Image.Image:
        """Adjust saturation with chaos-scaled randomness."""
        if self.rng.random() > 0.5:  # 50% chance
            return image

        # Range: ±40% at chaos=1.0
        max_adjustment = 0.4 * self.chaos_level
        factor = 1.0 + self.rng.uniform(-max_adjustment, max_adjustment)

        rgb = image.convert("RGB")
        enhancer = ImageEnhance.Color(rgb)
        rgb = enhancer.enhance(factor)

        result = rgb.convert("RGBA")
        result.putalpha(image.split()[3])
        return result

    def _maybe_invert_colors(self, image: Image.Image) -> Image.Image:
        """Invert colors (rare, high chaos only)."""
        # Only at chaos > 0.7, 10% chance scaled by chaos
        if self.chaos_level < 0.7:
            return image

        if self.rng.random() > (self.chaos_level - 0.7) * 0.33:  # Max 10% at chaos=1.0
            return image

        # Invert RGB, preserve alpha
        rgb = image.convert("RGB")
        rgb = ImageOps.invert(rgb)

        result = rgb.convert("RGBA")
        result.putalpha(image.split()[3])
        return result

    def _maybe_posterize(self, image: Image.Image) -> Image.Image:
        """Reduce color depth (posterize) at high chaos."""
        # Only at chaos > 0.5, probability increases with chaos
        if self.chaos_level < 0.5:
            return image

        if self.rng.random() > (self.chaos_level - 0.5) * 0.4:  # Max 20% at chaos=1.0
            return image

        # Posterize: reduce bits per channel (8 = normal, 1 = 2 colors)
        # Scale bits from 8 (no effect) to 2 (heavy posterize)
        bits = int(8 - (self.chaos_level * 4))  # 8 at chaos=0, 4 at chaos=1
        bits = max(2, min(8, bits))

        rgb = image.convert("RGB")
        rgb = ImageOps.posterize(rgb, bits)

        result = rgb.convert("RGBA")
        result.putalpha(image.split()[3])
        return result

    def _maybe_add_noise(self, image: Image.Image) -> Image.Image:
        """Add visual noise at very high chaos."""
        if self.chaos_level < 0.8:
            return image

        if self.rng.random() > (self.chaos_level - 0.8) * 0.5:  # Max 10% at chaos=1.0
            return image

        # Add random pixel noise
        pixels = image.load()
        width, height = image.size

        noise_intensity = int((self.chaos_level - 0.8) * 100)  # 0-20 at high chaos

        for y in range(height):
            for x in range(width):
                r, g, b, a = pixels[x, y]
                if a > 0:  # Only affect visible pixels
                    r = max(0, min(255, r + self.rng.randint(-noise_intensity, noise_intensity)))
                    g = max(0, min(255, g + self.rng.randint(-noise_intensity, noise_intensity)))
                    b = max(0, min(255, b + self.rng.randint(-noise_intensity, noise_intensity)))
                    pixels[x, y] = (r, g, b, a)

        return image


class VanillaSpriteExtractor:
    """Extracts sprites from FTL game files using Slipstream."""

    # Map weapon blueprint names to their sprite files
    # Format: blueprint_name -> sprite filename (without path)
    # These are the strip12 weapon mount sprites (not projectile sprites)
    WEAPON_SPRITES = {
        # Lasers
        "BASIC_LASER": "basic_laser_strip12.png",
        "BURST_LASER_2": "burst_laser_2_strip12.png",
        "BURST_LASER_3": "burst_laser_3_strip12.png",
        "HEAVY_LASER": "heavy_laser_strip12.png",
        "HEAVY_LASER_2": "heavy_laser_2_strip12.png",
        "LASER_CHAINGUN": "laser_chaingun_strip12.png",
        "DUAL_LASER": "dual_laser_strip12.png",
        "LASER_CHARGEGUN": "laser_chargegun_strip12.png",
        "LASER_CHARGEGUN_2": "laser_chargegun_2_strip12.png",
        "SCATTER_LASER": "scatter_laser_strip12.png",
        "SCATTER_LASER_2": "scatter_laser_2_strip12.png",
        # Beams
        "BEAM_1": "beam_1_strip12.png",
        "BEAM_2": "beam_2_strip12.png",
        "BEAM_HULL": "beam_hull_strip12.png",
        "BEAM_GLAIVE": "beam_glaive_strip12.png",
        "BEAM_FIRE": "beam_fire_strip12.png",
        "BEAM_BIO": "beam_bio_strip12.png",
        "BEAM_HULL_SMASHER": "beam_hull_smasher_strip12.png",
        "BEAM_HULL_SMASHER_2": "beam_hull_smasher_2_strip12.png",
        # Missiles
        "MISSILES": "missiles_strip12.png",
        "MISSILES_2": "missiles_2_strip12.png",
        "MISSILES_BREACH": "missiles_breach_strip12.png",
        "MISSILES_HULL": "missiles_hull_strip12.png",
        "MISSILES_BIG": "missiles_big_strip12.png",
        "MISSILES_ENERGY": "missiles_energy_strip12.png",
        "MISSILES_CLUSTER": "missiles_cluster_strip12.png",
        # Bombs
        "BOMB_ION": "bomb_ion_strip12.png",
        "BOMB_FIRE": "bomb_fire_strip12.png",
        "BOMB_BREACH_2": "bomb_breach_2_strip12.png",
        "BOMB_BREACH": "bomb_breach_strip12.png",
        "BOMB_SMALL": "bomb_small_strip12.png",
        "BOMB_STUN": "bomb_stun_strip12.png",
        "BOMB_HEAL": "bomb_heal_strip12.png",
        "BOMB_LOCKDOWN": "bomb_lockdown_strip12.png",
        # Ions
        "ION_BLAST": "ion_blast_strip12.png",
        "ION_BLAST_2": "ion_blast_2_strip12.png",
        "CHAIN_ION": "chain_ion_strip12.png",
        "ION_HEAVY": "ion_heavy_strip12.png",
        "ION_CHARGEGUN": "ion_chargegun_strip12.png",
        # Crystals
        "CRYSTAL_1": "crystal_burst_1_strip12.png",
        "CRYSTAL_2": "crystal_burst_2_strip12.png",
        "CRYSTAL_HEAVY": "crystal_heavy_1_strip12.png",
        "CRYSTAL_HEAVY_2": "crystal_heavy_2_strip12.png",
    }

    # Drone sprites
    DRONE_SPRITES = {
        "COMBAT_1": "owasp_2_sheet.png",
        "COMBAT_2": "owasp_1_sheet.png",
        "COMBAT_BEAM": "owasp_beam_sheet.png",
        "COMBAT_BEAM_2": "owasp_beam2_sheet.png",
        "COMBAT_FIRE": "owasp_fire_sheet.png",
        "COMBAT_ION": "owasp_ion_sheet.png",
        "DEFENSE_1": "anti_drone_sheet.png",
        "DEFENSE_2": "anti_projectile_sheet.png",
        "ANTI_COMBAT": "owasp_anti_sheet.png",
        "SHIELD": "shield_drone_sheet.png",
        "REPAIR": "repair_sheet.png",
        "SHIP_REPAIR": "battle2_sheet.png",
        "BOARDER_ION": "boarder_sheet.png",
        "BATTLE": "battle1_sheet.png",
    }

    def __init__(self, slipstream_path: Path | None = None):
        """Initialize extractor.

        Args:
            slipstream_path: Path to Slipstream installation
        """
        if slipstream_path is None:
            from ftl_gen.config import get_settings
            slipstream_path = get_settings().find_slipstream()
        self.slipstream_path = slipstream_path
        self._extracted_dir: Path | None = None

    @property
    def is_available(self) -> bool:
        """Check if extraction is available."""
        return self.slipstream_path is not None

    def extract_all(self, output_dir: Path) -> bool:
        """Extract all FTL resources using Slipstream.

        Args:
            output_dir: Directory to extract to

        Returns:
            True if extraction succeeded
        """
        if not self.slipstream_path:
            return False

        import subprocess

        cli_path = self.slipstream_path / "modman-cli.sh"
        output_dir.mkdir(parents=True, exist_ok=True)

        try:
            result = subprocess.run(
                [str(cli_path), f"--extract-dats={output_dir}"],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=self.slipstream_path,
            )
            self._extracted_dir = output_dir
            return result.returncode == 0
        except Exception:
            return False

    def get_weapon_sprite(self, weapon_name: str) -> bytes | None:
        """Get a weapon's sprite data.

        Args:
            weapon_name: Weapon blueprint name (e.g., "BASIC_LASER")

        Returns:
            PNG data or None if not found
        """
        if not self._extracted_dir:
            return None

        sprite_file = self.WEAPON_SPRITES.get(weapon_name)
        if not sprite_file:
            return None

        sprite_path = self._extracted_dir / "img" / "weapons" / sprite_file
        if sprite_path.exists():
            return sprite_path.read_bytes()

        return None

    def get_drone_sprite(self, drone_name: str) -> bytes | None:
        """Get a drone's sprite data.

        Args:
            drone_name: Drone blueprint name (e.g., "COMBAT_1")

        Returns:
            PNG data or None if not found
        """
        if not self._extracted_dir:
            return None

        sprite_file = self.DRONE_SPRITES.get(drone_name)
        if not sprite_file:
            return None

        sprite_path = self._extracted_dir / "img" / "ship" / sprite_file
        if sprite_path.exists():
            return sprite_path.read_bytes()

        return None

    def get_all_weapon_sprites(self) -> dict[str, bytes]:
        """Get all available weapon sprites.

        Returns:
            Dict mapping weapon names to PNG data
        """
        sprites = {}
        for weapon_name in self.WEAPON_SPRITES:
            data = self.get_weapon_sprite(weapon_name)
            if data:
                sprites[weapon_name] = data
        return sprites

    def get_all_drone_sprites(self) -> dict[str, bytes]:
        """Get all available drone sprites.

        Returns:
            Dict mapping drone names to PNG data
        """
        sprites = {}
        for drone_name in self.DRONE_SPRITES:
            data = self.get_drone_sprite(drone_name)
            if data:
                sprites[drone_name] = data
        return sprites


def mutate_vanilla_sprites(
    chaos_level: float,
    seed: int | None = None,
    slipstream_path: Path | None = None,
    temp_dir: Path | None = None,
) -> tuple[dict[str, bytes], dict[str, bytes]]:
    """Extract and mutate vanilla sprites for chaos mode.

    Args:
        chaos_level: Chaos intensity 0.0-1.0
        seed: Random seed for reproducibility
        slipstream_path: Path to Slipstream installation
        temp_dir: Directory for extracted files (created if None)

    Returns:
        Tuple of (weapon_sprites, drone_sprites) dicts mapping
        mod paths to mutated PNG data
    """
    import tempfile

    weapon_sprites: dict[str, bytes] = {}
    drone_sprites: dict[str, bytes] = {}

    extractor = VanillaSpriteExtractor(slipstream_path)
    if not extractor.is_available:
        return weapon_sprites, drone_sprites

    # Extract to temp directory
    if temp_dir is None:
        temp_dir = Path(tempfile.mkdtemp(prefix="ftl_chaos_"))

    if not extractor.extract_all(temp_dir):
        return weapon_sprites, drone_sprites

    mutator = SpriteMutator(chaos_level, seed)

    # Mutate weapon sprites
    for weapon_name, original_data in extractor.get_all_weapon_sprites().items():
        sprite_file = extractor.WEAPON_SPRITES[weapon_name]
        mutated_data = mutator.mutate_sprite(original_data)
        # Path in mod: img/weapons/filename.png -> weapons/filename for weaponArt
        weapon_sprites[f"weapons/{sprite_file}"] = mutated_data

    # Mutate drone sprites
    for drone_name, original_data in extractor.get_all_drone_sprites().items():
        sprite_file = extractor.DRONE_SPRITES[drone_name]
        mutated_data = mutator.mutate_sprite(original_data)
        drone_sprites[f"ship/{sprite_file}"] = mutated_data

    return weapon_sprites, drone_sprites
