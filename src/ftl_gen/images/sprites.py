"""Sprite sheet processing for FTL weapon animations."""

from io import BytesIO
from pathlib import Path

from PIL import Image

from ftl_gen.constants import (
    DRONE_BODY_SIZE,
    DRONE_FRAME_COUNT,
    DRONE_FRAME_HEIGHT,
    DRONE_FRAME_WIDTH,
    WEAPON_FRAME_COUNT,
    WEAPON_FRAME_HEIGHT,
    WEAPON_FRAME_WIDTH,
)


class SpriteProcessor:
    """Process images into FTL-compatible sprite sheets."""

    FRAME_WIDTH = WEAPON_FRAME_WIDTH
    FRAME_HEIGHT = WEAPON_FRAME_HEIGHT
    FRAME_COUNT = WEAPON_FRAME_COUNT
    DRONE_FRAME_WIDTH = DRONE_FRAME_WIDTH
    DRONE_FRAME_HEIGHT = DRONE_FRAME_HEIGHT
    DRONE_FRAME_COUNT = DRONE_FRAME_COUNT

    def create_weapon_sprite_sheet(
        self,
        image_data: bytes,
        frames: int = 12,
    ) -> bytes:
        """Convert a single image to a weapon sprite sheet.

        Takes a source image and creates a horizontal sprite sheet with
        the specified number of frames. Frames are created by applying
        slight variations (glow effects, etc.) to simulate animation.

        Pipeline:
        1. Remove green background (#00FF00) -> transparent
        2. Crop to content bounds
        3. Resize to fill frame width (~90% of 16px)
        4. Center in 16x60 frame
        5. Create animation frames

        Args:
            image_data: Source PNG image data
            frames: Number of animation frames (default 12)

        Returns:
            PNG data for the sprite sheet
        """
        # Load source image
        source = Image.open(BytesIO(image_data)).convert("RGBA")

        # Remove green background
        source = self._remove_green_background(source)

        # Crop to content (remove empty space)
        source = self._crop_to_content(source)

        # Rotate 90° counter-clockwise - Gemini generates horizontal weapons (pointing right)
        # but FTL sprites have weapons pointing UP
        source = source.rotate(90, expand=True)

        # Resize to fill frame
        frame = self._resize_to_frame(source)

        # Create sprite sheet
        sheet_width = self.FRAME_WIDTH * frames
        sheet_height = self.FRAME_HEIGHT
        sheet = Image.new("RGBA", (sheet_width, sheet_height), (0, 0, 0, 0))

        # Generate animation frames
        for i in range(frames):
            animated_frame = self._create_animation_frame(frame, i, frames)
            sheet.paste(animated_frame, (i * self.FRAME_WIDTH, 0))

        # Save to bytes
        buffer = BytesIO()
        sheet.save(buffer, format="PNG")
        return buffer.getvalue()

    def create_drone_sprite_sheet(
        self,
        image_data: bytes,
        frames: int = 4,
    ) -> bytes:
        """Convert a single image to a drone sprite sheet.

        Pipeline:
        1. Remove green background (#00FF00) -> transparent
        2. Crop to content bounds
        3. Resize to fill frame (50x20)
        4. Create 4 animation frames

        Args:
            image_data: Source PNG image data
            frames: Number of animation frames (default 4)

        Returns:
            PNG data for the sprite sheet
        """
        # Load source image
        source = Image.open(BytesIO(image_data)).convert("RGBA")

        # Remove green background
        source = self._remove_green_background(source)

        # Crop to content (remove empty space)
        source = self._crop_to_content(source)

        # Resize to fill drone frame (no rotation - drones are already horizontal)
        frame = self._resize_to_drone_frame(source)

        # Create sprite sheet
        sheet_width = self.DRONE_FRAME_WIDTH * frames
        sheet_height = self.DRONE_FRAME_HEIGHT
        sheet = Image.new("RGBA", (sheet_width, sheet_height), (0, 0, 0, 0))

        # Generate animation frames (simple brightness variation for drones)
        for i in range(frames):
            animated_frame = self._create_drone_animation_frame(frame, i, frames)
            sheet.paste(animated_frame, (i * self.DRONE_FRAME_WIDTH, 0))

        # Save to bytes
        buffer = BytesIO()
        sheet.save(buffer, format="PNG")
        return buffer.getvalue()

    def _resize_to_drone_frame(self, image: Image.Image) -> Image.Image:
        """Resize drone image to fill frame.

        Frame is 50x20 (wide, short) - drone faces right.
        Scale to fill ~90% of frame width while fitting height.
        """
        target_width = int(self.DRONE_FRAME_WIDTH * 0.9)  # ~45 pixels
        target_height = int(self.DRONE_FRAME_HEIGHT * 0.9)  # ~18 pixels

        # Scale to fit within target bounds while maintaining aspect ratio
        width_scale = target_width / image.width
        height_scale = target_height / image.height
        scale = min(width_scale, height_scale)

        new_width = int(image.width * scale)
        new_height = int(image.height * scale)

        # Ensure minimum dimensions
        new_width = max(1, new_width)
        new_height = max(1, new_height)

        # Resize using high-quality resampling
        resized = image.resize((new_width, new_height), Image.Resampling.LANCZOS)

        # Center on transparent frame
        frame = Image.new("RGBA", (self.DRONE_FRAME_WIDTH, self.DRONE_FRAME_HEIGHT), (0, 0, 0, 0))
        x_offset = (self.DRONE_FRAME_WIDTH - new_width) // 2
        y_offset = (self.DRONE_FRAME_HEIGHT - new_height) // 2
        frame.paste(resized, (x_offset, y_offset), resized)

        return frame

    def _create_drone_animation_frame(
        self,
        base_frame: Image.Image,
        frame_index: int,
        total_frames: int,
    ) -> Image.Image:
        """Create a drone animation frame with subtle variations.

        Drone animation is subtle - just engine glow variations.
        """
        frame = base_frame.copy()

        # Simple pulsing brightness
        pulse = 1.0 + 0.1 * ((frame_index % 2) * 2 - 1)  # Alternates 0.9 and 1.1
        frame = self._adjust_brightness(frame, pulse)

        return frame

    def create_drone_body_images(
        self,
        image_data: bytes,
    ) -> dict[str, bytes]:
        """Convert a single image to FTL drone body images (_base, _on, _charged).

        FTL drones use 64x64 static PNGs in img/ship/drones/, not animation sheets.
        If the input looks like a sprite sheet (much wider than tall), extracts the
        first frame before processing.

        Returns:
            Dict with "_base", "_on", and "_charged" keys mapping to PNG bytes.
        """
        source = Image.open(BytesIO(image_data)).convert("RGBA")

        # Detect animation sheets: if width > 2x height, extract first frame
        if source.width > source.height * 2:
            frame_w = source.height  # Assume square-ish frames, or use known dims
            # For known drone sheets (200x20 = 4 frames of 50x20)
            if source.height == self.DRONE_FRAME_HEIGHT:
                frame_w = self.DRONE_FRAME_WIDTH
            source = source.crop((0, 0, frame_w, source.height))

        source = self._remove_green_background(source)
        source = self._crop_to_content(source)

        # Resize to fit 64x64 frame
        size = DRONE_BODY_SIZE
        target = int(size * 0.9)
        width_scale = target / source.width
        height_scale = target / source.height
        scale = min(width_scale, height_scale)
        new_w = max(1, int(source.width * scale))
        new_h = max(1, int(source.height * scale))
        resized = source.resize((new_w, new_h), Image.Resampling.LANCZOS)

        base = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        base.paste(resized, ((size - new_w) // 2, (size - new_h) // 2), resized)

        # _on variant: slightly brighter (engine glow)
        on_img = self._adjust_brightness(base.copy(), 1.3)

        # _charged variant: slightly blue-tinted (weapon charge glow)
        charged_img = self._adjust_brightness(base.copy(), 1.15)

        result = {}
        for suffix, img in [("_base", base), ("_on", on_img), ("_charged", charged_img)]:
            buf = BytesIO()
            img.save(buf, format="PNG")
            result[suffix] = buf.getvalue()
        return result

    def create_placeholder_drone_body(self, drone_name: str) -> dict[str, bytes]:
        """Create placeholder 64x64 drone body images for testing.

        Returns:
            Dict with "_base", "_on", and "_charged" keys mapping to PNG bytes.
        """
        size = DRONE_BODY_SIZE
        result = {}
        for suffix, brightness in [("_base", 90), ("_on", 130), ("_charged", 110)]:
            img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
            pixels = img.load()
            center = size // 2
            for y in range(size):
                for x in range(size):
                    # Simple diamond/circle shape
                    dist = abs(x - center) + abs(y - center)
                    if dist < 24:
                        pixels[x, y] = (brightness, brightness, brightness + 20, 255)
            buf = BytesIO()
            img.save(buf, format="PNG")
            result[suffix] = buf.getvalue()
        return result

    def create_placeholder_drone_sprite_sheet(self, drone_name: str) -> bytes:
        """Create a simple placeholder drone sprite sheet for testing."""
        sheet_width = self.DRONE_FRAME_WIDTH * self.DRONE_FRAME_COUNT
        sheet_height = self.DRONE_FRAME_HEIGHT
        sheet = Image.new("RGBA", (sheet_width, sheet_height), (0, 0, 0, 0))

        # Draw a simple drone shape on each frame
        for i in range(self.DRONE_FRAME_COUNT):
            frame = self._create_placeholder_drone_frame(i)
            sheet.paste(frame, (i * self.DRONE_FRAME_WIDTH, 0))

        buffer = BytesIO()
        sheet.save(buffer, format="PNG")
        return buffer.getvalue()

    def _create_placeholder_drone_frame(self, frame_index: int) -> Image.Image:
        """Create a single placeholder drone frame."""
        frame = Image.new("RGBA", (self.DRONE_FRAME_WIDTH, self.DRONE_FRAME_HEIGHT), (0, 0, 0, 0))
        pixels = frame.load()

        # Brightness varies by frame
        brightness = 80 + (frame_index * 15) % 40

        # Draw simple drone shape (horizontal, facing right)
        center_y = self.DRONE_FRAME_HEIGHT // 2
        for y in range(self.DRONE_FRAME_HEIGHT):
            for x in range(self.DRONE_FRAME_WIDTH):
                # Main body (horizontal oval in center)
                if center_y - 6 < y < center_y + 6:
                    if 8 < x < 42:
                        pixels[x, y] = (brightness, brightness, brightness + 20, 255)
                # Nose (pointing right)
                if center_y - 3 < y < center_y + 3:
                    if x >= 38:
                        pixels[x, y] = (brightness - 20, brightness - 20, brightness, 255)

        return frame

    def _remove_green_background(self, image: Image.Image) -> Image.Image:
        """Remove green background, replacing with transparency.

        Gemini produces various shades of green, not just #00FF00.
        Remove any pixel where green is dominant and high.

        Args:
            image: Source image in RGBA mode

        Returns:
            Image with green pixels made transparent
        """
        image = image.convert("RGBA")
        data = image.getdata()

        new_data = []
        for pixel in data:
            r, g, b, a = pixel
            # Remove if green is high AND green dominates over red and blue
            is_green_high = g > 180
            is_green_dominant = g > r and g > b
            green_margin = min(g - r, g - b)  # How much greener than other channels

            if is_green_high and is_green_dominant and green_margin > 20:
                new_data.append((0, 0, 0, 0))  # Transparent
            else:
                new_data.append(pixel)

        image.putdata(new_data)
        return image

    def _crop_to_content(self, image: Image.Image, padding: int = 2) -> Image.Image:
        """Crop image to non-transparent content bounds.

        Args:
            image: Source image with transparency
            padding: Pixels of padding to add around content

        Returns:
            Cropped image with minimal padding
        """
        bbox = image.getbbox()  # Get bounding box of non-transparent pixels
        if bbox:
            cropped = image.crop(bbox)
            # Add small padding
            padded = Image.new(
                "RGBA",
                (cropped.width + padding * 2, cropped.height + padding * 2),
                (0, 0, 0, 0),
            )
            padded.paste(cropped, (padding, padding))
            return padded
        return image

    def _resize_to_frame(self, image: Image.Image) -> Image.Image:
        """Resize vertical weapon to fill tall frame.

        Frame is 16x60 (narrow, tall) - weapon points DOWN after rotation.
        Scale to fill ~90% of frame height while fitting within width.
        """
        # Target ~90% of frame height (weapon is vertical)
        target_height = int(self.FRAME_HEIGHT * 0.9)  # ~54 pixels
        target_width = int(self.FRAME_WIDTH * 0.9)  # ~14 pixels

        # Scale to fit within target bounds while maintaining aspect ratio
        width_scale = target_width / image.width
        height_scale = target_height / image.height
        scale = min(width_scale, height_scale)

        new_width = int(image.width * scale)
        new_height = int(image.height * scale)

        # Ensure minimum dimensions
        new_width = max(1, new_width)
        new_height = max(1, new_height)

        # Resize using high-quality resampling
        resized = image.resize((new_width, new_height), Image.Resampling.LANCZOS)

        # Center on transparent frame
        frame = Image.new("RGBA", (self.FRAME_WIDTH, self.FRAME_HEIGHT), (0, 0, 0, 0))
        x_offset = (self.FRAME_WIDTH - new_width) // 2
        y_offset = (self.FRAME_HEIGHT - new_height) // 2
        frame.paste(resized, (x_offset, y_offset), resized)

        return frame

    def _create_animation_frame(
        self,
        base_frame: Image.Image,
        frame_index: int,
        total_frames: int,
    ) -> Image.Image:
        """Create an animation frame with subtle variations.

        FTL weapon animations typically show:
        - Frames 0-4: Charging (subtle glow increase)
        - Frame 5: Charged (bright glow)
        - Frames 6-7: Firing (flash effect)
        - Frames 8-11: Cooldown (glow fade)
        """
        frame = base_frame.copy()

        # Calculate animation phase
        charge_end = total_frames // 2 - 1  # Frame 5 for 12 frames
        fire_start = charge_end + 1
        fire_end = fire_start + 1

        if frame_index <= charge_end:
            # Charging phase - gradual brightness increase
            brightness = 1.0 + (frame_index / charge_end) * 0.15
            frame = self._adjust_brightness(frame, brightness)

        elif frame_index <= fire_end:
            # Firing phase - bright flash
            brightness = 1.25
            frame = self._adjust_brightness(frame, brightness)
            frame = self._add_glow(frame, intensity=0.3)

        else:
            # Cooldown phase - fade back to normal
            cooldown_progress = (frame_index - fire_end) / (total_frames - fire_end - 1)
            brightness = 1.15 - cooldown_progress * 0.15
            frame = self._adjust_brightness(frame, brightness)

        return frame

    def _adjust_brightness(self, image: Image.Image, factor: float) -> Image.Image:
        """Adjust image brightness while preserving transparency."""
        if factor == 1.0:
            return image

        # Split into channels
        r, g, b, a = image.split()

        # Adjust RGB channels
        def adjust(channel):
            return channel.point(lambda x: min(255, int(x * factor)))

        r = adjust(r)
        g = adjust(g)
        b = adjust(b)

        return Image.merge("RGBA", (r, g, b, a))

    def _add_glow(self, image: Image.Image, intensity: float = 0.2) -> Image.Image:
        """Add a subtle glow effect to the image."""
        # Create a slightly blurred version for glow
        from PIL import ImageFilter

        glow = image.filter(ImageFilter.GaussianBlur(radius=1))

        # Blend with original
        return Image.blend(image, glow, intensity)

    def save_sprite_sheet(
        self,
        image_data: bytes,
        output_path: Path,
        weapon_name: str,
    ) -> Path:
        """Save sprite sheet to file with FTL naming convention.

        Args:
            image_data: Source image data
            output_path: Directory to save to
            weapon_name: Weapon name for filename

        Returns:
            Path to saved sprite sheet
        """
        # Create sprite sheet
        sheet_data = self.create_weapon_sprite_sheet(image_data)

        # Create output path
        output_path = Path(output_path)
        output_path.mkdir(parents=True, exist_ok=True)

        # FTL naming convention: weaponname_strip12.png
        filename = f"{weapon_name.lower()}_strip12.png"
        filepath = output_path / filename

        # Save
        with open(filepath, "wb") as f:
            f.write(sheet_data)

        return filepath

    def create_placeholder_sprite_sheet(self, weapon_name: str) -> bytes:
        """Create a simple placeholder sprite sheet for testing."""
        sheet_width = self.FRAME_WIDTH * self.FRAME_COUNT
        sheet_height = self.FRAME_HEIGHT
        sheet = Image.new("RGBA", (sheet_width, sheet_height), (0, 0, 0, 0))

        # Draw a simple weapon shape on each frame
        for i in range(self.FRAME_COUNT):
            frame = self._create_placeholder_frame(i)
            sheet.paste(frame, (i * self.FRAME_WIDTH, 0))

        buffer = BytesIO()
        sheet.save(buffer, format="PNG")
        return buffer.getvalue()

    def _create_placeholder_frame(self, frame_index: int) -> Image.Image:
        """Create a single placeholder frame.

        FTL weapon sprites are 16x60 (narrow, tall) with weapon pointing UP.
        """
        frame = Image.new("RGBA", (self.FRAME_WIDTH, self.FRAME_HEIGHT), (0, 0, 0, 0))
        pixels = frame.load()

        # Brightness varies by frame (animation effect)
        brightness = 80 + (frame_index * 10) % 60

        # Draw vertical weapon shape (pointing up)
        # Frame is 16x60 - weapon centered horizontally
        center_x = self.FRAME_WIDTH // 2  # 8

        for y in range(self.FRAME_HEIGHT):
            for x in range(self.FRAME_WIDTH):
                # Main body (vertical bar in center, from y=10 to y=55)
                if 10 < y < 55:
                    if center_x - 3 < x < center_x + 3:  # 5-10 range
                        pixels[x, y] = (brightness, brightness, brightness + 20, 255)

                # Barrel tip (pointing up, at top of frame)
                if y <= 15:
                    if center_x - 2 < x < center_x + 2:  # 6-9 range
                        pixels[x, y] = (brightness + 40, brightness + 20, brightness, 255)

                # Handle/grip (wider at bottom)
                if y > 50:
                    if center_x - 4 < x < center_x + 4:  # 4-11 range
                        pixels[x, y] = (brightness - 20, brightness - 20, brightness - 10, 255)

        return frame
