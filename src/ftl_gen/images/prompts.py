"""Prompts for pixel art sprite generation."""


def weapon_sprite_prompt(
    weapon_name: str,
    weapon_type: str,
    description: str,
    visual_description: str | None = None,
) -> str:
    """Generate prompt for weapon sprite image."""
    type_details = {
        "LASER": "a compact laser cannon with energy coils",
        "BEAM": "an elongated beam emitter with focusing crystals",
        "MISSILES": "a missile launcher with visible warhead",
        "BOMB": "a bomb deployment system with payload bay",
        "ION": "an ion projector with glowing capacitors",
        "BURST": "a multi-barrel burst weapon",
    }

    base_shape = type_details.get(weapon_type, "a futuristic weapon")

    visual_desc = visual_description or description

    return f"""Create a pixel art weapon sprite for a sci-fi spaceship game.

Weapon: {weapon_name}
Type: {weapon_type} - {base_shape}
Description: {visual_desc}

Requirements:
- Pixel art style, clean and readable at small size
- Side view of the weapon, oriented horizontally pointing right
- Simple, bold silhouette with 2-3 accent colors
- Dark background or transparent background
- Resolution: approximately 64x240 pixels (will be resized to 16x60)
- The weapon should look like it mounts on a spaceship hull

Style reference: FTL: Faster Than Light weapon sprites - simple, bold, readable pixel art with limited color palette.

Create a single weapon sprite image, not a sprite sheet or animation."""


def weapon_sprite_prompt_simple(weapon_type: str, theme: str) -> str:
    """Simplified prompt for weapon sprite based on type and theme."""
    return f"""Create a pixel art {weapon_type.lower()} weapon sprite for a sci-fi spaceship game.

Theme: {theme}

Requirements:
- Pixel art style, 64x240 pixels
- Side view, horizontal orientation, pointing right
- Simple bold shapes, 2-3 colors plus shadows
- Dark or transparent background
- Should look like it mounts on a spaceship

Style: FTL: Faster Than Light - clean, readable pixel art."""


def crew_sprite_prompt(race_name: str, description: str) -> str:
    """Generate prompt for crew race sprite."""
    return f"""Create a pixel art character sprite for a sci-fi spaceship game crew member.

Race: {race_name}
Description: {description}

Requirements:
- Pixel art style, approximately 32x32 pixels
- Front-facing view of the character
- Simple, readable design with clear silhouette
- 3-4 colors maximum
- Should be distinct from human crew

Style reference: FTL: Faster Than Light crew sprites - simple, iconic pixel art characters."""
