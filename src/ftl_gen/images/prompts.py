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

    return f"""Create a pixel art weapon sprite for a spaceship game.

CRITICAL REQUIREMENTS:
- BACKGROUND: Solid bright green (#00FF00) - like a green screen
- ORIENTATION: Weapon should be HORIZONTAL, pointing RIGHT (like a side-view turret)
- SIZE: Weapon must be LARGE and fill 90-95% of the image. No small centered objects - the weapon should nearly touch the edges.
- STYLE: Clean pixel art, 2-4 colors max, no gradients, retro game style
- EDGES: Sharp edges, no anti-aliasing or blur into background

Weapon: {weapon_name}
Type: {weapon_type} - {base_shape}
Description: {visual_desc}

This is a spaceship-mounted weapon shown from the side. The barrel/emitter points to the RIGHT.
Make the weapon BIG - it should dominate the frame, not be a small icon.
Output a single weapon image, not a sprite sheet or animation."""


def drone_sprite_prompt(
    drone_name: str,
    drone_type: str,
    description: str,
) -> str:
    """Generate prompt for drone sprite image."""
    type_details = {
        "COMBAT": "a small attack drone with visible weapons",
        "DEFENSE": "a defensive drone with shield projector",
        "REPAIR": "a repair drone with tools and manipulators",
        "BOARDER": "an infiltration drone with breaching equipment",
        "SHIELD": "a shield drone projecting protective field",
        "BATTLE": "an aggressive combat drone",
    }

    base_shape = type_details.get(drone_type, "a futuristic drone")

    return f"""Create a pixel art drone sprite for a spaceship game.

CRITICAL REQUIREMENTS:
- BACKGROUND: Solid bright green (#00FF00) - like a green screen
- ORIENTATION: Drone shown from TOP-DOWN view (bird's eye), facing RIGHT
- SIZE: Drone must be LARGE and fill 90% of the image width. No small centered objects.
- STYLE: Clean pixel art, 2-4 colors max, no gradients, retro game style
- EDGES: Sharp edges, no anti-aliasing or blur into background

Drone: {drone_name}
Type: {drone_type} - {base_shape}
Description: {description}

This is a small autonomous drone viewed from above. It faces RIGHT (moving right).
Make the drone BIG - it should nearly fill the frame horizontally.
Output a single drone image, not a sprite sheet or animation."""


