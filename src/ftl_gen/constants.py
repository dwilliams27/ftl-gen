"""Shared constants for FTL mod generation.

Single source of truth for sprite dimensions and vanilla assets.
Balance ranges and type sets are derived at runtime from vanilla_reference.json
via the loader module — use get_balance_ranges() for those.
"""

from typing import Any

# --- Sprite Dimensions ---

# Weapon sprites: narrow and tall, weapon points UP
WEAPON_FRAME_WIDTH = 16
WEAPON_FRAME_HEIGHT = 60
WEAPON_FRAME_COUNT = 12

# Drone sprites: wide and short, drone faces RIGHT (legacy animation sheet format)
DRONE_FRAME_WIDTH = 50
DRONE_FRAME_HEIGHT = 20
DRONE_FRAME_COUNT = 4

# Drone body images: 64x64 static PNGs used by FTL's drone renderer
# Stored at img/ship/drones/{droneImage}_base.png and _on.png
DRONE_BODY_SIZE = 64


# --- Derived Balance Ranges ---
# All ranges are computed from vanilla_reference.json at runtime.
# Import and call these functions instead of using hardcoded dicts.


def get_balance_ranges() -> dict[str, dict[str, tuple[Any, Any]]]:
    """Get balance ranges derived from vanilla game data.

    Returns dict like: {"weapon": {"damage": (0, 4), ...}, "drone": {...}, ...}
    """
    from ftl_gen.data.loader import derive_balance_ranges
    return derive_balance_ranges()


def get_generation_ranges() -> dict[str, dict[str, tuple[Any, Any]]]:
    """Get padded ranges for LLM generation (20% wider than vanilla)."""
    from ftl_gen.data.loader import get_generation_ranges as _get
    return _get()


# Backward-compatible lazy BALANCE_RANGES for existing imports.
# Prefer get_balance_ranges() in new code.
BALANCE_RANGES = {
    "weapon": {
        "damage": (0, 10),
        "shots": (1, 10),
        "cooldown": (1, 30),
        "power": (1, 5),
        "cost": (10, 200),
        "rarity": (0, 5),
        "fireChance": (0, 10),
        "breachChance": (0, 10),
        "sp": (0, 5),
        "ion": (1, 10),
        "stun": (0, 15),
        "length": (10, 100),
        "missiles": (0, 3),
        "persDamage": (-10, 60),
        "sysDamage": (0, 5),
    },
    "drone": {
        "power": (1, 4),
        "cost": (10, 150),
        "rarity": (0, 5),
        "cooldown": (1, 1000),
        "speed": (1, 50),
    },
    "augment": {
        "cost": (10, 120),
        "rarity": (0, 5),
    },
    "crew": {
        "maxHealth": (25, 200),
        "moveSpeed": (25, 200),
        "repairSpeed": (25, 200),
        "damageMultiplier": (0.5, 2.5),
        "fireRepair": (0, 200),
        "suffocationModifier": (0, 2.0),
        "cost": (20, 100),
    },
}


# --- Derived Type Sets ---


def get_weapon_types() -> set[str]:
    """Get weapon types found in vanilla data."""
    from ftl_gen.data.loader import load_vanilla_reference
    data = load_vanilla_reference()
    types = set()
    for w in data.get("weapons", {}).values():
        t = w.get("type")
        if t:
            types.add(t)
    return types or WEAPON_TYPES  # fallback


def get_drone_types() -> set[str]:
    """Get drone types found in vanilla data."""
    from ftl_gen.data.loader import load_vanilla_reference
    data = load_vanilla_reference()
    types = set()
    for d in data.get("drones", {}).values():
        t = d.get("type")
        if t:
            types.add(t)
    return types or DRONE_TYPES  # fallback


# --- Vanilla Asset Mappings ---
# Sound effects and default images by weapon type

VANILLA_WEAPON_ASSETS = {
    "LASER": {
        "image": "laser_light1",
        "weaponArt": "laser_burst_1",
        "iconImage": "laser",
        "launch": ["lightLaser1", "lightLaser2", "lightLaser3"],
        "hitShip": ["hitHull2", "hitHull3"],
        "hitShield": ["hitShield1", "hitShield2", "hitShield3"],
        "miss": ["miss"],
    },
    # BURST = Flak weapons in vanilla (need <projectiles> section). We map to LASER
    # in the builder for safety, but keep assets for the rare case it's used.
    "BURST": {
        "image": "laser_light1",
        "weaponArt": "laser_burst_2",
        "iconImage": "laser",
        "launch": ["lightLaser1", "lightLaser2", "lightLaser3"],
        "hitShip": ["hitHull2", "hitHull3"],
        "hitShield": ["hitShield1", "hitShield2", "hitShield3"],
        "miss": ["miss"],
    },
    # ION weapons use <type>LASER</type> in vanilla + <ion> tag.
    # Builder maps ION → LASER for the <type> element.
    "ION": {
        "image": "ion_1_shot",
        "weaponArt": "ion_1",
        "iconImage": "ion",
        "explosion": "explosion_small_ion",
        "speed": 30,
        "launch": ["ionShoot1", "ionShoot2", "ionShoot3"],
        "hitShip": ["ionHit1", "ionHit2", "ionHit3"],
        "hitShield": ["ionShields1", "ionShields2", "ionShields3"],
        "miss": ["miss"],
    },
    "BEAM": {
        "image": "beam_contact",
        "weaponArt": "beam_1",
        "iconImage": "beam",
        "speed": 3,
        "launch": ["beam1", "beam1_2"],
        "hitShip": [],
        "hitShield": [],
    },
    "MISSILES": {
        "image": "missile_2",
        "weaponArt": "missiles_1",
        "iconImage": "missile",
        "launch": ["smallMissile1", "smallMissile2"],
        "hitShip": ["smallExplosion"],
        "hitShield": ["hitShield1", "hitShield2", "hitShield3"],
        "miss": ["miss"],
    },
    "BOMB": {
        "image": "bomb1",
        "weaponArt": "bomb_1",
        "iconImage": "bomb",
        "launch": ["bombTeleport"],
        "hitShip": ["smallExplosion"],
        "hitShield": [],
    },
}

# Default vanilla drone images by type
VANILLA_DRONE_IMAGES = {
    "COMBAT": "drone_combat",
    "DEFENSE": "drone_defense",
    "SHIP_REPAIR": "drone_shiprepair",
    "BOARDER": "drone_combat",      # No dedicated boarder body image in vanilla
    "REPAIR": "drone_combat",       # No dedicated repair body image in vanilla
    "BATTLE": "drone_combat",       # No dedicated battle body image in vanilla
    "HACKING": "drone_hack",
    "SHIELD": "drone_shield",
}

# Valid blueprint types (static fallback; prefer get_weapon_types()/get_drone_types())
WEAPON_TYPES = {"LASER", "MISSILES", "BEAM", "BOMB", "BURST", "ION"}
DRONE_TYPES = {"COMBAT", "DEFENSE", "SHIP_REPAIR", "BOARDER", "REPAIR", "BATTLE", "HACKING", "SHIELD"}
