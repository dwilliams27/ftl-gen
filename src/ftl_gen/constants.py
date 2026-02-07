"""Shared constants for FTL mod generation.

Single source of truth for sprite dimensions, balance ranges, and vanilla assets.
"""

# --- Sprite Dimensions ---

# Weapon sprites: narrow and tall, weapon points UP
WEAPON_FRAME_WIDTH = 16
WEAPON_FRAME_HEIGHT = 60
WEAPON_FRAME_COUNT = 12

# Drone sprites: wide and short, drone faces RIGHT
DRONE_FRAME_WIDTH = 50
DRONE_FRAME_HEIGHT = 20
DRONE_FRAME_COUNT = 4

# --- Balance Ranges ---
# Used by schemas (Pydantic validation), prompts (LLM guidance),
# constraints (balance checking), and validators (XML checking).

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
        "stun": (0, 10),
        "length": (10, 100),
        "missiles": (1, 3),
        "persDamage": (1, 5),
        "sysDamage": (1, 3),
    },
    "drone": {
        "power": (1, 4),
        "cost": (10, 150),
        "rarity": (0, 5),
        "cooldown": (1, 30),
        "speed": (1, 50),
    },
    "augment": {
        "cost": (10, 100),
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
    "COMBAT": "drone_player_combat",
    "DEFENSE": "drone_player_defensive",
    "SHIP_REPAIR": "drone_repair_ship",
    "BOARDER": "drone_boarder",
    "REPAIR": "drone_repair",
    "BATTLE": "drone_player_battle",
    "HACKING": "drone_hacking",
}

# Valid blueprint types
WEAPON_TYPES = {"LASER", "MISSILES", "BEAM", "BOMB", "BURST", "ION"}
DRONE_TYPES = {"COMBAT", "DEFENSE", "SHIP_REPAIR", "BOARDER", "REPAIR", "BATTLE", "HACKING"}
