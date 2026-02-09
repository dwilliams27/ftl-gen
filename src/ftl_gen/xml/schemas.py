"""Pydantic models for FTL mod blueprints.

Pydantic validates shape (correct types, required fields).
BalanceValidator validates values (game balance ranges).
"""

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class BlueprintBase(BaseModel):
    """Base class for FTL blueprints with shared fields."""

    name: str = Field(..., description="Blueprint identifier")
    title: str = Field(..., description="Display name")
    desc: str = Field(..., description="Description text")
    cost: int = Field(..., description="Scrap cost")
    rarity: int = Field(default=2, ge=0, description="Rarity (higher = rarer)")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Ensure name is UPPERCASE_WITH_UNDERSCORES."""
        if not v.isupper() or " " in v:
            return v.upper().replace(" ", "_").replace("-", "_")
        return v

    model_config = {"populate_by_name": True}


class WeaponBlueprint(BlueprintBase):
    """Blueprint for an FTL weapon."""

    type: Literal["LASER", "MISSILES", "BEAM", "BOMB", "BURST", "ION"] = Field(
        ..., description="Weapon type"
    )
    short: str | None = Field(None, description="Short name for UI")
    tooltip: str | None = Field(None, description="Additional tooltip text")

    # Combat stats — no upper bound; BalanceValidator checks ranges
    damage: int = Field(default=1, ge=0, description="Hull/system damage")
    shots: int = Field(default=1, ge=1, description="Number of projectiles")
    sp: int | None = Field(None, ge=0, description="Shield piercing")
    ion: int | None = Field(None, ge=1, description="Ion damage")
    stun: float | None = Field(None, ge=0, description="Stun duration")

    # Effects
    fire_chance: int = Field(
        default=0, ge=0, alias="fireChance", description="Fire chance (10=100%)"
    )
    breach_chance: int = Field(
        default=0, ge=0, alias="breachChance", description="Breach chance (10=100%)"
    )
    hull_bust: bool = Field(
        default=False, alias="hullBust", description="Bonus damage to hull"
    )
    lockdown: bool = Field(default=False, description="Crystal lockdown effect")
    crew_damage: int | None = Field(
        None, alias="persDamage", description="Direct crew damage"
    )
    sys_damage: int | None = Field(
        None, alias="sysDamage", description="Bonus system damage"
    )

    # Beam specific
    length: int | None = Field(None, ge=1, description="Beam length in pixels")

    # Missile/bomb specific
    missiles: int | None = Field(None, ge=0, description="Missiles consumed per shot")
    explosion: str | None = Field(None, description="Explosion animation for bombs/missiles")

    # Timing
    cooldown: float = Field(..., ge=1, description="Recharge time in seconds")

    # Resources
    power: int = Field(..., ge=1, description="Power bars required")
    cost: int = Field(..., ge=0, description="Scrap cost in stores")

    # Visual
    image: str | None = Field(None, description="Sprite image path")
    weapon_art: str | None = Field(None, alias="weaponArt", description="Weapon art name")


class DroneBlueprint(BlueprintBase):
    """Blueprint for an FTL drone."""

    type: Literal[
        "COMBAT", "DEFENSE", "SHIP_REPAIR", "BOARDER", "REPAIR", "BATTLE", "HACKING"
    ] = Field(..., description="Drone type")
    short: str | None = Field(None, description="Short name for UI")

    # Stats — no upper bound; BalanceValidator checks ranges
    power: int = Field(..., ge=0, description="Power required")
    cost: int = Field(..., ge=0, description="Scrap cost")

    # Combat drones
    cooldown: float | None = Field(None, ge=0, description="Attack cooldown")
    speed: int | None = Field(None, ge=0, description="Movement speed")

    # Visual (set by sprite generator)
    drone_image: str | None = Field(None, description="Drone image/animation name")


class AugmentBlueprint(BlueprintBase):
    """Blueprint for an FTL augment."""

    cost: int = Field(..., ge=0, description="Scrap cost")
    stackable: bool = Field(default=False, description="Can have multiple")
    value: float | None = Field(None, description="Effect magnitude")
    effect_source: str | None = Field(
        None,
        description="Vanilla augment whose mechanical effect to use (requires binary patch)",
    )


class CrewBlueprint(BlueprintBase):
    """Blueprint for a custom crew race."""

    # Stats (0-200, 100 is human baseline) — no upper bound; BalanceValidator checks
    max_health: int = Field(default=100, ge=1, alias="maxHealth")
    move_speed: int = Field(default=100, ge=1, alias="moveSpeed")
    repair_speed: int = Field(default=100, ge=0, alias="repairSpeed")
    damage_multiplier: float = Field(default=1.0, ge=0, alias="damageMultiplier")
    fire_repair: int = Field(default=100, ge=0, alias="fireRepair")
    suffocation_modifier: float = Field(default=1.0, ge=0, alias="suffocationModifier")

    # Special abilities
    can_fight: bool = Field(default=True, alias="canFight")
    controllable: bool = Field(default=True)
    selectable: bool = Field(default=True)
    can_repair: bool = Field(default=True, alias="canRepair")
    can_man: bool = Field(default=True, alias="canMan")
    can_sabotage: bool = Field(default=True, alias="canSabotage")
    can_suffocate: bool = Field(default=True, alias="canSuffocate")
    can_burn: bool = Field(default=True, alias="canBurn")
    provide_power: bool = Field(default=False, alias="providePower")
    clone_speed_modifier: float = Field(default=1.0, ge=0, alias="cloneSpeedModifier")

    short: str | None = Field(None, description="Short name")
    cost: int = Field(default=50, ge=0, description="Scrap cost to hire")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Crew names are lowercase."""
        return v.lower().replace(" ", "_").replace("-", "_")


class EventOutcome(BaseModel):
    """Outcome of an event choice."""

    text: str | None = Field(None, description="Result text shown to player")

    # Rewards/penalties
    scrap: int | None = Field(None, description="Scrap reward")
    fuel: int | None = Field(None, description="Fuel reward")
    missiles: int | None = Field(None, description="Missiles reward")
    drones: int | None = Field(None, description="Drone parts reward")
    hull: int | None = Field(None, description="Hull damage/repair")

    # Items
    weapon: str | None = Field(None, description="Weapon blueprint to give")
    drone: str | None = Field(None, description="Drone blueprint to give")
    augment: str | None = Field(None, description="Augment blueprint to give")

    # Crew
    add_crew: str | None = Field(None, alias="addCrew", description="Crew race to add")
    remove_crew: bool | None = Field(None, alias="removeCrew", description="Remove a crew member")

    # Damage
    damage_system: str | None = Field(None, alias="damageSystem", description="System to damage")
    damage_amount: int | None = Field(None, alias="damageAmount", ge=1)

    # Chain to another event
    load_event: str | None = Field(None, alias="loadEvent", description="Event to chain to")

    # Store
    store: bool = Field(default=False, description="Open a store")

    model_config = {"populate_by_name": True}


class EventChoice(BaseModel):
    """A choice available in an event."""

    text: str = Field(..., description="Choice text shown to player")
    req: str | None = Field(None, description="Requirement (crew race, system, etc.)")
    level: int | None = Field(None, ge=1, description="Required system level")
    hidden: bool = Field(default=False, description="Hide if requirements not met")
    event: EventOutcome | None = Field(None, description="Outcome if chosen")

    model_config = {"populate_by_name": True}


class EventBlueprint(BaseModel):
    """Blueprint for an FTL event."""

    name: str = Field(..., description="UPPERCASE_WITH_UNDERSCORES identifier")
    text: str = Field(..., description="Event description text")
    unique: bool = Field(default=False, description="Can only happen once per run")

    # Ship encounter
    ship: str | None = Field(None, description="Enemy ship blueprint")
    hostile: bool = Field(default=False, description="Ship is hostile by default")
    distress_beacon: bool = Field(default=False, alias="distressBeacon")

    # Choices
    choices: list[EventChoice] = Field(default_factory=list, description="Available choices")

    # Auto-reward (no choices)
    auto_reward: EventOutcome | None = Field(None, alias="autoReward")

    # Environment
    environment: Literal["normal", "asteroid", "storm", "nebula", "pulsar"] | None = Field(
        None, description="Combat environment"
    )

    model_config = {"populate_by_name": True}


class ShipRoom(BaseModel):
    """A room in a ship layout."""

    id: int = Field(..., ge=0, description="Room ID")
    x: int = Field(..., ge=0, description="Grid X position")
    y: int = Field(..., ge=0, description="Grid Y position")
    w: int = Field(default=2, ge=1, description="Width in tiles")
    h: int = Field(default=2, ge=1, description="Height in tiles")
    system: str | None = Field(None, description="System installed in room")


class ShipBlueprint(BlueprintBase):
    """Blueprint for an FTL ship."""

    layout: str = Field(..., description="Layout file name")
    img: str = Field(..., description="Ship image name")

    # Display
    class_name: str = Field(..., alias="class", description="Ship class name")
    ship_name: str = Field(..., alias="name_", description="Default ship name")
    unlock: str | None = Field(None, description="Unlock achievement text")

    # Systems (level 0 = not present, 1+ = installed level)
    shields: int = Field(default=0, ge=0)
    engines: int = Field(default=0, ge=0)
    oxygen: int = Field(default=0, ge=0)
    weapons: int = Field(default=0, ge=0)
    drones: int = Field(default=0, ge=0)
    medbay: int = Field(default=0, ge=0)
    clonebay: int = Field(default=0, ge=0)
    teleporter: int = Field(default=0, ge=0)
    cloaking: int = Field(default=0, ge=0)
    artillery: int = Field(default=0, ge=0)
    hacking: int = Field(default=0, ge=0)
    mind: int = Field(default=0, ge=0)
    battery: int = Field(default=0, ge=0)
    pilot: int = Field(default=0, ge=0)
    sensors: int = Field(default=0, ge=0)
    doors: int = Field(default=0, ge=0)

    # Resources
    max_power: int = Field(default=8, ge=1, alias="maxPower")
    max_hull: int = Field(default=30, ge=1, alias="maxHull")
    max_crew: int = Field(default=8, ge=1, alias="maxCrew")

    # Starting equipment
    weapons_list: list[str] = Field(default_factory=list, alias="weaponsList")
    drones_list: list[str] = Field(default_factory=list, alias="dronesList")
    augments: list[str] = Field(default_factory=list)

    # Starting crew
    crew: list[str] = Field(default_factory=list, description="List of crew races")

    # Resources (override base cost since ships don't use scrap cost the same way)
    cost: int = Field(default=0, ge=0, description="Ship cost")
    missiles: int = Field(default=8, ge=0)
    drone_parts: int = Field(default=2, ge=0, alias="droneParts")


class ModMetadata(BaseModel):
    """Metadata for a mod package."""

    name: str = Field(..., description="Mod name")
    author: str = Field(default="FTL-Gen", description="Mod author")
    version: str = Field(default="1.0.0", description="Mod version")
    description: str = Field(..., description="Mod description")
    url: str | None = Field(None, description="Mod URL")
    thread_id: int | None = Field(None, alias="threadId", description="Forum thread ID")

    model_config = {"populate_by_name": True}


class ModContent(BaseModel):
    """Complete content for a mod."""

    metadata: ModMetadata
    weapons: list[WeaponBlueprint] = Field(default_factory=list)
    drones: list[DroneBlueprint] = Field(default_factory=list)
    augments: list[AugmentBlueprint] = Field(default_factory=list)
    crew: list[CrewBlueprint] = Field(default_factory=list)
    events: list[EventBlueprint] = Field(default_factory=list)
    ships: list[ShipBlueprint] = Field(default_factory=list)
