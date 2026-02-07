"""Chaos stat randomization engine.

Applies deterministic randomization to FTL game data based on a chaos level.
All randomization is seeded for reproducibility.
"""

import logging
from dataclasses import dataclass, field
from random import Random
from typing import Any

logger = logging.getLogger(__name__)

from ftl_gen.xml.schemas import (
    AugmentBlueprint,
    CrewBlueprint,
    DroneBlueprint,
    WeaponBlueprint,
)


@dataclass
class ChaosConfig:
    """Configuration for chaos randomization."""

    # Chaos level: 0.0 = no chaos, 1.0 = full chaos
    level: float = 0.5

    # Random seed for reproducibility (None = random)
    seed: int | None = None

    # Whether to remove safety bounds (allow extreme values)
    unsafe: bool = False

    # Stat bounds (multiplier range) - ignored if unsafe=True
    # At chaos=1.0: values range from (1-max_reduction) to (1+max_increase) of original
    max_reduction: float = 0.5  # 50% reduction at chaos=1.0
    max_increase: float = 0.5  # 50% increase at chaos=1.0

    # Absolute bounds for unsafe mode
    unsafe_max_reduction: float = 0.9  # 90% reduction
    unsafe_max_increase: float = 4.0  # 400% increase

    def __post_init__(self):
        if not 0.0 <= self.level <= 1.0:
            raise ValueError(f"Chaos level must be between 0.0 and 1.0, got {self.level}")


@dataclass
class ChaosResult:
    """Result of chaos randomization."""

    weapons: list[WeaponBlueprint] = field(default_factory=list)
    drones: list[DroneBlueprint] = field(default_factory=list)
    augments: list[AugmentBlueprint] = field(default_factory=list)
    crew: list[CrewBlueprint] = field(default_factory=list)
    seed_used: int = 0


class ChaosRandomizer:
    """Applies chaos randomization to vanilla game data."""

    # Stats that are safe to randomize for ALL weapon types
    SAFE_WEAPON_STATS = [
        "damage",
        "cooldown",
        "power",
        "cost",
        "fireChance",
        "breachChance",
    ]

    # Stats that are type-specific (only randomize if present)
    TYPE_SPECIFIC_WEAPON_STATS = {
        "shots": ["LASER", "BURST", "ION", "MISSILES"],
        "length": ["BEAM"],
        "ion": ["ION", "BOMB"],
        "sp": ["LASER", "MISSILES", "BOMB"],
        "stun": ["ION", "BOMB"],
        "persDamage": ["BEAM"],
        "missiles": ["MISSILES", "BOMB"],
    }

    # Drone stats that can be randomized
    DRONE_STATS = ["power", "cost", "cooldown", "speed"]

    # Augment stats that can be randomized
    AUGMENT_STATS = ["cost", "value"]

    # Crew stats that can be randomized
    CREW_STATS = [
        "maxHealth",
        "moveSpeed",
        "repairSpeed",
        "damageMultiplier",
        "fireRepair",
        "suffocationModifier",
        "cost",
    ]

    def __init__(self, config: ChaosConfig):
        self.config = config
        self.rng = Random(config.seed)
        # Store the seed that was actually used
        self._seed_used = config.seed if config.seed is not None else self.rng.getrandbits(32)
        if config.seed is None:
            self.rng = Random(self._seed_used)

    @property
    def seed_used(self) -> int:
        """Return the seed that was used for this randomizer."""
        return self._seed_used

    def _apply_chaos(
        self,
        value: int | float,
        is_int: bool = True,
        min_val: int | float | None = None,
        max_val: int | float | None = None,
    ) -> int | float:
        """Apply chaos randomization to a value.

        Args:
            value: Original value
            is_int: Whether to round to integer
            min_val: Minimum allowed value (or None for no minimum)
            max_val: Maximum allowed value (or None for no maximum)

        Returns:
            Randomized value
        """
        if self.config.level == 0:
            return value

        if value == 0:
            # Don't randomize zero values (they usually mean "disabled")
            return value

        # Calculate the chaos range
        if self.config.unsafe:
            reduction = self.config.unsafe_max_reduction
            increase = self.config.unsafe_max_increase
        else:
            reduction = self.config.max_reduction
            increase = self.config.max_increase

        # Scale by chaos level
        low = 1.0 - (reduction * self.config.level)
        high = 1.0 + (increase * self.config.level)

        # Apply randomization
        multiplier = self.rng.uniform(low, high)
        new_value = value * multiplier

        # Apply bounds
        if min_val is not None:
            new_value = max(min_val, new_value)
        if max_val is not None:
            new_value = min(max_val, new_value)

        if is_int:
            return int(round(new_value))
        return round(new_value, 2)

    def randomize_weapon(self, weapon_data: dict[str, Any]) -> WeaponBlueprint:
        """Randomize a weapon's stats while preserving type safety.

        CRITICAL: Never change weapon type - only randomize stats within same type.
        """
        weapon = weapon_data.copy()
        weapon_type = weapon.get("type", "LASER")

        # Randomize safe stats (present in all types)
        for stat in self.SAFE_WEAPON_STATS:
            if stat in weapon and weapon[stat] is not None:
                if stat == "power":
                    weapon[stat] = self._apply_chaos(weapon[stat], is_int=True, min_val=1, max_val=5)
                elif stat == "cooldown":
                    weapon[stat] = self._apply_chaos(weapon[stat], is_int=False, min_val=1, max_val=30)
                elif stat in ("fireChance", "breachChance"):
                    weapon[stat] = self._apply_chaos(weapon[stat], is_int=True, min_val=0, max_val=10)
                elif stat == "cost":
                    weapon[stat] = self._apply_chaos(weapon[stat], is_int=True, min_val=10, max_val=200)
                elif stat == "damage":
                    weapon[stat] = self._apply_chaos(weapon[stat], is_int=True, min_val=0, max_val=10)

        # Randomize type-specific stats (only if present AND type matches)
        for stat, valid_types in self.TYPE_SPECIFIC_WEAPON_STATS.items():
            if stat in weapon and weapon[stat] is not None and weapon_type in valid_types:
                if stat == "shots":
                    weapon[stat] = self._apply_chaos(weapon[stat], is_int=True, min_val=1, max_val=10)
                elif stat == "length":
                    weapon[stat] = self._apply_chaos(weapon[stat], is_int=True, min_val=10, max_val=100)
                elif stat == "ion":
                    weapon[stat] = self._apply_chaos(weapon[stat], is_int=True, min_val=1, max_val=10)
                elif stat == "sp":
                    weapon[stat] = self._apply_chaos(weapon[stat], is_int=True, min_val=0, max_val=5)
                elif stat == "stun":
                    weapon[stat] = self._apply_chaos(weapon[stat], is_int=False, min_val=0, max_val=10)
                elif stat == "persDamage":
                    weapon[stat] = self._apply_chaos(weapon[stat], is_int=True, min_val=0, max_val=100)
                elif stat == "missiles":
                    # Missiles cost: always keep at least 1
                    weapon[stat] = self._apply_chaos(weapon[stat], is_int=True, min_val=1, max_val=3)

        # Ensure required fields exist for type
        if weapon_type in ("MISSILES", "BOMB") and "missiles" not in weapon:
            weapon["missiles"] = 1
        if weapon_type == "BEAM" and "length" not in weapon:
            weapon["length"] = 40

        # Generate desc if not present
        if "desc" not in weapon:
            weapon["desc"] = f"A chaotified {weapon.get('title', 'weapon')}."

        # Map fireChance/breachChance to schema names
        if "fireChance" in weapon:
            weapon["fire_chance"] = weapon.pop("fireChance")
        if "breachChance" in weapon:
            weapon["breach_chance"] = weapon.pop("breachChance")
        if "hullBust" in weapon:
            weapon["hull_bust"] = weapon.pop("hullBust")
        if "persDamage" in weapon:
            weapon["crew_damage"] = weapon.pop("persDamage")

        # Validate through schema
        return WeaponBlueprint.model_validate(weapon)

    def randomize_drone(self, drone_data: dict[str, Any]) -> DroneBlueprint:
        """Randomize a drone's stats."""
        drone = drone_data.copy()

        # Skip special drones with zero power/cost (like hacking drone which is internal)
        if drone.get("power", 1) == 0 and drone.get("cost", 10) == 0:
            # Set minimum values for schema validation
            drone["power"] = 1
            drone["cost"] = 10

        for stat in self.DRONE_STATS:
            if stat in drone and drone[stat] is not None:
                if stat == "power":
                    # Ensure power is at least 1 after randomization
                    current_power = drone[stat]
                    if current_power > 0:
                        drone[stat] = self._apply_chaos(drone[stat], is_int=True, min_val=1, max_val=4)
                elif stat == "cost":
                    # Ensure cost is at least 10 after randomization
                    current_cost = drone[stat]
                    if current_cost > 0:
                        drone[stat] = self._apply_chaos(drone[stat], is_int=True, min_val=10, max_val=150)
                elif stat == "cooldown":
                    drone[stat] = self._apply_chaos(drone[stat], is_int=False, min_val=1, max_val=30)
                elif stat == "speed":
                    drone[stat] = self._apply_chaos(drone[stat], is_int=True, min_val=1, max_val=50)

        # Generate desc if not present
        if "desc" not in drone:
            drone["desc"] = f"A chaotified {drone.get('title', 'drone')}."

        return DroneBlueprint.model_validate(drone)

    def randomize_augment(self, augment_data: dict[str, Any]) -> AugmentBlueprint:
        """Randomize an augment's stats."""
        augment = augment_data.copy()

        for stat in self.AUGMENT_STATS:
            if stat in augment and augment[stat] is not None:
                if stat == "cost":
                    augment[stat] = self._apply_chaos(augment[stat], is_int=True, min_val=10, max_val=100)
                elif stat == "value":
                    # Value is a float multiplier, randomize carefully
                    augment[stat] = self._apply_chaos(augment[stat], is_int=False, min_val=0.01, max_val=2.0)

        return AugmentBlueprint.model_validate(augment)

    def randomize_crew(self, crew_data: dict[str, Any]) -> CrewBlueprint:
        """Randomize a crew race's stats."""
        crew = crew_data.copy()

        for stat in self.CREW_STATS:
            if stat in crew and crew[stat] is not None:
                if stat == "maxHealth":
                    crew[stat] = self._apply_chaos(crew[stat], is_int=True, min_val=25, max_val=200)
                elif stat in ("moveSpeed", "repairSpeed", "fireRepair"):
                    crew[stat] = self._apply_chaos(crew[stat], is_int=True, min_val=25, max_val=200)
                elif stat == "damageMultiplier":
                    crew[stat] = self._apply_chaos(crew[stat], is_int=False, min_val=0.5, max_val=2.5)
                elif stat == "suffocationModifier":
                    crew[stat] = self._apply_chaos(crew[stat], is_int=False, min_val=0, max_val=2.0)
                elif stat == "cost":
                    crew[stat] = self._apply_chaos(crew[stat], is_int=True, min_val=20, max_val=100)

        # Map to schema field names
        field_mappings = {
            "maxHealth": "max_health",
            "moveSpeed": "move_speed",
            "repairSpeed": "repair_speed",
            "damageMultiplier": "damage_multiplier",
            "fireRepair": "fire_repair",
            "suffocationModifier": "suffocation_modifier",
            "canFight": "can_fight",
            "canRepair": "can_repair",
            "canSabotage": "can_sabotage",
            "canSuffocate": "can_suffocate",
            "canBurn": "can_burn",
            "providePower": "provide_power",
        }

        for old_key, new_key in field_mappings.items():
            if old_key in crew:
                crew[new_key] = crew.pop(old_key)

        # Generate desc if not present
        if "desc" not in crew:
            crew["desc"] = f"A chaotified {crew.get('title', 'crew member')}."

        return CrewBlueprint.model_validate(crew)


def load_vanilla_data() -> dict[str, Any]:
    """Load vanilla reference data from JSON file."""
    from ftl_gen.data.loader import load_vanilla_reference

    return load_vanilla_reference()


def randomize_all(config: ChaosConfig) -> ChaosResult:
    """Randomize all vanilla game data based on chaos configuration.

    Args:
        config: Chaos configuration

    Returns:
        ChaosResult with randomized weapons, drones, augments, and crew
    """
    vanilla = load_vanilla_data()
    randomizer = ChaosRandomizer(config)
    result = ChaosResult(seed_used=randomizer.seed_used)

    # Randomize weapons (flatten nested structure)
    for weapon_category in vanilla.get("weapons", {}).values():
        for weapon_name, weapon_data in weapon_category.items():
            data = weapon_data.copy()
            data["name"] = weapon_name
            try:
                result.weapons.append(randomizer.randomize_weapon(data))
            except Exception as e:
                # Log but continue on validation errors
                logger.warning("Could not randomize weapon %s: %s", weapon_name, e)

    # Randomize drones (flatten nested structure)
    for drone_category in vanilla.get("drones", {}).values():
        for drone_name, drone_data in drone_category.items():
            data = drone_data.copy()
            data["name"] = drone_name
            try:
                result.drones.append(randomizer.randomize_drone(data))
            except Exception as e:
                logger.warning("Could not randomize drone %s: %s", drone_name, e)

    # Randomize augments (flatten nested structure)
    for augment_category in vanilla.get("augments", {}).values():
        for augment_name, augment_data in augment_category.items():
            data = augment_data.copy()
            data["name"] = augment_name
            try:
                result.augments.append(randomizer.randomize_augment(data))
            except Exception as e:
                logger.warning("Could not randomize augment %s: %s", augment_name, e)

    # Randomize crew
    for crew_name, crew_data in vanilla.get("crew", {}).items():
        data = crew_data.copy()
        data["name"] = crew_name
        try:
            result.crew.append(randomizer.randomize_crew(data))
        except Exception as e:
            logger.warning("Could not randomize crew %s: %s", crew_name, e)

    return result
