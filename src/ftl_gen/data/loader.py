"""Single cached loader for vanilla reference data and derived ranges."""

import json
import math
from pathlib import Path
from typing import Any

_VANILLA_DATA: dict[str, Any] | None = None
_BALANCE_RANGES: dict[str, dict[str, tuple[int | float, int | float]]] | None = None
_GENERATION_RANGES: dict[str, dict[str, tuple[int | float, int | float]]] | None = None
_DATA_PATH = Path(__file__).parent / "vanilla_reference.json"


def load_vanilla_reference() -> dict[str, Any]:
    """Load vanilla reference data from JSON file (cached after first call)."""
    global _VANILLA_DATA
    if _VANILLA_DATA is None:
        if _DATA_PATH.exists():
            with open(_DATA_PATH) as f:
                _VANILLA_DATA = json.load(f)
        else:
            _VANILLA_DATA = {}
    return _VANILLA_DATA


def _stat_range(
    items: dict[str, Any],
    stat: str,
    *,
    skip_noloc: bool = True,
    default_min: int | float = 0,
    default_max: int | float = 10,
) -> tuple[int | float, int | float]:
    """Compute (min, max) of a stat across all items, ignoring NOLOC by default."""
    values = []
    for item in items.values():
        if skip_noloc and item.get("noloc"):
            continue
        val = item.get(stat)
        if val is not None:
            values.append(val)
    if not values:
        return (default_min, default_max)
    return (min(values), max(values))


def derive_balance_ranges() -> dict[str, dict[str, tuple[int | float, int | float]]]:
    """Derive balance ranges from vanilla_reference.json.

    Scans all vanilla items and computes min/max for every stat.
    Cached after first call.

    Returns:
        Dict like {"weapon": {"damage": (0, 4), "cooldown": (4, 26), ...}, ...}
    """
    global _BALANCE_RANGES
    if _BALANCE_RANGES is not None:
        return _BALANCE_RANGES

    data = load_vanilla_reference()
    weapons = data.get("weapons", {})
    drones = data.get("drones", {})
    augments = data.get("augments", {})
    crew = data.get("crew", {})

    weapon_ranges: dict[str, tuple[int | float, int | float]] = {}
    for stat, default_min, default_max in [
        ("damage", 0, 10),
        ("shots", 1, 10),
        ("cooldown", 1, 30),
        ("power", 1, 5),
        ("cost", 10, 200),
        ("rarity", 0, 5),
        ("fireChance", 0, 10),
        ("breachChance", 0, 10),
        ("sp", 0, 5),
        ("ion", 1, 10),
        ("stun", 0, 15),
        ("stunChance", 0, 10),
        ("length", 10, 100),
        ("missiles", 0, 3),
        ("persDamage", -10, 60),
        ("sysDamage", 0, 5),
    ]:
        weapon_ranges[stat] = _stat_range(
            weapons, stat, default_min=default_min, default_max=default_max
        )

    drone_ranges: dict[str, tuple[int | float, int | float]] = {}
    for stat, default_min, default_max in [
        ("power", 1, 4),
        ("cost", 10, 150),
        ("rarity", 0, 5),
        ("cooldown", 1, 1000),
        ("speed", 1, 50),
    ]:
        drone_ranges[stat] = _stat_range(
            drones, stat, default_min=default_min, default_max=default_max
        )

    augment_ranges: dict[str, tuple[int | float, int | float]] = {}
    for stat, default_min, default_max in [
        ("cost", 10, 120),
        ("rarity", 0, 5),
    ]:
        augment_ranges[stat] = _stat_range(
            augments, stat, default_min=default_min, default_max=default_max
        )

    crew_ranges: dict[str, tuple[int | float, int | float]] = {}
    for stat, default_min, default_max in [
        ("maxHealth", 25, 200),
        ("moveSpeed", 25, 200),
        ("repairSpeed", 25, 200),
        ("damageMultiplier", 0.5, 2.5),
        ("fireRepair", 0, 200),
        ("suffocationModifier", 0, 2.0),
        ("cost", 20, 100),
    ]:
        crew_ranges[stat] = _stat_range(
            crew, stat, skip_noloc=True, default_min=default_min, default_max=default_max
        )

    _BALANCE_RANGES = {
        "weapon": weapon_ranges,
        "drone": drone_ranges,
        "augment": augment_ranges,
        "crew": crew_ranges,
    }
    return _BALANCE_RANGES


def get_generation_ranges() -> dict[str, dict[str, tuple[int | float, int | float]]]:
    """Get padded ranges for LLM generation prompts.

    Pads vanilla ranges by ~20% to allow LLM creativity while keeping
    items close to vanilla balance. Cached after first call.
    """
    global _GENERATION_RANGES
    if _GENERATION_RANGES is not None:
        return _GENERATION_RANGES

    base = derive_balance_ranges()
    padded: dict[str, dict[str, tuple[int | float, int | float]]] = {}

    for category, ranges in base.items():
        padded[category] = {}
        for stat, (lo, hi) in ranges.items():
            span = hi - lo
            pad = span * 0.2
            # Don't go below 0 for most stats
            new_lo = max(0, lo - pad)
            new_hi = hi + pad
            # Keep as int if originals were int
            if isinstance(lo, int) and isinstance(hi, int):
                new_lo = max(0, math.floor(new_lo))
                new_hi = math.ceil(new_hi)
            else:
                new_lo = round(max(0, new_lo), 2)
                new_hi = round(new_hi, 2)
            padded[category][stat] = (new_lo, new_hi)

    _GENERATION_RANGES = padded
    return _GENERATION_RANGES
