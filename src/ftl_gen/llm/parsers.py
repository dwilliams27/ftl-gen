"""Response parsing utilities for LLM output."""

import json
import logging
import re
from typing import Any

from pydantic import BaseModel, ValidationError

from ftl_gen.xml.schemas import (
    AugmentBlueprint,
    CrewBlueprint,
    DroneBlueprint,
    EventBlueprint,
    ModContent,
    ModMetadata,
    ShipBlueprint,
    WeaponBlueprint,
)

logger = logging.getLogger(__name__)

# Patterns that indicate impossible/hallucinated mechanics in descriptions
IMPOSSIBLE_MECHANIC_PATTERNS = [
    (r"\b(heal|repair|restore|regenerate)s?\b.*\b(hull|health|HP|crew|system)", "healing effects"),
    (r"\b\d+%?\s*chance\s+to\s+(heal|repair|restore)", "probability-based healing"),
    (r"\b\d+%\s*chance\s+to\s+(?!start\s+a?\s*fire|cause\s+a?\s*breach|stun)", "custom probability effects"),
    (r"\b(damage|drain|burn)s?\b.*(over\s+time|per\s+second|gradually)", "damage over time"),
    (r"\b(chain|spread|jump)s?\s+to\s+(adjacent|nearby|other)", "chain effects"),
    (r"\b(generate|produce|create|spawn)s?\s+\d*\s*(scrap|fuel|missiles|drone)", "resource generation"),
    (r"\b(spawn|summon|create|deploy)s?\s+\d*\s*(drone|unit|copy|clone)", "spawning effects"),
    (r"\bpermanent(ly)?\s+(disable|destroy|remove)", "permanent effects"),
    (r"\bevery\s+\d+\s*(turn|jump|sector)", "periodic effects"),
]


def validate_description(desc: str, item_type: str = "weapon") -> tuple[bool, list[str]]:
    """Check description for impossible/hallucinated mechanics."""
    issues = []
    desc_lower = desc.lower()

    for pattern, issue_name in IMPOSSIBLE_MECHANIC_PATTERNS:
        if re.search(pattern, desc_lower, re.IGNORECASE):
            issues.append(f"Description contains impossible mechanic: {issue_name}")

    return len(issues) == 0, issues


def sanitize_weapon_description(weapon: dict[str, Any]) -> dict[str, Any]:
    """Sanitize weapon description to match actual stats."""
    desc = weapon.get("desc", "")
    is_valid, issues = validate_description(desc, "weapon")

    if not is_valid:
        weapon["desc"] = _generate_accurate_weapon_desc(weapon)
        weapon["_sanitized"] = True
        weapon["_original_desc"] = desc
        weapon["_issues"] = issues

    return weapon


def _generate_accurate_weapon_desc(weapon: dict[str, Any]) -> str:
    """Generate an accurate description based on weapon stats."""
    parts = []
    weapon_type = weapon.get("type", "LASER")

    damage = weapon.get("damage", 1)
    shots = weapon.get("shots", 1)

    if weapon_type == "BEAM":
        length = weapon.get("length", 40)
        parts.append(f"A {length}-pixel beam dealing {damage} damage per room")
    elif weapon_type in ("LASER", "BURST", "ION"):
        if shots > 1:
            parts.append(f"Fires {shots} shots dealing {damage} damage each")
        else:
            parts.append(f"Fires a shot dealing {damage} damage")
    elif weapon_type == "MISSILES":
        parts.append(f"Launches a missile dealing {damage} damage")
    elif weapon_type == "BOMB":
        parts.append(f"Teleports a bomb dealing {damage} damage")

    effects = []
    if weapon.get("fireChance", 0) > 0:
        effects.append("can start fires")
    if weapon.get("breachChance", 0) > 0:
        effects.append("can cause breaches")
    if weapon.get("ion", 0) > 0:
        effects.append(f"deals {weapon['ion']} ion damage")
    if weapon.get("sp", 0) > 0:
        effects.append(f"pierces {weapon['sp']} shield{'s' if weapon['sp'] > 1 else ''}")
    if weapon.get("stun", 0) > 0:
        effects.append(f"stuns crew for {weapon['stun']}s")
    if weapon.get("persDamage", 0) > 0:
        effects.append("deals bonus crew damage")
    if weapon.get("sysDamage", 0) > 0:
        effects.append("deals bonus system damage")
    if weapon.get("hullBust"):
        effects.append("deals bonus hull damage")

    if effects:
        parts.append("; ".join(effects).capitalize())

    return ". ".join(parts) + "."


class LLMResponseError(Exception):
    """Error parsing LLM response."""
    pass


def extract_json(text: str) -> dict[str, Any]:
    """Extract JSON object from LLM response text."""
    if not text or not text.strip():
        raise LLMResponseError(
            "LLM returned empty response. This may be due to content moderation - "
            "try a different theme."
        )

    text = text.strip()

    if "```" in text:
        pattern = r'```(?:json)?\s*([\s\S]*?)```'
        matches = re.findall(pattern, text)
        if matches:
            text = matches[0].strip()

    json_match = re.search(r'\{[\s\S]*\}', text)
    if json_match:
        text = json_match.group(0)
    else:
        if any(word in text.lower() for word in ["sorry", "cannot", "can't", "inappropriate", "apologize"]):
            raise LLMResponseError(
                f"LLM refused to generate content for this theme. Try a different theme.\n"
                f"Response: {text[:200]}..."
            )
        raise LLMResponseError(f"No JSON found in LLM response: {text[:200]}...")

    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise LLMResponseError(f"Invalid JSON in LLM response: {e}\nText: {text[:200]}...")


def extract_json_list(text: str, key: str = "items") -> list[dict[str, Any]]:
    """Extract a list of JSON objects from LLM response."""
    data = extract_json(text)

    for list_key in [key, "items", "weapons", "events", "drones", "crew"]:
        if list_key in data and isinstance(data[list_key], list):
            return data[list_key]

    if "name" in data:
        return [data]

    return []


# --- Generic blueprint data fixing ---


def _fix_blueprint_data(
    data: dict[str, Any],
    *,
    name_case: str = "upper",
    defaults: dict[str, Any] | None = None,
    int_fields: list[str] | None = None,
    float_fields: list[str] | None = None,
) -> dict[str, Any]:
    """Fix common LLM output issues for any blueprint type.

    Args:
        data: Raw dict from LLM
        name_case: "upper" or "lower" for name normalization
        defaults: Default values for missing required fields
        int_fields: Fields to convert from string to int
        float_fields: Fields to convert from string to float
    """
    fixed = data.copy()

    # Name normalization
    if "name" in fixed:
        name = fixed["name"].replace(" ", "_").replace("-", "_")
        fixed["name"] = name.upper() if name_case == "upper" else name.lower()

    # Apply defaults for missing fields
    if defaults:
        for field, default in defaults.items():
            if field not in fixed:
                fixed[field] = default

    # Convert string numbers to int
    if int_fields:
        for field in int_fields:
            if field in fixed and isinstance(fixed[field], str):
                try:
                    fixed[field] = int(fixed[field])
                except ValueError:
                    pass

    # Convert string numbers to float
    if float_fields:
        for field in float_fields:
            if field in fixed and isinstance(fixed[field], str):
                try:
                    fixed[field] = float(fixed[field])
                except ValueError:
                    pass

    return fixed


def _fix_weapon_data(data: dict[str, Any]) -> dict[str, Any]:
    """Fix common issues in weapon data."""
    fixed = _fix_blueprint_data(
        data,
        name_case="upper",
        defaults={"damage": 1, "cooldown": 12, "power": 2, "cost": 50},
        int_fields=["damage", "shots", "power", "cost", "rarity", "fireChance", "breachChance"],
        float_fields=["cooldown"],
    )

    # Ensure shots >= 1 for projectile weapons
    if fixed.get("type") in ("LASER", "BURST", "ION"):
        if "shots" not in fixed or (isinstance(fixed.get("shots"), int) and fixed["shots"] < 1):
            fixed["shots"] = 1

    return fixed


def _fix_event_data(data: dict[str, Any]) -> dict[str, Any]:
    """Fix common issues in event data."""
    fixed = _fix_blueprint_data(data, name_case="upper")

    if "choices" not in fixed:
        fixed["choices"] = []
    elif not isinstance(fixed["choices"], list):
        fixed["choices"] = [fixed["choices"]]

    for i, choice in enumerate(fixed.get("choices", [])):
        if isinstance(choice, str):
            fixed["choices"][i] = {"text": choice}
        elif isinstance(choice, dict):
            if "text" not in choice:
                choice["text"] = f"Choice {i + 1}"
            if "outcome" in choice and "event" not in choice:
                choice["event"] = choice.pop("outcome")

    return fixed


def _fix_drone_data(data: dict[str, Any]) -> dict[str, Any]:
    """Fix common issues in drone data."""
    return _fix_blueprint_data(
        data,
        name_case="upper",
        defaults={"power": 2, "cost": 50},
        int_fields=["power", "cost", "rarity", "cooldown", "speed"],
    )


def _fix_augment_data(data: dict[str, Any]) -> dict[str, Any]:
    """Fix common issues in augment data."""
    return _fix_blueprint_data(
        data,
        name_case="upper",
        defaults={"cost": 50},
        int_fields=["cost", "rarity"],
        float_fields=["value"],
    )


def _fix_crew_data(data: dict[str, Any]) -> dict[str, Any]:
    """Fix common issues in crew data."""
    return _fix_blueprint_data(
        data,
        name_case="lower",
        int_fields=["maxHealth", "moveSpeed", "repairSpeed", "fireRepair", "cost"],
        float_fields=["damageMultiplier", "suffocationModifier", "cloneSpeedModifier"],
    )


def _fix_ship_data(data: dict[str, Any]) -> dict[str, Any]:
    """Fix common issues in ship data."""
    fixed = _fix_blueprint_data(
        data,
        name_case="upper",
        int_fields=[
            "shields", "engines", "oxygen", "weapons", "drones", "medbay",
            "clonebay", "teleporter", "cloaking", "hacking", "mind",
            "battery", "pilot", "sensors", "doors", "artillery",
            "maxPower", "maxHull", "maxCrew", "missiles", "droneParts",
        ],
    )

    # Handle class/name_ aliases
    if "class" in fixed and "class_name" not in fixed:
        fixed["class_name"] = fixed.pop("class")
    if "name_" in fixed and "ship_name" not in fixed:
        fixed["ship_name"] = fixed.pop("name_")

    # Ensure lists
    for field in ["weaponsList", "dronesList", "augments", "crew"]:
        if field in fixed and not isinstance(fixed[field], list):
            fixed[field] = [fixed[field]] if fixed[field] else []

    return fixed


# --- Generic parse functions ---


def _parse_single(
    text: str,
    model: type[BaseModel],
    fixer: callable,
) -> BaseModel:
    """Parse a single blueprint from LLM response."""
    data = extract_json(text)
    data = fixer(data)
    return model.model_validate(data)


def _parse_list(
    text: str,
    model: type[BaseModel],
    fixer: callable,
    key: str = "items",
    *,
    sanitize_desc: bool = False,
) -> list[BaseModel]:
    """Parse a list of blueprints from LLM response."""
    items = extract_json_list(text, key)
    results = []

    for item in items:
        if sanitize_desc:
            item = sanitize_weapon_description(item)
            if item.get("_sanitized"):
                logger.warning("Sanitized description for %s: %s", item.get("name", "?"), item.get("_issues", []))

        try:
            obj = model.model_validate(item)
            results.append(obj)
        except ValidationError:
            fixed = fixer(item)
            if sanitize_desc:
                fixed = sanitize_weapon_description(fixed)
            try:
                obj = model.model_validate(fixed)
                results.append(obj)
            except ValidationError as e:
                logger.warning("Could not parse %s: %s", model.__name__, e)
                continue

    return results


# --- Public parse functions (thin wrappers) ---


def parse_weapon_response(text: str) -> WeaponBlueprint:
    """Parse a single weapon from LLM response."""
    data = extract_json(text)
    data = sanitize_weapon_description(data)
    if data.get("_sanitized"):
        logger.warning("Sanitized description for %s: %s", data.get("name", "weapon"), data.get("_issues", []))
    return WeaponBlueprint.model_validate(data)


def parse_weapons_response(text: str) -> list[WeaponBlueprint]:
    """Parse multiple weapons from LLM response."""
    return _parse_list(text, WeaponBlueprint, _fix_weapon_data, "weapons", sanitize_desc=True)


def parse_event_response(text: str) -> EventBlueprint:
    """Parse a single event from LLM response."""
    return _parse_single(text, EventBlueprint, _fix_event_data)


def parse_events_response(text: str) -> list[EventBlueprint]:
    """Parse multiple events from LLM response."""
    return _parse_list(text, EventBlueprint, _fix_event_data, "events")


def parse_drone_response(text: str) -> DroneBlueprint:
    """Parse a single drone from LLM response."""
    return _parse_single(text, DroneBlueprint, _fix_drone_data)


def parse_drones_response(text: str) -> list[DroneBlueprint]:
    """Parse multiple drones from LLM response."""
    return _parse_list(text, DroneBlueprint, _fix_drone_data, "drones")


def parse_augment_response(text: str) -> AugmentBlueprint:
    """Parse a single augment from LLM response."""
    return _parse_single(text, AugmentBlueprint, _fix_augment_data)


def parse_augments_response(text: str) -> list[AugmentBlueprint]:
    """Parse multiple augments from LLM response."""
    return _parse_list(text, AugmentBlueprint, _fix_augment_data, "augments")


def parse_crew_response(text: str) -> CrewBlueprint:
    """Parse a single crew race from LLM response."""
    return _parse_single(text, CrewBlueprint, _fix_crew_data)


def parse_crew_races_response(text: str) -> list[CrewBlueprint]:
    """Parse multiple crew races from LLM response."""
    return _parse_list(text, CrewBlueprint, _fix_crew_data, "crew")


def parse_ship_response(text: str) -> ShipBlueprint:
    """Parse a single ship from LLM response."""
    return _parse_single(text, ShipBlueprint, _fix_ship_data)


def parse_mod_concept(text: str) -> dict[str, Any]:
    """Parse mod concept response."""
    return extract_json(text)


def build_mod_content(
    mod_name: str,
    description: str,
    weapons: list[WeaponBlueprint] | None = None,
    events: list[EventBlueprint] | None = None,
    drones: list[DroneBlueprint] | None = None,
    augments: list[AugmentBlueprint] | None = None,
    crew: list[CrewBlueprint] | None = None,
    ships: list[ShipBlueprint] | None = None,
) -> ModContent:
    """Build a complete ModContent object."""
    metadata = ModMetadata(
        name=mod_name,
        description=description,
    )

    return ModContent(
        metadata=metadata,
        weapons=weapons or [],
        events=events or [],
        drones=drones or [],
        augments=augments or [],
        crew=crew or [],
        ships=ships or [],
    )
