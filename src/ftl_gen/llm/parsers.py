"""Response parsing utilities for LLM output."""

import json
import re
from typing import Any

from pydantic import ValidationError

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

# Patterns that indicate impossible/hallucinated mechanics in descriptions
IMPOSSIBLE_MECHANIC_PATTERNS = [
    # Healing/repair effects on weapons (weapons can't heal)
    (r"\b(heal|repair|restore|regenerate)s?\b.*\b(hull|health|HP|crew|system)", "healing effects"),
    (r"\b\d+%?\s*chance\s+to\s+(heal|repair|restore)", "probability-based healing"),
    # Custom probability effects not in stats
    (r"\b\d+%\s*chance\s+to\s+(?!start\s+a?\s*fire|cause\s+a?\s*breach|stun)", "custom probability effects"),
    # Damage over time (doesn't exist for weapons)
    (r"\b(damage|drain|burn)s?\b.*(over\s+time|per\s+second|gradually)", "damage over time"),
    # Chain/combo effects
    (r"\b(chain|spread|jump)s?\s+to\s+(adjacent|nearby|other)", "chain effects"),
    # Resource generation
    (r"\b(generate|produce|create|spawn)s?\s+\d*\s*(scrap|fuel|missiles|drone)", "resource generation"),
    # Self-replication/spawning
    (r"\b(spawn|summon|create|deploy)s?\s+\d*\s*(drone|unit|copy|clone)", "spawning effects"),
    # Permanent effects
    (r"\bpermanent(ly)?\s+(disable|destroy|remove)", "permanent effects"),
    # Turn-based or jump-based effects
    (r"\bevery\s+\d+\s*(turn|jump|sector)", "periodic effects"),
]


def validate_description(desc: str, item_type: str = "weapon") -> tuple[bool, list[str]]:
    """Check description for impossible/hallucinated mechanics.

    Returns:
        Tuple of (is_valid, list_of_issues)
    """
    issues = []
    desc_lower = desc.lower()

    for pattern, issue_name in IMPOSSIBLE_MECHANIC_PATTERNS:
        if re.search(pattern, desc_lower, re.IGNORECASE):
            issues.append(f"Description contains impossible mechanic: {issue_name}")

    return len(issues) == 0, issues


def sanitize_weapon_description(weapon: dict[str, Any]) -> dict[str, Any]:
    """Sanitize weapon description to match actual stats.

    If the description claims mechanics not supported by the stats,
    generate a more accurate description.
    """
    desc = weapon.get("desc", "")
    is_valid, issues = validate_description(desc, "weapon")

    if not is_valid:
        # Generate a more accurate description based on actual stats
        weapon["desc"] = _generate_accurate_weapon_desc(weapon)
        weapon["_sanitized"] = True
        weapon["_original_desc"] = desc
        weapon["_issues"] = issues

    return weapon


def _generate_accurate_weapon_desc(weapon: dict[str, Any]) -> str:
    """Generate an accurate description based on weapon stats."""
    parts = []
    weapon_type = weapon.get("type", "LASER")

    # Damage
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

    # Special effects
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

    # Remove markdown code blocks
    if "```" in text:
        # Find JSON or plain code blocks
        pattern = r'```(?:json)?\s*([\s\S]*?)```'
        matches = re.findall(pattern, text)
        if matches:
            text = matches[0].strip()

    # Find JSON object
    json_match = re.search(r'\{[\s\S]*\}', text)
    if json_match:
        text = json_match.group(0)
    else:
        # No JSON found - might be a refusal message
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

    # Try common list keys
    for list_key in [key, "items", "weapons", "events", "drones", "crew"]:
        if list_key in data and isinstance(data[list_key], list):
            return data[list_key]

    # If data itself looks like a single item, wrap it
    if "name" in data:
        return [data]

    return []


def parse_weapon_response(text: str) -> WeaponBlueprint:
    """Parse a single weapon from LLM response."""
    data = extract_json(text)
    data = sanitize_weapon_description(data)
    if data.get("_sanitized"):
        print(f"Warning: Sanitized description for {data.get('name', 'weapon')}: {data.get('_issues', [])}")
    return WeaponBlueprint.model_validate(data)


def parse_weapons_response(text: str) -> list[WeaponBlueprint]:
    """Parse multiple weapons from LLM response."""
    items = extract_json_list(text, "weapons")
    weapons = []

    for item in items:
        try:
            # Sanitize description before validation
            item = sanitize_weapon_description(item)
            if item.get("_sanitized"):
                print(f"Warning: Sanitized description for {item.get('name', 'weapon')}: {item.get('_issues', [])}")

            weapon = WeaponBlueprint.model_validate(item)
            weapons.append(weapon)
        except ValidationError as e:
            # Try to fix common issues
            fixed = _fix_weapon_data(item)
            fixed = sanitize_weapon_description(fixed)
            try:
                weapon = WeaponBlueprint.model_validate(fixed)
                weapons.append(weapon)
            except ValidationError:
                print(f"Warning: Could not parse weapon: {e}")
                continue

    return weapons


def parse_event_response(text: str) -> EventBlueprint:
    """Parse a single event from LLM response."""
    data = extract_json(text)
    return EventBlueprint.model_validate(data)


def parse_events_response(text: str) -> list[EventBlueprint]:
    """Parse multiple events from LLM response."""
    items = extract_json_list(text, "events")
    events = []

    for item in items:
        try:
            event = EventBlueprint.model_validate(item)
            events.append(event)
        except ValidationError as e:
            # Try to fix common issues
            fixed = _fix_event_data(item)
            try:
                event = EventBlueprint.model_validate(fixed)
                events.append(event)
            except ValidationError:
                print(f"Warning: Could not parse event: {e}")
                continue

    return events


def parse_mod_concept(text: str) -> dict[str, Any]:
    """Parse mod concept response."""
    return extract_json(text)


def _fix_weapon_data(data: dict[str, Any]) -> dict[str, Any]:
    """Attempt to fix common issues in weapon data."""
    fixed = data.copy()

    # Fix name formatting
    if "name" in fixed:
        fixed["name"] = fixed["name"].upper().replace(" ", "_").replace("-", "_")

    # Ensure required fields have defaults
    if "damage" not in fixed:
        fixed["damage"] = 1
    if "cooldown" not in fixed:
        fixed["cooldown"] = 12
    if "power" not in fixed:
        fixed["power"] = 2
    if "cost" not in fixed:
        fixed["cost"] = 50

    # Ensure shots is at least 1 for projectile weapons
    if fixed.get("type") in ("LASER", "BURST", "ION"):
        if "shots" not in fixed or fixed["shots"] < 1:
            fixed["shots"] = 1

    # Convert string numbers to ints
    for field in ["damage", "shots", "power", "cost", "rarity", "fireChance", "breachChance"]:
        if field in fixed and isinstance(fixed[field], str):
            try:
                fixed[field] = int(fixed[field])
            except ValueError:
                pass

    # Convert cooldown to float
    if "cooldown" in fixed and isinstance(fixed["cooldown"], str):
        try:
            fixed["cooldown"] = float(fixed["cooldown"])
        except ValueError:
            fixed["cooldown"] = 12.0

    return fixed


def _fix_event_data(data: dict[str, Any]) -> dict[str, Any]:
    """Attempt to fix common issues in event data."""
    fixed = data.copy()

    # Fix name formatting
    if "name" in fixed:
        fixed["name"] = fixed["name"].upper().replace(" ", "_").replace("-", "_")

    # Ensure choices is a list
    if "choices" not in fixed:
        fixed["choices"] = []
    elif not isinstance(fixed["choices"], list):
        fixed["choices"] = [fixed["choices"]]

    # Fix choice structure
    for i, choice in enumerate(fixed.get("choices", [])):
        if isinstance(choice, str):
            fixed["choices"][i] = {"text": choice}
        elif isinstance(choice, dict):
            # Ensure text field exists
            if "text" not in choice:
                choice["text"] = f"Choice {i + 1}"
            # Fix nested event/outcome
            if "outcome" in choice and "event" not in choice:
                choice["event"] = choice.pop("outcome")

    return fixed


def parse_drone_response(text: str) -> DroneBlueprint:
    """Parse a single drone from LLM response."""
    data = extract_json(text)
    return DroneBlueprint.model_validate(_fix_drone_data(data))


def parse_drones_response(text: str) -> list[DroneBlueprint]:
    """Parse multiple drones from LLM response."""
    items = extract_json_list(text, "drones")
    drones = []

    for item in items:
        try:
            fixed = _fix_drone_data(item)
            drone = DroneBlueprint.model_validate(fixed)
            drones.append(drone)
        except ValidationError as e:
            print(f"Warning: Could not parse drone: {e}")
            continue

    return drones


def parse_augment_response(text: str) -> AugmentBlueprint:
    """Parse a single augment from LLM response."""
    data = extract_json(text)
    return AugmentBlueprint.model_validate(_fix_augment_data(data))


def parse_augments_response(text: str) -> list[AugmentBlueprint]:
    """Parse multiple augments from LLM response."""
    items = extract_json_list(text, "augments")
    augments = []

    for item in items:
        try:
            fixed = _fix_augment_data(item)
            augment = AugmentBlueprint.model_validate(fixed)
            augments.append(augment)
        except ValidationError as e:
            print(f"Warning: Could not parse augment: {e}")
            continue

    return augments


def parse_crew_response(text: str) -> CrewBlueprint:
    """Parse a single crew race from LLM response."""
    data = extract_json(text)
    return CrewBlueprint.model_validate(_fix_crew_data(data))


def parse_crew_races_response(text: str) -> list[CrewBlueprint]:
    """Parse multiple crew races from LLM response."""
    items = extract_json_list(text, "crew")
    crew_list = []

    for item in items:
        try:
            fixed = _fix_crew_data(item)
            crew = CrewBlueprint.model_validate(fixed)
            crew_list.append(crew)
        except ValidationError as e:
            print(f"Warning: Could not parse crew: {e}")
            continue

    return crew_list


def parse_ship_response(text: str) -> ShipBlueprint:
    """Parse a single ship from LLM response."""
    data = extract_json(text)
    return ShipBlueprint.model_validate(_fix_ship_data(data))


def _fix_drone_data(data: dict[str, Any]) -> dict[str, Any]:
    """Attempt to fix common issues in drone data."""
    fixed = data.copy()

    if "name" in fixed:
        fixed["name"] = fixed["name"].upper().replace(" ", "_").replace("-", "_")

    if "power" not in fixed:
        fixed["power"] = 2
    if "cost" not in fixed:
        fixed["cost"] = 50

    for field in ["power", "cost", "rarity", "cooldown", "speed"]:
        if field in fixed and isinstance(fixed[field], str):
            try:
                fixed[field] = int(fixed[field])
            except ValueError:
                pass

    return fixed


def _fix_augment_data(data: dict[str, Any]) -> dict[str, Any]:
    """Attempt to fix common issues in augment data."""
    fixed = data.copy()

    if "name" in fixed:
        fixed["name"] = fixed["name"].upper().replace(" ", "_").replace("-", "_")

    if "cost" not in fixed:
        fixed["cost"] = 50

    for field in ["cost", "rarity"]:
        if field in fixed and isinstance(fixed[field], str):
            try:
                fixed[field] = int(fixed[field])
            except ValueError:
                pass

    if "value" in fixed and isinstance(fixed["value"], str):
        try:
            fixed["value"] = float(fixed["value"])
        except ValueError:
            pass

    return fixed


def _fix_crew_data(data: dict[str, Any]) -> dict[str, Any]:
    """Attempt to fix common issues in crew data."""
    fixed = data.copy()

    if "name" in fixed:
        fixed["name"] = fixed["name"].lower().replace(" ", "_").replace("-", "_")

    # Convert stats
    stat_fields = ["maxHealth", "moveSpeed", "repairSpeed", "fireRepair", "cost"]
    for field in stat_fields:
        if field in fixed and isinstance(fixed[field], str):
            try:
                fixed[field] = int(fixed[field])
            except ValueError:
                pass

    float_fields = ["damageMultiplier", "suffocationModifier", "cloneSpeedModifier"]
    for field in float_fields:
        if field in fixed and isinstance(fixed[field], str):
            try:
                fixed[field] = float(fixed[field])
            except ValueError:
                pass

    return fixed


def _fix_ship_data(data: dict[str, Any]) -> dict[str, Any]:
    """Attempt to fix common issues in ship data."""
    fixed = data.copy()

    if "name" in fixed:
        fixed["name"] = fixed["name"].upper().replace(" ", "_").replace("-", "_")

    # Handle class/name_ aliases
    if "class" in fixed and "class_name" not in fixed:
        fixed["class_name"] = fixed.pop("class")
    if "name_" in fixed and "ship_name" not in fixed:
        fixed["ship_name"] = fixed.pop("name_")

    # Convert system levels
    system_fields = [
        "shields", "engines", "oxygen", "weapons", "drones", "medbay",
        "clonebay", "teleporter", "cloaking", "hacking", "mind",
        "battery", "pilot", "sensors", "doors", "artillery"
    ]
    for field in system_fields:
        if field in fixed and isinstance(fixed[field], str):
            try:
                fixed[field] = int(fixed[field])
            except ValueError:
                fixed[field] = 0

    # Convert resources
    resource_fields = ["maxPower", "maxHull", "maxCrew", "missiles", "droneParts"]
    for field in resource_fields:
        if field in fixed and isinstance(fixed[field], str):
            try:
                fixed[field] = int(fixed[field])
            except ValueError:
                pass

    # Ensure lists
    for field in ["weaponsList", "dronesList", "augments", "crew"]:
        if field in fixed and not isinstance(fixed[field], list):
            fixed[field] = [fixed[field]] if fixed[field] else []

    return fixed


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
