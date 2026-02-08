"""Extract vanilla FTL game data from Slipstream-extracted files.

Parses blueprints.xml + dlcBlueprints.xml and writes a comprehensive
vanilla_reference.json used as the single source of truth for balance
ranges, type sets, and vanilla comparison data.
"""

import json
import logging
from pathlib import Path
from typing import Any

from lxml import etree

logger = logging.getLogger(__name__)

# Stats to extract per weapon (int unless noted)
_WEAPON_INT_STATS = [
    "damage", "shots", "sp", "fireChance", "breachChance", "stunChance",
    "ion", "missiles", "power", "cost", "rarity", "stun",
    "persDamage", "sysDamage",
]
_WEAPON_FLOAT_STATS = ["cooldown"]
_WEAPON_BOOL_STATS = ["hullBust", "lockdown"]

# Stats to extract per drone
_DRONE_INT_STATS = ["power", "cost", "rarity", "speed", "dodge"]
_DRONE_FLOAT_STATS = ["cooldown"]

# Stats to extract per augment
_AUGMENT_INT_STATS = ["cost", "rarity"]


def _int_or_none(elem: etree._Element | None) -> int | None:
    """Parse element text as int, or None if missing/empty."""
    if elem is None or elem.text is None:
        return None
    try:
        return int(elem.text.strip())
    except ValueError:
        return None


def _float_or_none(elem: etree._Element | None) -> float | None:
    """Parse element text as float, handling '1.f' notation."""
    if elem is None or elem.text is None:
        return None
    text = elem.text.strip()
    # Handle FTL's "1.f" float notation
    if text.endswith("f"):
        text = text[:-1]
    try:
        return float(text)
    except ValueError:
        return None


def _bool_elem(elem: etree._Element | None) -> bool:
    """Parse element as bool (present and text is 'true' or '1')."""
    if elem is None:
        return False
    if elem.text is None:
        return True  # <hullBust/> means true
    return elem.text.strip().lower() in ("true", "1")


def _extract_weapon(wp: etree._Element) -> dict[str, Any]:
    """Extract stats from a <weaponBlueprint> element."""
    data: dict[str, Any] = {}

    # Type
    type_elem = wp.find("type")
    if type_elem is not None and type_elem.text:
        raw_type = type_elem.text.strip()
        # Classify ION weapons: vanilla uses LASER type + <ion> tag
        ion_elem = wp.find("ion")
        if raw_type == "LASER" and ion_elem is not None and _int_or_none(ion_elem):
            data["type"] = "ION"
        else:
            data["type"] = raw_type

    # NOLOC flag
    if wp.get("NOLOC") == "1":
        data["noloc"] = True

    # Int stats
    for stat in _WEAPON_INT_STATS:
        val = _int_or_none(wp.find(stat))
        if val is not None:
            data[stat] = val

    # Float stats
    for stat in _WEAPON_FLOAT_STATS:
        val = _float_or_none(wp.find(stat))
        if val is not None:
            data[stat] = val

    # Bool stats
    for stat in _WEAPON_BOOL_STATS:
        if _bool_elem(wp.find(stat)):
            data[stat] = True

    # Beam length
    length = _int_or_none(wp.find("length"))
    if length is not None:
        data["length"] = length

    # Speed
    speed = _int_or_none(wp.find("speed"))
    if speed is not None:
        data["speed"] = speed

    return data


def _extract_drone(dp: etree._Element) -> dict[str, Any]:
    """Extract stats from a <droneBlueprint> element."""
    data: dict[str, Any] = {}

    type_elem = dp.find("type")
    if type_elem is not None and type_elem.text:
        data["type"] = type_elem.text.strip()

    if dp.get("NOLOC") == "1":
        data["noloc"] = True

    for stat in _DRONE_INT_STATS:
        val = _int_or_none(dp.find(stat))
        if val is not None:
            data[stat] = val

    for stat in _DRONE_FLOAT_STATS:
        val = _float_or_none(dp.find(stat))
        if val is not None:
            data[stat] = val

    return data


def _extract_augment(ap: etree._Element) -> dict[str, Any]:
    """Extract stats from an <augBlueprint> element."""
    data: dict[str, Any] = {}

    if ap.get("NOLOC") == "1":
        data["noloc"] = True

    for stat in _AUGMENT_INT_STATS:
        val = _int_or_none(ap.find(stat))
        if val is not None:
            data[stat] = val

    stackable = ap.find("stackable")
    if stackable is not None and stackable.text:
        data["stackable"] = stackable.text.strip().lower() == "true"

    value = _float_or_none(ap.find("value"))
    if value is not None:
        data["value"] = value

    return data


def _extract_crew(cp: etree._Element) -> dict[str, Any]:
    """Extract stats from a <crewBlueprint> element."""
    data: dict[str, Any] = {}

    if cp.get("NOLOC") == "1":
        data["noloc"] = True

    cost = _int_or_none(cp.find("cost"))
    if cost is not None:
        data["cost"] = cost

    rarity = _int_or_none(cp.find("rarity"))
    if rarity is not None:
        data["rarity"] = rarity

    return data


def _extract_ship(sp: etree._Element) -> dict[str, Any]:
    """Extract key info from a <shipBlueprint> element."""
    data: dict[str, Any] = {}

    data["layout"] = sp.get("layout", "")
    data["img"] = sp.get("img", "")

    # Weapon/drone slots
    ws = sp.find("weaponSlots")
    if ws is not None and ws.text:
        data["weaponSlots"] = int(ws.text.strip())
    ds = sp.find("droneSlots")
    if ds is not None and ds.text:
        data["droneSlots"] = int(ds.text.strip())

    # Health / power
    health = sp.find("health")
    if health is not None:
        data["health"] = int(health.get("amount", "30"))
    max_power = sp.find("maxPower")
    if max_power is not None:
        data["maxPower"] = int(max_power.get("amount", "8"))

    # Weapons
    wl = sp.find("weaponList")
    if wl is not None:
        data["missiles"] = int(wl.get("missiles", "0"))
        data["weaponCount"] = int(wl.get("count", "0"))
        data["weapons"] = [w.get("name") for w in wl.findall("weapon")]

    # Drones
    dl = sp.find("droneList")
    if dl is not None:
        data["drones_parts"] = int(dl.get("drones", "0"))
        data["droneCount"] = int(dl.get("count", "0"))
        data["drones"] = [d.get("name") for d in dl.findall("drone")]

    # Augment(s) — vanilla uses <aug name="..."/>
    augs = [a.get("name") for a in sp.findall("aug")]
    if augs:
        data["augments"] = augs

    # Crew
    crew_counts = []
    for cc in sp.findall("crewCount"):
        crew_counts.append({
            "class": cc.get("class", "human"),
            "amount": int(cc.get("amount", "1")),
        })
    if crew_counts:
        data["crew"] = crew_counts

    return data


def _parse_blueprint_lists(root: etree._Element) -> dict[str, list[str]]:
    """Extract all <blueprintList> elements."""
    lists: dict[str, list[str]] = {}
    for bl in root.findall(".//blueprintList"):
        list_name = bl.get("name")
        if not list_name:
            continue
        names = [n.text.strip() for n in bl.findall("name") if n.text]
        if names:
            lists[list_name] = names
    return lists


def extract_vanilla_data(source_dir: Path) -> dict[str, Any]:
    """Parse extracted FTL game data into a comprehensive dict.

    Args:
        source_dir: Path to Slipstream-extracted directory (contains data/ subdir)

    Returns:
        Dict with weapons, drones, augments, crew, ships, blueprint_lists
    """
    data_dir = source_dir / "data"
    if not data_dir.exists():
        # Maybe source_dir IS the data dir
        if (source_dir / "blueprints.xml").exists():
            data_dir = source_dir
        else:
            raise FileNotFoundError(
                f"No data directory found in {source_dir}. "
                f"Expected {data_dir} or {source_dir}/blueprints.xml"
            )

    # Parse all blueprint files
    files_to_parse = ["blueprints.xml", "dlcBlueprints.xml"]
    roots: list[etree._Element] = []

    for filename in files_to_parse:
        filepath = data_dir / filename
        if filepath.exists():
            logger.info("Parsing %s", filepath)
            tree = etree.parse(str(filepath))
            roots.append(tree.getroot())
        else:
            logger.warning("File not found: %s", filepath)

    if not roots:
        raise FileNotFoundError(f"No blueprint files found in {data_dir}")

    weapons: dict[str, Any] = {}
    drones: dict[str, Any] = {}
    augments: dict[str, Any] = {}
    crew: dict[str, Any] = {}
    ships: dict[str, Any] = {}
    blueprint_lists: dict[str, list[str]] = {}

    for root in roots:
        # Weapons
        for wp in root.findall(".//weaponBlueprint"):
            name = wp.get("name")
            if not name:
                continue
            weapons[name] = _extract_weapon(wp)

        # Drones
        for dp in root.findall(".//droneBlueprint"):
            name = dp.get("name")
            if not name:
                continue
            drones[name] = _extract_drone(dp)

        # Augments
        for ap in root.findall(".//augBlueprint"):
            name = ap.get("name")
            if not name:
                continue
            augments[name] = _extract_augment(ap)

        # Crew
        for cp in root.findall(".//crewBlueprint"):
            name = cp.get("name")
            if not name:
                continue
            crew[name] = _extract_crew(cp)

        # Ships (player ships only)
        for sp in root.findall(".//shipBlueprint"):
            name = sp.get("name")
            if not name or not name.startswith("PLAYER_SHIP"):
                continue
            ships[name] = _extract_ship(sp)

        # Blueprint lists
        blueprint_lists.update(_parse_blueprint_lists(root))

    # Merge in manually-researched crew engine stats that aren't in XML
    _CREW_ENGINE_STATS = {
        "human": {
            "title": "Human",
            "maxHealth": 100, "moveSpeed": 100, "repairSpeed": 100,
            "damageMultiplier": 1.0, "fireRepair": 100, "suffocationModifier": 1.0,
            "canFight": True, "canRepair": True, "canSabotage": True,
            "canSuffocate": True, "canBurn": True, "providePower": False,
        },
        "engi": {
            "title": "Engi",
            "maxHealth": 100, "moveSpeed": 100, "repairSpeed": 200,
            "damageMultiplier": 0.5, "fireRepair": 120, "suffocationModifier": 1.0,
            "canFight": True, "canRepair": True, "canSabotage": True,
            "canSuffocate": True, "canBurn": True, "providePower": False,
        },
        "mantis": {
            "title": "Mantis",
            "maxHealth": 100, "moveSpeed": 120, "repairSpeed": 50,
            "damageMultiplier": 1.5, "fireRepair": 50, "suffocationModifier": 1.0,
            "canFight": True, "canRepair": True, "canSabotage": True,
            "canSuffocate": True, "canBurn": True, "providePower": False,
        },
        "rockmen": {
            "title": "Rock",
            "maxHealth": 150, "moveSpeed": 50, "repairSpeed": 100,
            "damageMultiplier": 1.0, "fireRepair": 200, "suffocationModifier": 1.0,
            "canFight": True, "canRepair": True, "canSabotage": True,
            "canSuffocate": True, "canBurn": False, "providePower": False,
        },
        "crystal": {
            "title": "Crystal",
            "maxHealth": 125, "moveSpeed": 80, "repairSpeed": 100,
            "damageMultiplier": 1.0, "fireRepair": 100, "suffocationModifier": 0.5,
            "canFight": True, "canRepair": True, "canSabotage": True,
            "canSuffocate": True, "canBurn": True, "providePower": False,
            "lockdown": True,
        },
        "zoltan": {
            "title": "Zoltan",
            "maxHealth": 70, "moveSpeed": 100, "repairSpeed": 100,
            "damageMultiplier": 1.0, "fireRepair": 100, "suffocationModifier": 1.0,
            "canFight": True, "canRepair": True, "canSabotage": True,
            "canSuffocate": True, "canBurn": True, "providePower": True,
        },
        "slug": {
            "title": "Slug",
            "maxHealth": 100, "moveSpeed": 100, "repairSpeed": 100,
            "damageMultiplier": 1.0, "fireRepair": 100, "suffocationModifier": 1.0,
            "canFight": True, "canRepair": True, "canSabotage": True,
            "canSuffocate": True, "canBurn": True, "providePower": False,
            "telepathic": True,
        },
        "ghost": {
            "title": "Ghost",
            "maxHealth": 50, "moveSpeed": 150, "repairSpeed": 150,
            "damageMultiplier": 0.5, "fireRepair": 100, "suffocationModifier": 0.0,
            "canFight": True, "canRepair": True, "canSabotage": True,
            "canSuffocate": False, "canBurn": False, "providePower": False,
        },
        "anaerobic": {
            "title": "Lanius",
            "maxHealth": 100, "moveSpeed": 85, "repairSpeed": 100,
            "damageMultiplier": 1.0, "fireRepair": 100, "suffocationModifier": 0.0,
            "canFight": True, "canRepair": True, "canSabotage": True,
            "canSuffocate": False, "canBurn": True, "providePower": False,
            "drainOxygen": True,
        },
    }

    for crew_name, engine_stats in _CREW_ENGINE_STATS.items():
        if crew_name in crew:
            # Merge: XML-extracted cost/rarity + engine stats
            crew[crew_name] = {**engine_stats, **crew[crew_name]}
        else:
            crew[crew_name] = engine_stats

    # Build crew_races list (non-NOLOC only)
    crew_races = [name for name, data in crew.items() if not data.get("noloc")]

    # Build systems list
    systems = [
        "shields", "engines", "weapons", "medbay", "clonebay", "oxygen",
        "teleporter", "cloaking", "artillery", "drone_ctrl", "hacking",
        "mind", "battery", "pilot", "sensors", "doors",
    ]

    return {
        "weapons": weapons,
        "drones": drones,
        "augments": augments,
        "crew": crew,
        "ships": ships,
        "blueprint_lists": blueprint_lists,
        "crew_races": crew_races,
        "systems": systems,
    }


def write_vanilla_reference(data: dict[str, Any], output_path: Path | None = None) -> Path:
    """Write extracted data to vanilla_reference.json.

    Args:
        data: Extracted vanilla data dict
        output_path: Where to write (defaults to data/vanilla_reference.json)

    Returns:
        Path to written file
    """
    if output_path is None:
        output_path = Path(__file__).parent / "vanilla_reference.json"

    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

    logger.info("Wrote vanilla reference to %s", output_path)
    return output_path
