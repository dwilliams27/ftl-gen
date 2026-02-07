"""Services for reading and parsing generated mods from disk."""

import zipfile
from datetime import datetime, timezone
from pathlib import Path

from lxml import etree

from ftl_gen.api.models import ModDetail, ModSummary
from ftl_gen.xml.schemas import (
    AugmentBlueprint,
    CrewBlueprint,
    DroneBlueprint,
    EventBlueprint,
    EventChoice,
    EventOutcome,
    WeaponBlueprint,
)


class ModReader:
    """Reads generated mods from disk back into structured data."""

    def __init__(self, mods_dir: Path):
        self.mods_dir = mods_dir

    def list_mods(self) -> list[ModSummary]:
        """List all mods in the output directory."""
        if not self.mods_dir.exists():
            return []

        mods = []
        seen_names = set()

        # Find mod directories (unpacked mods)
        for item in sorted(self.mods_dir.iterdir()):
            if item.is_dir() and not item.name.startswith("."):
                if (item / "data").exists():
                    summary = self._summarize_dir(item)
                    if summary:
                        mods.append(summary)
                        seen_names.add(item.name)

        # Find .ftl files without corresponding directories
        for item in sorted(self.mods_dir.glob("*.ftl")):
            if item.stem not in seen_names:
                summary = self._summarize_ftl(item)
                if summary:
                    mods.append(summary)

        # Sort by creation time, newest first
        mods.sort(key=lambda m: m.created_at, reverse=True)
        return mods

    def get_mod(self, name: str) -> ModDetail | None:
        """Get full details for a mod by name."""
        mod_dir = self.mods_dir / name
        ftl_path = self.mods_dir / f"{name}.ftl"

        if mod_dir.is_dir() and (mod_dir / "data").exists():
            return self._read_dir(mod_dir)
        elif ftl_path.exists():
            return self._read_ftl(ftl_path)
        return None

    def get_sprite_data(self, mod_name: str, sprite_path: str) -> bytes | None:
        """Get sprite PNG data from a mod."""
        # Try unpacked directory first
        mod_dir = self.mods_dir / mod_name
        full_path = mod_dir / "img" / sprite_path
        if full_path.exists():
            return full_path.read_bytes()

        # Try .ftl ZIP
        ftl_path = self.mods_dir / f"{mod_name}.ftl"
        if ftl_path.exists():
            try:
                with zipfile.ZipFile(ftl_path, "r") as zf:
                    return zf.read(f"img/{sprite_path}")
            except (KeyError, zipfile.BadZipFile):
                pass

        return None

    def _summarize_dir(self, mod_dir: Path) -> ModSummary | None:
        """Create a summary from an unpacked mod directory."""
        try:
            stat = mod_dir.stat()
            size = sum(f.stat().st_size for f in mod_dir.rglob("*") if f.is_file())
            ftl_exists = (self.mods_dir / f"{mod_dir.name}.ftl").exists()

            counts = self._count_items_dir(mod_dir)
            sprites = self._count_sprites_dir(mod_dir)

            return ModSummary(
                name=mod_dir.name,
                path=str(mod_dir),
                size_bytes=size,
                created_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
                has_ftl=ftl_exists,
                sprite_count=sprites,
                **counts,
            )
        except Exception:
            return None

    def _summarize_ftl(self, ftl_path: Path) -> ModSummary | None:
        """Create a summary from a .ftl ZIP file."""
        try:
            stat = ftl_path.stat()
            counts = self._count_items_ftl(ftl_path)
            sprites = self._count_sprites_ftl(ftl_path)

            return ModSummary(
                name=ftl_path.stem,
                path=str(ftl_path),
                size_bytes=stat.st_size,
                created_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
                has_ftl=True,
                sprite_count=sprites,
                **counts,
            )
        except Exception:
            return None

    def _count_items_dir(self, mod_dir: Path) -> dict:
        """Count blueprint items from an unpacked mod directory."""
        counts = {"weapon_count": 0, "drone_count": 0, "augment_count": 0,
                  "crew_count": 0, "event_count": 0}

        bp_file = mod_dir / "data" / "blueprints.xml.append"
        if bp_file.exists():
            try:
                tree = etree.parse(str(bp_file))
                root = tree.getroot()
                counts["weapon_count"] = len(root.findall(".//weaponBlueprint"))
                counts["drone_count"] = len(root.findall(".//droneBlueprint"))
                counts["augment_count"] = len(root.findall(".//augBlueprint"))
                counts["crew_count"] = len(root.findall(".//crewBlueprint"))
            except etree.XMLSyntaxError:
                pass

        ev_file = mod_dir / "data" / "events.xml.append"
        if ev_file.exists():
            try:
                tree = etree.parse(str(ev_file))
                root = tree.getroot()
                # Count top-level events (not nested outcomes)
                counts["event_count"] = len(root.findall("./event[@name]"))
            except etree.XMLSyntaxError:
                pass

        return counts

    def _count_items_ftl(self, ftl_path: Path) -> dict:
        """Count items from a .ftl ZIP."""
        counts = {"weapon_count": 0, "drone_count": 0, "augment_count": 0,
                  "crew_count": 0, "event_count": 0}
        try:
            with zipfile.ZipFile(ftl_path, "r") as zf:
                if "data/blueprints.xml.append" in zf.namelist():
                    xml_data = zf.read("data/blueprints.xml.append")
                    root = etree.fromstring(xml_data)
                    counts["weapon_count"] = len(root.findall(".//weaponBlueprint"))
                    counts["drone_count"] = len(root.findall(".//droneBlueprint"))
                    counts["augment_count"] = len(root.findall(".//augBlueprint"))
                    counts["crew_count"] = len(root.findall(".//crewBlueprint"))

                if "data/events.xml.append" in zf.namelist():
                    xml_data = zf.read("data/events.xml.append")
                    root = etree.fromstring(xml_data)
                    counts["event_count"] = len(root.findall("./event[@name]"))
        except (zipfile.BadZipFile, etree.XMLSyntaxError):
            pass
        return counts

    def _count_sprites_dir(self, mod_dir: Path) -> int:
        """Count sprite files in an unpacked mod."""
        img_dir = mod_dir / "img"
        if not img_dir.exists():
            return 0
        return len(list(img_dir.rglob("*.png")))

    def _count_sprites_ftl(self, ftl_path: Path) -> int:
        """Count sprite files in a .ftl ZIP."""
        try:
            with zipfile.ZipFile(ftl_path, "r") as zf:
                return sum(1 for n in zf.namelist() if n.startswith("img/") and n.endswith(".png"))
        except zipfile.BadZipFile:
            return 0

    def _read_dir(self, mod_dir: Path) -> ModDetail:
        """Read full mod details from an unpacked directory."""
        stat = mod_dir.stat()
        ftl_exists = (self.mods_dir / f"{mod_dir.name}.ftl").exists()

        # Read XML files
        blueprints_xml = self._read_text(mod_dir / "data" / "blueprints.xml.append")
        events_xml = self._read_text(mod_dir / "data" / "events.xml.append")
        animations_xml = self._read_text(mod_dir / "data" / "animations.xml.append")
        metadata_xml = self._read_text(mod_dir / "mod-appendix" / "metadata.xml")

        # Parse blueprints
        weapons, drones, augments, crew = self._parse_blueprints(blueprints_xml)
        events = self._parse_events(events_xml)

        # Get sprite list
        sprites = []
        img_dir = mod_dir / "img"
        if img_dir.exists():
            for png in img_dir.rglob("*.png"):
                sprites.append(str(png.relative_to(img_dir)))

        # Get description from metadata
        description = self._extract_description(metadata_xml)

        return ModDetail(
            name=mod_dir.name,
            path=str(mod_dir),
            description=description,
            created_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
            has_ftl=ftl_exists,
            weapons=weapons,
            drones=drones,
            augments=augments,
            crew=crew,
            events=events,
            sprite_files=sprites,
            blueprints_xml=blueprints_xml,
            events_xml=events_xml,
            animations_xml=animations_xml,
            metadata_xml=metadata_xml,
        )

    def _read_ftl(self, ftl_path: Path) -> ModDetail:
        """Read full mod details from a .ftl ZIP."""
        stat = ftl_path.stat()

        try:
            with zipfile.ZipFile(ftl_path, "r") as zf:
                blueprints_xml = self._read_zip_text(zf, "data/blueprints.xml.append")
                events_xml = self._read_zip_text(zf, "data/events.xml.append")
                animations_xml = self._read_zip_text(zf, "data/animations.xml.append")
                metadata_xml = self._read_zip_text(zf, "mod-appendix/metadata.xml")
                sprites = [n[4:] for n in zf.namelist()
                           if n.startswith("img/") and n.endswith(".png")]
        except zipfile.BadZipFile:
            blueprints_xml = events_xml = animations_xml = metadata_xml = ""
            sprites = []

        weapons, drones, augments, crew = self._parse_blueprints(blueprints_xml)
        events = self._parse_events(events_xml)
        description = self._extract_description(metadata_xml)

        return ModDetail(
            name=ftl_path.stem,
            path=str(ftl_path),
            description=description,
            created_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
            has_ftl=True,
            weapons=weapons,
            drones=drones,
            augments=augments,
            crew=crew,
            events=events,
            sprite_files=sprites,
            blueprints_xml=blueprints_xml,
            events_xml=events_xml,
            animations_xml=animations_xml,
            metadata_xml=metadata_xml,
        )

    def _read_text(self, path: Path) -> str:
        """Read a text file, return empty string if missing."""
        if path.exists():
            return path.read_text()
        return ""

    def _read_zip_text(self, zf: zipfile.ZipFile, name: str) -> str:
        """Read a text entry from a ZIP, return empty string if missing."""
        if name in zf.namelist():
            return zf.read(name).decode("utf-8", errors="replace")
        return ""

    def _extract_description(self, metadata_xml: str) -> str:
        """Extract description from metadata XML."""
        if not metadata_xml:
            return ""
        try:
            root = etree.fromstring(metadata_xml.encode())
            desc_elem = root.find("description")
            return desc_elem.text or "" if desc_elem is not None else ""
        except etree.XMLSyntaxError:
            return ""

    def _parse_blueprints(self, xml_str: str) -> tuple[
        list[WeaponBlueprint], list[DroneBlueprint],
        list[AugmentBlueprint], list[CrewBlueprint]
    ]:
        """Parse blueprints.xml.append into Pydantic models."""
        weapons = []
        drones = []
        augments = []
        crew = []

        if not xml_str:
            return weapons, drones, augments, crew

        try:
            root = etree.fromstring(xml_str.encode())
        except etree.XMLSyntaxError:
            return weapons, drones, augments, crew

        for elem in root.findall("weaponBlueprint"):
            try:
                weapons.append(self._parse_weapon(elem))
            except Exception:
                pass

        for elem in root.findall("droneBlueprint"):
            try:
                drones.append(self._parse_drone(elem))
            except Exception:
                pass

        for elem in root.findall("augBlueprint"):
            try:
                augments.append(self._parse_augment(elem))
            except Exception:
                pass

        for elem in root.findall("crewBlueprint"):
            try:
                crew.append(self._parse_crew(elem))
            except Exception:
                pass

        return weapons, drones, augments, crew

    def _get_text(self, elem: etree._Element, tag: str, default: str = "") -> str:
        """Get text content of a child element."""
        child = elem.find(tag)
        return child.text or default if child is not None else default

    def _get_int(self, elem: etree._Element, tag: str, default: int = 0) -> int:
        """Get integer text content of a child element."""
        text = self._get_text(elem, tag)
        try:
            return int(text) if text else default
        except ValueError:
            return default

    def _get_float(self, elem: etree._Element, tag: str, default: float = 0.0) -> float:
        """Get float text content of a child element."""
        text = self._get_text(elem, tag)
        try:
            return float(text) if text else default
        except ValueError:
            return default

    def _parse_weapon(self, elem: etree._Element) -> WeaponBlueprint:
        """Parse a weaponBlueprint element."""
        name = elem.get("name", "UNKNOWN")
        weapon_type = self._get_text(elem, "type", "LASER")

        data = {
            "name": name,
            "type": weapon_type,
            "title": self._get_text(elem, "title", name),
            "short": self._get_text(elem, "short") or None,
            "desc": self._get_text(elem, "desc", ""),
            "tooltip": self._get_text(elem, "tooltip") or None,
            "damage": self._get_int(elem, "damage", 1),
            "shots": self._get_int(elem, "shots", 1),
            "cooldown": self._get_float(elem, "cooldown", 10.0),
            "power": self._get_int(elem, "power", 1),
            "cost": self._get_int(elem, "cost", 50),
            "rarity": self._get_int(elem, "rarity", 2),
            "fireChance": self._get_int(elem, "fireChance"),
            "breachChance": self._get_int(elem, "breachChance"),
            "weaponArt": self._get_text(elem, "weaponArt") or None,
        }

        sp_val = self._get_text(elem, "sp")
        if sp_val:
            data["sp"] = int(sp_val)

        ion_val = self._get_text(elem, "ion")
        if ion_val:
            data["ion"] = int(ion_val)

        length_val = self._get_text(elem, "length")
        if length_val:
            data["length"] = int(length_val)

        missiles_val = self._get_text(elem, "missiles")
        if missiles_val:
            data["missiles"] = int(missiles_val)

        return WeaponBlueprint(**data)

    def _parse_drone(self, elem: etree._Element) -> DroneBlueprint:
        """Parse a droneBlueprint element."""
        name = elem.get("name", "UNKNOWN")
        data = {
            "name": name,
            "type": self._get_text(elem, "type", "COMBAT"),
            "title": self._get_text(elem, "title", name),
            "short": self._get_text(elem, "short") or None,
            "desc": self._get_text(elem, "desc", ""),
            "power": self._get_int(elem, "power", 1),
            "cost": self._get_int(elem, "cost", 50),
            "rarity": self._get_int(elem, "rarity", 2),
        }

        cooldown = self._get_text(elem, "cooldown")
        if cooldown:
            data["cooldown"] = float(cooldown)
        speed = self._get_text(elem, "speed")
        if speed:
            data["speed"] = int(speed)

        drone_image = self._get_text(elem, "droneImage")
        if drone_image:
            data["drone_image"] = drone_image

        return DroneBlueprint(**data)

    def _parse_augment(self, elem: etree._Element) -> AugmentBlueprint:
        """Parse an augBlueprint element."""
        name = elem.get("name", "UNKNOWN")
        data = {
            "name": name,
            "title": self._get_text(elem, "title", name),
            "desc": self._get_text(elem, "desc", ""),
            "cost": self._get_int(elem, "cost", 50),
            "rarity": self._get_int(elem, "rarity", 2),
        }

        stackable = self._get_text(elem, "stackable")
        if stackable == "true":
            data["stackable"] = True

        value = self._get_text(elem, "value")
        if value:
            data["value"] = float(value)

        return AugmentBlueprint(**data)

    def _parse_crew(self, elem: etree._Element) -> CrewBlueprint:
        """Parse a crewBlueprint element."""
        name = elem.get("name", "UNKNOWN")
        data = {
            "name": name,
            "title": self._get_text(elem, "title", name),
            "desc": self._get_text(elem, "desc", ""),
            "cost": self._get_int(elem, "cost", 50),
        }

        power_list = elem.find("powerList")
        if power_list is not None:
            data["maxHealth"] = self._get_int(power_list, "maxHealth", 100)
            data["moveSpeed"] = self._get_int(power_list, "moveSpeed", 100)
            data["repairSpeed"] = self._get_int(power_list, "repairSpeed", 100)
            dm = self._get_text(power_list, "damageMultiplier")
            if dm:
                data["damageMultiplier"] = float(dm)
            fr = self._get_text(power_list, "fireRepair")
            if fr:
                data["fireRepair"] = int(fr)
            sm = self._get_text(power_list, "suffocationModifier")
            if sm:
                data["suffocationModifier"] = float(sm)

            if self._get_text(power_list, "canFight") == "false":
                data["canFight"] = False
            if self._get_text(power_list, "controllable") == "false":
                data["controllable"] = False
            if self._get_text(power_list, "canRepair") == "false":
                data["canRepair"] = False
            if self._get_text(power_list, "canMan") == "false":
                data["canMan"] = False
            if self._get_text(power_list, "canSabotage") == "false":
                data["canSabotage"] = False
            if self._get_text(power_list, "canSuffocate") == "false":
                data["canSuffocate"] = False
            if self._get_text(power_list, "canBurn") == "false":
                data["canBurn"] = False
            if self._get_text(power_list, "providePower") == "true":
                data["providePower"] = True

        return CrewBlueprint(**data)

    def _parse_events(self, xml_str: str) -> list[EventBlueprint]:
        """Parse events.xml.append into EventBlueprint models."""
        if not xml_str:
            return []

        try:
            root = etree.fromstring(xml_str.encode())
        except etree.XMLSyntaxError:
            return []

        events = []
        for elem in root.findall("event[@name]"):
            try:
                events.append(self._parse_event(elem))
            except Exception:
                pass

        return events

    def _parse_event(self, elem: etree._Element) -> EventBlueprint:
        """Parse an event element."""
        name = elem.get("name", "UNKNOWN")
        data = {
            "name": name,
            "text": self._get_text(elem, "text", ""),
            "unique": elem.get("unique") == "true",
        }

        # Ship encounter
        ship_elem = elem.find("ship")
        if ship_elem is not None:
            data["ship"] = ship_elem.get("load")
            data["hostile"] = ship_elem.get("hostile") == "true"

        data["distressBeacon"] = elem.find("distressBeacon") is not None

        env_elem = elem.find("environment")
        if env_elem is not None:
            data["environment"] = env_elem.get("type")

        # Choices
        choices = []
        for choice_elem in elem.findall("choice"):
            choices.append(self._parse_choice(choice_elem))
        if choices:
            data["choices"] = choices

        return EventBlueprint(**data)

    def _parse_choice(self, elem: etree._Element) -> EventChoice:
        """Parse a choice element."""
        data = {
            "text": self._get_text(elem, "text", ""),
            "hidden": elem.get("hidden") == "true",
        }
        req = elem.get("req")
        if req:
            data["req"] = req
        lvl = elem.get("lvl")
        if lvl:
            data["level"] = int(lvl)

        event_elem = elem.find("event")
        if event_elem is not None:
            data["event"] = self._parse_outcome(event_elem)

        return EventChoice(**data)

    def _parse_outcome(self, elem: etree._Element) -> EventOutcome:
        """Parse an event outcome element."""
        data: dict = {}
        text = self._get_text(elem, "text")
        if text:
            data["text"] = text

        weapon = elem.find("weapon")
        if weapon is not None:
            data["weapon"] = weapon.get("name")

        drone = elem.find("drone")
        if drone is not None:
            data["drone"] = drone.get("name")

        augment = elem.find("augment")
        if augment is not None:
            data["augment"] = augment.get("name")

        crew_member = elem.find("crewMember")
        if crew_member is not None:
            data["addCrew"] = crew_member.get("class")

        if elem.find("removeCrew") is not None:
            data["removeCrew"] = True

        if elem.find("store") is not None:
            data["store"] = True

        load_event = elem.find("event")
        if load_event is not None and load_event.get("load"):
            data["loadEvent"] = load_event.get("load")

        return EventOutcome(**data)
