"""XML generation for FTL mod files."""

from lxml import etree

from ftl_gen.xml.schemas import (
    AugmentBlueprint,
    CrewBlueprint,
    DroneBlueprint,
    EventBlueprint,
    EventChoice,
    EventOutcome,
    ModContent,
    WeaponBlueprint,
)


class XMLBuilder:
    """Builds FTL XML files from Pydantic models."""

    @staticmethod
    def _create_root() -> etree._Element:
        """Create XML root element for append files."""
        return etree.Element("FTL")

    @staticmethod
    def _add_element(
        parent: etree._Element, tag: str, text: str | None = None, **attribs: str
    ) -> etree._Element:
        """Add a child element with optional text and attributes."""
        elem = etree.SubElement(parent, tag, **attribs)
        if text is not None:
            elem.text = str(text)
        return elem

    # Vanilla FTL assets by weapon type
    WEAPON_ASSETS = {
        "LASER": {
            "image": "laser_light1",
            "weaponArt": "laser_burst_1",
            "launch": ["lightLaser1", "lightLaser2", "lightLaser3"],
            "hitShip": ["hitHull1", "hitHull2", "hitHull3"],
            "hitShield": ["hitShield1", "hitShield2", "hitShield3"],
        },
        "BURST": {
            "image": "laser_burst1",
            "weaponArt": "laser_burst_2",
            "launch": ["lightLaser1", "lightLaser2", "lightLaser3"],
            "hitShip": ["hitHull1", "hitHull2", "hitHull3"],
            "hitShield": ["hitShield1", "hitShield2", "hitShield3"],
        },
        "ION": {
            "image": "intruder_ion",
            "weaponArt": "ion_1",
            "launch": ["ionShoot1", "ionShoot2", "ionShoot3"],
            "hitShip": ["intruder_ionHit"],
            "hitShield": ["intruder_ionHit"],
        },
        "BEAM": {
            "image": "beam_contact",
            "weaponArt": "beam_1",
            "launch": ["beam1"],
            "hitShip": [],
            "hitShield": [],
        },
        "MISSILES": {
            "image": "missile_2",
            "weaponArt": "missiles_2",
            "launch": ["missileLaunch"],
            "hitShip": ["explosion2", "explosion3", "explosion1"],
            "hitShield": [],
            "miss": ["miss"],
        },
        "BOMB": {
            "image": "bomb_1",
            "weaponArt": "bomb_1",
            "launch": ["bombTeleport"],
            "hitShip": ["smallExplosion"],
            "hitShield": [],
        },
    }

    def build_weapon(self, weapon: WeaponBlueprint) -> etree._Element:
        """Build weaponBlueprint XML element."""
        bp = etree.Element("weaponBlueprint", name=weapon.name)

        # Basic info
        self._add_element(bp, "type", weapon.type)
        self._add_element(bp, "title", weapon.title)
        # Short name is REQUIRED for weapons to display in the weapon bar
        # If not provided, generate from title (max 8 chars)
        short_name = weapon.short
        if not short_name:
            # Generate short name: take first word or abbreviate
            words = weapon.title.split()
            if len(words) == 1:
                short_name = weapon.title[:8]
            else:
                # Try first word, or combine initials
                short_name = words[0][:8] if len(words[0]) <= 8 else "".join(w[0] for w in words[:4])
        self._add_element(bp, "short", short_name)
        self._add_element(bp, "desc", weapon.desc)
        if weapon.tooltip:
            self._add_element(bp, "tooltip", weapon.tooltip)

        # Combat stats
        self._add_element(bp, "damage", str(weapon.damage))
        if weapon.type in ("LASER", "BURST", "ION"):
            self._add_element(bp, "shots", str(weapon.shots))
        if weapon.sp:
            self._add_element(bp, "sp", str(weapon.sp))
        if weapon.ion:
            self._add_element(bp, "ion", str(weapon.ion))
        if weapon.stun:
            self._add_element(bp, "stun", str(weapon.stun))

        # Effects
        if weapon.fire_chance > 0:
            self._add_element(bp, "fireChance", str(weapon.fire_chance))
        if weapon.breach_chance > 0:
            self._add_element(bp, "breachChance", str(weapon.breach_chance))
        if weapon.hull_bust:
            self._add_element(bp, "hullBust", "true")
        if weapon.lockdown:
            self._add_element(bp, "lockdown", "true")
        if weapon.crew_damage:
            self._add_element(bp, "persDamage", str(weapon.crew_damage))
        if weapon.sys_damage:
            self._add_element(bp, "sysDamage", str(weapon.sys_damage))

        # Beam specific
        if weapon.type == "BEAM" and weapon.length:
            self._add_element(bp, "length", str(weapon.length))

        # Missile/bomb specific
        if weapon.missiles:
            self._add_element(bp, "missiles", str(weapon.missiles))

        # Bombs and missiles need explosion animation and shots
        if weapon.type in ("BOMB", "MISSILES"):
            self._add_element(bp, "shots", "1")
            if not weapon.sp:  # Only add sp=0 if not already set
                self._add_element(bp, "sp", "0")
            explosion = weapon.explosion if weapon.explosion else "explosion_random"
            self._add_element(bp, "explosion", explosion)

        # Timing and resources
        # Format cooldown as int if it's a whole number
        cooldown_str = str(int(weapon.cooldown)) if weapon.cooldown == int(weapon.cooldown) else str(weapon.cooldown)
        self._add_element(bp, "cooldown", cooldown_str)
        self._add_element(bp, "power", str(weapon.power))
        self._add_element(bp, "cost", str(weapon.cost))
        self._add_element(bp, "rarity", str(weapon.rarity))

        # Get vanilla assets for this weapon type
        assets = self.WEAPON_ASSETS.get(weapon.type, self.WEAPON_ASSETS["LASER"])

        # Projectile/beam image - always use vanilla assets since custom images don't exist
        self._add_element(bp, "image", assets["image"])

        # Weapon art (links to animation for the weapon mount sprite)
        # Only use custom weaponArt if it matches our sprite naming convention (lowercase weapon name)
        # This means it was set by our sprite generator, not hallucinated by the LLM
        if weapon.weapon_art and weapon.weapon_art == weapon.name.lower():
            self._add_element(bp, "weaponArt", weapon.weapon_art)
        else:
            self._add_element(bp, "weaponArt", assets["weaponArt"])

        # Sound effects (required for weapon to function properly)
        if assets["launch"]:
            launch_elem = etree.SubElement(bp, "launchSounds")
            for sound in assets["launch"]:
                self._add_element(launch_elem, "sound", sound)

        if assets["hitShip"]:
            hit_ship_elem = etree.SubElement(bp, "hitShipSounds")
            for sound in assets["hitShip"]:
                self._add_element(hit_ship_elem, "sound", sound)

        if assets["hitShield"]:
            hit_shield_elem = etree.SubElement(bp, "hitShieldSounds")
            for sound in assets["hitShield"]:
                self._add_element(hit_shield_elem, "sound", sound)

        if "miss" in assets and assets["miss"]:
            miss_elem = etree.SubElement(bp, "missSounds")
            for sound in assets["miss"]:
                self._add_element(miss_elem, "sound", sound)

        return bp

    # Default vanilla drone images by type
    DRONE_IMAGES = {
        "COMBAT": "drone_player_combat",
        "DEFENSE": "drone_player_defensive",
        "SHIP_REPAIR": "drone_repair_ship",
        "BOARDER": "drone_boarder",
        "REPAIR": "drone_repair",
        "BATTLE": "drone_player_battle",
        "HACKING": "drone_hacking",
    }

    def build_drone(self, drone: DroneBlueprint) -> etree._Element:
        """Build droneBlueprint XML element."""
        bp = etree.Element("droneBlueprint", name=drone.name)

        self._add_element(bp, "type", drone.type)
        self._add_element(bp, "title", drone.title)
        if drone.short:
            self._add_element(bp, "short", drone.short)
        self._add_element(bp, "desc", drone.desc)
        self._add_element(bp, "power", str(drone.power))
        self._add_element(bp, "cost", str(drone.cost))
        self._add_element(bp, "rarity", str(drone.rarity))

        if drone.cooldown:
            self._add_element(bp, "cooldown", str(drone.cooldown))
        if drone.speed:
            self._add_element(bp, "speed", str(drone.speed))

        # Drone image - use custom if available, otherwise vanilla default
        if drone.drone_image and drone.drone_image == drone.name.lower():
            self._add_element(bp, "droneImage", drone.drone_image)
        else:
            default_image = self.DRONE_IMAGES.get(drone.type, "drone_player_combat")
            self._add_element(bp, "droneImage", default_image)

        return bp

    def build_augment(self, augment: AugmentBlueprint) -> etree._Element:
        """Build augBlueprint XML element."""
        bp = etree.Element("augBlueprint", name=augment.name)

        self._add_element(bp, "title", augment.title)
        self._add_element(bp, "desc", augment.desc)
        self._add_element(bp, "cost", str(augment.cost))
        self._add_element(bp, "rarity", str(augment.rarity))
        if augment.stackable:
            self._add_element(bp, "stackable", "true")
        if augment.value is not None:
            self._add_element(bp, "value", str(augment.value))

        return bp

    def build_crew(self, crew: CrewBlueprint) -> etree._Element:
        """Build crewBlueprint XML element."""
        bp = etree.Element("crewBlueprint", name=crew.name)

        self._add_element(bp, "title", crew.title)
        if crew.short:
            self._add_element(bp, "short", crew.short)
        self._add_element(bp, "desc", crew.desc)
        self._add_element(bp, "cost", str(crew.cost))

        # Stats
        power_list = self._add_element(bp, "powerList")
        self._add_element(power_list, "maxHealth", str(crew.max_health))
        self._add_element(power_list, "moveSpeed", str(crew.move_speed))
        self._add_element(power_list, "repairSpeed", str(crew.repair_speed))
        self._add_element(power_list, "damageMultiplier", str(crew.damage_multiplier))
        self._add_element(power_list, "fireRepair", str(crew.fire_repair))
        self._add_element(power_list, "suffocationModifier", str(crew.suffocation_modifier))

        # Abilities
        if not crew.can_fight:
            self._add_element(power_list, "canFight", "false")
        if not crew.controllable:
            self._add_element(power_list, "controllable", "false")
        if not crew.can_repair:
            self._add_element(power_list, "canRepair", "false")
        if not crew.can_man:
            self._add_element(power_list, "canMan", "false")
        if not crew.can_sabotage:
            self._add_element(power_list, "canSabotage", "false")
        if not crew.can_suffocate:
            self._add_element(power_list, "canSuffocate", "false")
        if not crew.can_burn:
            self._add_element(power_list, "canBurn", "false")
        if crew.provide_power:
            self._add_element(power_list, "providePower", "true")
        if crew.clone_speed_modifier != 1.0:
            self._add_element(power_list, "cloneSpeedModifier", str(crew.clone_speed_modifier))

        return bp

    def build_event_outcome(self, outcome: EventOutcome) -> etree._Element:
        """Build event outcome XML element."""
        event = etree.Element("event")

        if outcome.text:
            self._add_element(event, "text", outcome.text)

        # Auto-reward with proper FTL format
        if any([outcome.scrap, outcome.fuel, outcome.missiles, outcome.drones]):
            # Determine reward level based on amounts
            level = "LOW"
            max_reward = max(
                abs(outcome.scrap or 0),
                abs(outcome.fuel or 0) * 5,
                abs(outcome.missiles or 0) * 3,
                abs(outcome.drones or 0) * 5,
            )
            if max_reward > 50:
                level = "HIGH"
            elif max_reward > 25:
                level = "MED"
            self._add_element(event, "autoReward", "standard", level=level)

        # Hull damage/repair
        if outcome.hull:
            if outcome.hull < 0:
                # Damage the player's ship
                dmg = etree.SubElement(event, "damage", amount=str(-outcome.hull))
                dmg.set("effect", "random")
            else:
                # Repair - not directly supported, use autoReward instead
                pass

        # Item rewards
        if outcome.weapon:
            etree.SubElement(event, "weapon", name=outcome.weapon)
        if outcome.drone:
            etree.SubElement(event, "drone", name=outcome.drone)
        if outcome.augment:
            etree.SubElement(event, "augment", name=outcome.augment)

        # Crew
        if outcome.add_crew:
            crew_elem = etree.SubElement(event, "crewMember", amount="1")
            crew_elem.set("class", outcome.add_crew)
        if outcome.remove_crew:
            etree.SubElement(event, "removeCrew")

        # System damage
        if outcome.damage_system:
            dmg = etree.SubElement(event, "damage")
            dmg.set("system", outcome.damage_system)
            dmg.set("amount", str(outcome.damage_amount or 1))

        # Chain
        if outcome.load_event:
            etree.SubElement(event, "event", load=outcome.load_event)

        # Store
        if outcome.store:
            etree.SubElement(event, "store")

        return event

    def build_choice(self, choice: EventChoice) -> etree._Element:
        """Build event choice XML element."""
        attrs = {}
        if choice.hidden:
            attrs["hidden"] = "true"
        if choice.req:
            attrs["req"] = choice.req
        if choice.level:
            attrs["lvl"] = str(choice.level)

        choice_elem = etree.Element("choice", **attrs)
        self._add_element(choice_elem, "text", choice.text)

        if choice.event:
            outcome_elem = self.build_event_outcome(choice.event)
            choice_elem.append(outcome_elem)

        return choice_elem

    def build_event(self, event: EventBlueprint) -> etree._Element:
        """Build event XML element."""
        attrs = {"name": event.name}
        if event.unique:
            attrs["unique"] = "true"

        event_elem = etree.Element("event", **attrs)

        self._add_element(event_elem, "text", event.text)

        # Ship encounter
        if event.ship:
            ship_elem = self._add_element(event_elem, "ship", load=event.ship)
            if event.hostile:
                ship_elem.set("hostile", "true")

        if event.distress_beacon:
            self._add_element(event_elem, "distressBeacon")

        if event.environment:
            self._add_element(event_elem, "environment", type=event.environment)

        # Auto reward (no choices)
        if event.auto_reward and not event.choices:
            outcome_elem = self.build_event_outcome(event.auto_reward)
            for child in outcome_elem:
                event_elem.append(child)

        # Choices
        for choice in event.choices:
            choice_elem = self.build_choice(choice)
            event_elem.append(choice_elem)

        return event_elem

    def build_kestrel_loadout(self, weapon_name: str) -> etree._Element:
        """Build a modified Kestrel A loadout with a custom weapon for testing.

        Replaces the Artemis Missiles with the specified weapon.
        """
        # Complete Kestrel A ship blueprint with all systems
        ship = etree.Element("shipBlueprint", name="PLAYER_SHIP_HARD", layout="kestral", img="kestral")

        etree.SubElement(ship, "class").text = "Kestrel Cruiser"
        etree.SubElement(ship, "name").text = "The Kestrel"
        etree.SubElement(ship, "desc").text = "This class of ship was decommissioned from the Federation fleet years ago. After a number of refits and adjustments, this classic ship is ready for battle."

        # Full system list for Kestrel A
        system_list = etree.SubElement(ship, "systemList")
        etree.SubElement(system_list, "pilot", power="1", room="0", start="true", img="room_pilot")
        etree.SubElement(system_list, "doors", power="1", room="2", start="true", img="room_doors")
        etree.SubElement(system_list, "sensors", power="1", room="3", start="true", img="room_sensors")
        etree.SubElement(system_list, "medbay", power="1", room="4", start="true", img="room_medbay")
        etree.SubElement(system_list, "oxygen", power="1", room="13", start="true", img="room_oxygen")
        etree.SubElement(system_list, "shields", power="2", room="5", start="true", img="room_shields")
        etree.SubElement(system_list, "engines", power="2", room="14", start="true", img="room_engines")
        etree.SubElement(system_list, "weapons", power="3", room="11", start="true", img="room_weapons")
        etree.SubElement(system_list, "drones", power="0", room="8", start="false")
        etree.SubElement(system_list, "teleporter", power="0", room="1", start="false")
        etree.SubElement(system_list, "cloaking", power="0", room="6", start="false")

        etree.SubElement(ship, "weaponSlots").text = "4"
        etree.SubElement(ship, "droneSlots").text = "2"

        # Weapons: keep Burst Laser II, replace Artemis with custom weapon
        weapon_list = etree.SubElement(ship, "weaponList", missiles="8", count="2")
        etree.SubElement(weapon_list, "weapon", name="LASER_BURST_3")
        etree.SubElement(weapon_list, "weapon", name=weapon_name)

        etree.SubElement(ship, "droneList", drones="0", count="0")

        etree.SubElement(ship, "health", amount="30")
        etree.SubElement(ship, "maxPower", amount="8")

        etree.SubElement(ship, "crewCount", amount="3", max="8", **{"class": "human"})

        return ship

    def build_blueprints_append(self, content: ModContent) -> str:
        """Build blueprints.xml.append content."""
        root = self._create_root()

        # Weapons
        for weapon in content.weapons:
            root.append(self.build_weapon(weapon))

        # Drones
        for drone in content.drones:
            root.append(self.build_drone(drone))

        # Augments
        for augment in content.augments:
            root.append(self.build_augment(augment))

        # Crew
        for crew in content.crew:
            root.append(self.build_crew(crew))

        # Add Kestrel loadout modification for testing (first weapon)
        if content.weapons:
            root.append(self.build_kestrel_loadout(content.weapons[0].name))

        return etree.tostring(root, pretty_print=True, encoding="unicode", xml_declaration=False)

    def build_events_append(self, content: ModContent) -> str:
        """Build events.xml.append content."""
        root = self._create_root()

        for event in content.events:
            root.append(self.build_event(event))

        # Create event lists for sectors if needed
        if content.events:
            event_list = etree.SubElement(root, "eventList", name=f"{content.metadata.name.upper()}_EVENTS")
            for event in content.events:
                self._add_element(event_list, "event", load=event.name)

        return etree.tostring(root, pretty_print=True, encoding="unicode", xml_declaration=False)

    # FTL weapon sprite frame dimensions (must match sprites.py)
    # Vanilla: 16x60 frames, weapon points UP
    FRAME_WIDTH = 16
    FRAME_HEIGHT = 60
    FRAME_COUNT = 12

    # FTL drone sprite frame dimensions (must match sprites.py)
    # Vanilla: 50x20 frames, 4 frames, drone faces right
    DRONE_FRAME_WIDTH = 50
    DRONE_FRAME_HEIGHT = 20
    DRONE_FRAME_COUNT = 4

    def build_animations_append(self, weapon_names: list[str]) -> str:
        """Build animations.xml.append for weapon sprites."""
        root = self._create_root()

        # Calculate sheet dimensions
        sheet_width = self.FRAME_WIDTH * self.FRAME_COUNT  # 660
        sheet_height = self.FRAME_HEIGHT  # 28

        for name in weapon_names:
            name_lower = name.lower()

            # Animation sheet
            sheet = etree.SubElement(
                root, "animSheet",
                name=name_lower,
                w=str(sheet_width), h=str(sheet_height),
                fw=str(self.FRAME_WIDTH), fh=str(self.FRAME_HEIGHT)
            )
            sheet.text = f"weapons/{name_lower}_strip12.png"

            # Weapon animation
            anim = etree.SubElement(root, "weaponAnim", name=name_lower)
            self._add_element(anim, "sheet", name_lower)
            etree.SubElement(anim, "desc", length="12", x="0", y="0")
            self._add_element(anim, "chargedFrame", "5")
            self._add_element(anim, "fireFrame", "7")
            # firePoint: where projectiles spawn (right edge, vertically centered)
            etree.SubElement(anim, "firePoint", x=str(self.FRAME_WIDTH - 5), y=str(self.FRAME_HEIGHT // 2))
            # mountPoint: where weapon attaches to ship (left edge, vertically centered)
            etree.SubElement(anim, "mountPoint", x="0", y=str(self.FRAME_HEIGHT // 2))

        return etree.tostring(root, pretty_print=True, encoding="unicode", xml_declaration=False)

    def build_drone_animations_append(self, drone_names: list[str]) -> str:
        """Build animations.xml.append for drone sprites."""
        root = self._create_root()

        # Calculate sheet dimensions
        sheet_width = self.DRONE_FRAME_WIDTH * self.DRONE_FRAME_COUNT  # 200
        sheet_height = self.DRONE_FRAME_HEIGHT  # 20

        for name in drone_names:
            name_lower = name.lower()

            # Animation sheet
            sheet = etree.SubElement(
                root, "animSheet",
                name=name_lower,
                w=str(sheet_width), h=str(sheet_height),
                fw=str(self.DRONE_FRAME_WIDTH), fh=str(self.DRONE_FRAME_HEIGHT)
            )
            sheet.text = f"drones/{name_lower}_sheet.png"

            # Drone animation
            anim = etree.SubElement(root, "anim", name=name_lower)
            self._add_element(anim, "sheet", name_lower)
            etree.SubElement(anim, "desc", length="4", x="0", y="0")
            self._add_element(anim, "time", "0.3")

        return etree.tostring(root, pretty_print=True, encoding="unicode", xml_declaration=False)

    def build_metadata_append(self, content: ModContent) -> str:
        """Build metadata.xml content for mod-appendix."""
        root = etree.Element("metadata")

        self._add_element(root, "title", content.metadata.name)
        self._add_element(root, "author", content.metadata.author)
        self._add_element(root, "version", content.metadata.version)
        self._add_element(root, "description", content.metadata.description)
        if content.metadata.url:
            self._add_element(root, "url", content.metadata.url)
        if content.metadata.thread_id:
            self._add_element(root, "threadId", str(content.metadata.thread_id))

        xml_str = etree.tostring(root, pretty_print=True, encoding="unicode")
        return '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_str
