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

    def build_weapon(self, weapon: WeaponBlueprint) -> etree._Element:
        """Build weaponBlueprint XML element."""
        bp = etree.Element("weaponBlueprint", name=weapon.name)

        # Basic info
        self._add_element(bp, "type", weapon.type)
        self._add_element(bp, "title", weapon.title)
        if weapon.short:
            self._add_element(bp, "short", weapon.short)
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

        # Timing and resources
        # Format cooldown as int if it's a whole number
        cooldown_str = str(int(weapon.cooldown)) if weapon.cooldown == int(weapon.cooldown) else str(weapon.cooldown)
        self._add_element(bp, "cooldown", cooldown_str)
        self._add_element(bp, "power", str(weapon.power))
        self._add_element(bp, "cost", str(weapon.cost))
        self._add_element(bp, "rarity", str(weapon.rarity))

        # Visual
        if weapon.weapon_art:
            self._add_element(bp, "weaponArt", weapon.weapon_art)
        if weapon.image:
            self._add_element(bp, "image", weapon.image)

        return bp

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

        # Auto-reward section
        auto = None
        if any([outcome.scrap, outcome.fuel, outcome.missiles, outcome.drones]):
            auto = self._add_element(event, "autoReward", level="LOW")

        # Item section
        if outcome.scrap:
            item = self._add_element(event, "item", type="scrap")
            item.set("min", str(max(0, outcome.scrap - 10)))
            item.set("max", str(outcome.scrap + 10))

        if outcome.fuel:
            self._add_element(event, "modifyPursuit", amount=str(-outcome.fuel) if outcome.fuel < 0 else str(outcome.fuel))

        if outcome.hull:
            dmg = self._add_element(event, "damage", amount=str(-outcome.hull))
            dmg.set("effect", "random")

        # Items
        if outcome.weapon:
            self._add_element(event, "weapon", name=outcome.weapon)
        if outcome.drone:
            self._add_element(event, "drone", name=outcome.drone)
        if outcome.augment:
            self._add_element(event, "augment", name=outcome.augment)

        # Crew
        if outcome.add_crew:
            self._add_element(event, "crewMember", amount="1", class_=outcome.add_crew)
        if outcome.remove_crew:
            self._add_element(event, "removeCrew")

        # System damage
        if outcome.damage_system:
            dmg = self._add_element(event, "damage")
            dmg.set("system", outcome.damage_system)
            dmg.set("amount", str(outcome.damage_amount or 1))

        # Chain
        if outcome.load_event:
            self._add_element(event, "event", load=outcome.load_event)

        # Store
        if outcome.store:
            self._add_element(event, "store")

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

    def build_animations_append(self, weapon_names: list[str]) -> str:
        """Build animations.xml.append for weapon sprites."""
        root = self._create_root()

        for name in weapon_names:
            name_lower = name.lower()

            # Animation sheet
            sheet = etree.SubElement(
                root, "animSheet",
                name=name_lower,
                w="192", h="60",
                fw="16", fh="60"
            )
            sheet.text = f"weapons/{name_lower}_strip12.png"

            # Weapon animation
            anim = etree.SubElement(root, "weaponAnim", name=name_lower)
            self._add_element(anim, "sheet", name_lower)
            etree.SubElement(anim, "desc", length="12", x="0", y="0")
            self._add_element(anim, "chargedFrame", "5")
            self._add_element(anim, "fireFrame", "7")
            etree.SubElement(anim, "firePoint", x="8", y="30")
            etree.SubElement(anim, "mountPoint", x="0", y="30")

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
