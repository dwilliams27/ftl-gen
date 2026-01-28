"""Tests for XML schema models and builders."""

import pytest
from lxml import etree

from ftl_gen.xml.builders import XMLBuilder
from ftl_gen.xml.schemas import (
    EventBlueprint,
    EventChoice,
    EventOutcome,
    ModContent,
    ModMetadata,
    WeaponBlueprint,
)


class TestWeaponBlueprint:
    """Tests for WeaponBlueprint model."""

    def test_basic_weapon(self):
        weapon = WeaponBlueprint(
            name="TEST_LASER",
            type="LASER",
            title="Test Laser",
            desc="A test weapon",
            damage=2,
            shots=2,
            cooldown=10,
            power=2,
            cost=50,
        )

        assert weapon.name == "TEST_LASER"
        assert weapon.type == "LASER"
        assert weapon.damage == 2
        assert weapon.shots == 2

    def test_name_normalization(self):
        weapon = WeaponBlueprint(
            name="test weapon-name",
            type="LASER",
            title="Test",
            desc="Test",
            cooldown=10,
            power=2,
            cost=50,
        )

        assert weapon.name == "TEST_WEAPON_NAME"

    def test_defaults(self):
        weapon = WeaponBlueprint(
            name="TEST",
            type="LASER",
            title="Test",
            desc="Test",
            cooldown=10,
            power=2,
            cost=50,
        )

        assert weapon.damage == 1
        assert weapon.shots == 1
        assert weapon.fire_chance == 0
        assert weapon.breach_chance == 0
        assert weapon.rarity == 2

    def test_validation_ranges(self):
        with pytest.raises(ValueError):
            WeaponBlueprint(
                name="TEST",
                type="LASER",
                title="Test",
                desc="Test",
                damage=15,  # Too high
                cooldown=10,
                power=2,
                cost=50,
            )

    def test_beam_weapon(self):
        weapon = WeaponBlueprint(
            name="TEST_BEAM",
            type="BEAM",
            title="Test Beam",
            desc="A test beam",
            damage=2,
            length=40,
            cooldown=15,
            power=3,
            cost=65,
        )

        assert weapon.type == "BEAM"
        assert weapon.length == 40


class TestEventBlueprint:
    """Tests for EventBlueprint model."""

    def test_basic_event(self):
        event = EventBlueprint(
            name="TEST_EVENT",
            text="You encounter a test event.",
            choices=[
                EventChoice(
                    text="Accept the test",
                    event=EventOutcome(text="The test was successful.", scrap=50),
                ),
                EventChoice(
                    text="Decline the test",
                    event=EventOutcome(text="You leave."),
                ),
            ],
        )

        assert event.name == "TEST_EVENT"
        assert len(event.choices) == 2
        assert event.choices[0].event.scrap == 50

    def test_event_with_requirements(self):
        event = EventBlueprint(
            name="CREW_EVENT",
            text="An event requiring specific crew.",
            choices=[
                EventChoice(
                    text="Send the Engi",
                    req="engi",
                    hidden=True,
                    event=EventOutcome(text="The Engi succeeds."),
                ),
            ],
        )

        assert event.choices[0].req == "engi"
        assert event.choices[0].hidden is True


class TestXMLBuilder:
    """Tests for XMLBuilder."""

    def test_build_weapon(self):
        builder = XMLBuilder()
        weapon = WeaponBlueprint(
            name="PLASMA_LASER",
            type="LASER",
            title="Plasma Laser",
            desc="A powerful plasma weapon",
            damage=3,
            shots=2,
            fireChance=3,
            cooldown=12,
            power=3,
            cost=75,
            rarity=3,
        )

        xml = builder.build_weapon(weapon)

        assert xml.tag == "weaponBlueprint"
        assert xml.get("name") == "PLASMA_LASER"
        assert xml.find("type").text == "LASER"
        assert xml.find("damage").text == "3"
        assert xml.find("shots").text == "2"
        assert xml.find("fireChance").text == "3"
        assert xml.find("cooldown").text == "12"
        assert xml.find("power").text == "3"

    def test_build_event(self):
        builder = XMLBuilder()
        event = EventBlueprint(
            name="TEST_ENCOUNTER",
            text="You find a derelict ship.",
            choices=[
                EventChoice(
                    text="Board the ship",
                    event=EventOutcome(text="You find supplies.", scrap=30),
                ),
                EventChoice(
                    text="Leave it alone",
                    event=EventOutcome(text="You continue on."),
                ),
            ],
        )

        xml = builder.build_event(event)

        assert xml.tag == "event"
        assert xml.get("name") == "TEST_ENCOUNTER"
        assert xml.find("text").text == "You find a derelict ship."

        choices = xml.findall("choice")
        assert len(choices) == 2
        assert choices[0].find("text").text == "Board the ship"

    def test_build_blueprints_append(self):
        builder = XMLBuilder()
        content = ModContent(
            metadata=ModMetadata(name="TestMod", description="A test mod"),
            weapons=[
                WeaponBlueprint(
                    name="TEST_WEAPON",
                    type="LASER",
                    title="Test",
                    desc="Test",
                    cooldown=10,
                    power=2,
                    cost=50,
                ),
            ],
        )

        xml_str = builder.build_blueprints_append(content)

        assert "<FTL>" in xml_str
        assert "<weaponBlueprint" in xml_str
        assert 'name="TEST_WEAPON"' in xml_str

    def test_build_animations_append(self):
        builder = XMLBuilder()
        weapon_names = ["PLASMA_LASER", "CRYSTAL_BEAM"]

        xml_str = builder.build_animations_append(weapon_names)

        assert "<FTL>" in xml_str
        assert "<animSheet" in xml_str
        assert "plasma_laser_strip12.png" in xml_str
        assert "<weaponAnim" in xml_str

    def test_xml_is_valid(self):
        builder = XMLBuilder()
        weapon = WeaponBlueprint(
            name="VALID_WEAPON",
            type="MISSILES",
            title="Valid Missile",
            desc="A valid weapon",
            damage=3,
            missiles=1,
            cooldown=15,
            power=2,
            cost=60,
        )

        xml = builder.build_weapon(weapon)
        # Should not raise
        xml_str = etree.tostring(xml, encoding="unicode")
        parsed = etree.fromstring(xml_str)
        assert parsed is not None


class TestModContent:
    """Tests for ModContent model."""

    def test_empty_mod(self):
        content = ModContent(
            metadata=ModMetadata(name="EmptyMod", description="Empty"),
        )

        assert content.weapons == []
        assert content.events == []
        assert content.drones == []

    def test_full_mod(self):
        content = ModContent(
            metadata=ModMetadata(name="FullMod", description="Full"),
            weapons=[
                WeaponBlueprint(
                    name="W1",
                    type="LASER",
                    title="W1",
                    desc="W1",
                    cooldown=10,
                    power=2,
                    cost=50,
                ),
            ],
            events=[
                EventBlueprint(
                    name="E1",
                    text="Event 1",
                    choices=[],
                ),
            ],
        )

        assert len(content.weapons) == 1
        assert len(content.events) == 1
