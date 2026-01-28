"""Tests for mod builder and packaging."""

import zipfile
from pathlib import Path

import pytest

from ftl_gen.core.mod_builder import ModBuilder
from ftl_gen.xml.schemas import (
    EventBlueprint,
    EventChoice,
    EventOutcome,
    ModContent,
    ModMetadata,
    WeaponBlueprint,
)


@pytest.fixture
def temp_output(tmp_path):
    """Create temporary output directory."""
    return tmp_path / "output"


@pytest.fixture
def sample_content():
    """Create sample mod content."""
    return ModContent(
        metadata=ModMetadata(
            name="TestMod",
            description="A test mod",
            author="Test Author",
            version="1.0.0",
        ),
        weapons=[
            WeaponBlueprint(
                name="TEST_LASER",
                type="LASER",
                title="Test Laser",
                desc="A test weapon",
                damage=2,
                shots=2,
                cooldown=10,
                power=2,
                cost=50,
            ),
        ],
        events=[
            EventBlueprint(
                name="TEST_EVENT",
                text="A test event",
                choices=[
                    EventChoice(
                        text="Accept",
                        event=EventOutcome(text="Success", scrap=25),
                    ),
                ],
            ),
        ],
    )


class TestModBuilder:
    """Tests for ModBuilder."""

    def test_build_creates_ftl_file(self, temp_output, sample_content):
        builder = ModBuilder(temp_output)
        ftl_path = builder.build(sample_content)

        assert ftl_path.exists()
        assert ftl_path.suffix == ".ftl"

    def test_ftl_is_valid_zip(self, temp_output, sample_content):
        builder = ModBuilder(temp_output)
        ftl_path = builder.build(sample_content)

        assert zipfile.is_zipfile(ftl_path)

    def test_ftl_contains_required_files(self, temp_output, sample_content):
        builder = ModBuilder(temp_output)
        ftl_path = builder.build(sample_content)

        with zipfile.ZipFile(ftl_path, "r") as zf:
            names = zf.namelist()

            # Check for data directory
            assert any("data/" in n for n in names)

            # Check for blueprints
            assert any("blueprints.xml.append" in n for n in names)

            # Check for events
            assert any("events.xml.append" in n for n in names)

            # Check for metadata
            assert any("mod-appendix/metadata.xml" in n for n in names)

    def test_ftl_contains_animations(self, temp_output, sample_content):
        builder = ModBuilder(temp_output)
        ftl_path = builder.build(sample_content)

        with zipfile.ZipFile(ftl_path, "r") as zf:
            names = zf.namelist()

            # Check for animations (since we have weapons)
            assert any("animations.xml.append" in n for n in names)

    def test_build_with_sprites(self, temp_output, sample_content):
        builder = ModBuilder(temp_output)
        sprite_files = {
            "test_laser_strip12.png": b"PNG_DATA_HERE",
        }
        ftl_path = builder.build(sample_content, sprite_files)

        with zipfile.ZipFile(ftl_path, "r") as zf:
            names = zf.namelist()

            # Check for sprite files
            assert any("img/weapons/test_laser_strip12.png" in n for n in names)

    def test_build_creates_mod_directory(self, temp_output, sample_content):
        builder = ModBuilder(temp_output)
        builder.build(sample_content)

        mod_dir = temp_output / "TestMod"
        assert mod_dir.exists()
        assert (mod_dir / "data").exists()
        assert (mod_dir / "img" / "weapons").exists()
        assert (mod_dir / "mod-appendix").exists()

    def test_sanitize_name(self, temp_output):
        builder = ModBuilder(temp_output)

        assert builder._sanitize_name("Test Mod") == "Test Mod"
        assert builder._sanitize_name("Test/Mod") == "TestMod"
        assert builder._sanitize_name("Test:Mod") == "TestMod"
        assert builder._sanitize_name("Test<Mod>") == "TestMod"

    def test_build_from_files(self, temp_output):
        builder = ModBuilder(temp_output)

        blueprints_xml = """<FTL>
<weaponBlueprint name="SIMPLE_LASER">
    <type>LASER</type>
    <title>Simple Laser</title>
    <desc>A simple weapon</desc>
    <damage>1</damage>
    <shots>1</shots>
    <cooldown>10</cooldown>
    <power>1</power>
    <cost>30</cost>
</weaponBlueprint>
</FTL>"""

        ftl_path = builder.build_from_files(
            mod_name="SimpleMod",
            blueprints_xml=blueprints_xml,
        )

        assert ftl_path.exists()
        with zipfile.ZipFile(ftl_path, "r") as zf:
            names = zf.namelist()
            assert any("blueprints.xml.append" in n for n in names)

    def test_overwrites_existing_mod(self, temp_output, sample_content):
        builder = ModBuilder(temp_output)

        # Build twice
        ftl_path1 = builder.build(sample_content)
        ftl_path2 = builder.build(sample_content)

        assert ftl_path1 == ftl_path2
        assert ftl_path2.exists()

    def test_custom_output_name(self, temp_output, sample_content):
        builder = ModBuilder(temp_output)
        ftl_path = builder.build(sample_content, output_name="CustomName")

        assert ftl_path.name == "CustomName.ftl"


class TestModBuilderXMLContent:
    """Tests for XML content in built mods."""

    def test_blueprints_xml_valid(self, temp_output, sample_content):
        from lxml import etree

        builder = ModBuilder(temp_output)
        ftl_path = builder.build(sample_content)

        with zipfile.ZipFile(ftl_path, "r") as zf:
            for name in zf.namelist():
                if "blueprints.xml.append" in name:
                    content = zf.read(name).decode("utf-8")
                    # Should not raise
                    root = etree.fromstring(content.encode())
                    assert root.tag == "FTL"
                    assert root.find(".//weaponBlueprint") is not None

    def test_events_xml_valid(self, temp_output, sample_content):
        from lxml import etree

        builder = ModBuilder(temp_output)
        ftl_path = builder.build(sample_content)

        with zipfile.ZipFile(ftl_path, "r") as zf:
            for name in zf.namelist():
                if "events.xml.append" in name:
                    content = zf.read(name).decode("utf-8")
                    # Should not raise
                    root = etree.fromstring(content.encode())
                    assert root.tag == "FTL"
                    assert root.find(".//event") is not None

    def test_metadata_xml_valid(self, temp_output, sample_content):
        from lxml import etree

        builder = ModBuilder(temp_output)
        ftl_path = builder.build(sample_content)

        with zipfile.ZipFile(ftl_path, "r") as zf:
            for name in zf.namelist():
                if "metadata.xml" in name:
                    content = zf.read(name).decode("utf-8")
                    root = etree.fromstring(content.encode())
                    assert root.tag == "metadata"
                    assert root.find("title").text == "TestMod"
