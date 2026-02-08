"""Tests for data extraction and balance range derivation."""

from pathlib import Path
from textwrap import dedent

import pytest

from ftl_gen.data import loader
from ftl_gen.data.extractor import extract_vanilla_data, write_vanilla_reference


@pytest.fixture(autouse=True)
def _clear_caches():
    """Clear loader caches before each test."""
    loader._VANILLA_DATA = None
    loader._BALANCE_RANGES = None
    loader._GENERATION_RANGES = None
    yield
    loader._VANILLA_DATA = None
    loader._BALANCE_RANGES = None
    loader._GENERATION_RANGES = None


class TestDeriveBalanceRanges:
    """Tests for derive_balance_ranges() using real vanilla data."""

    def test_returns_all_categories(self):
        ranges = loader.derive_balance_ranges()
        assert "weapon" in ranges
        assert "drone" in ranges
        assert "augment" in ranges
        assert "crew" in ranges

    def test_weapon_ranges_reasonable(self):
        ranges = loader.derive_balance_ranges()
        wr = ranges["weapon"]

        # Damage: vanilla ranges from 0 (some special) to ~4 for normal weapons
        lo, hi = wr["damage"]
        assert lo >= 0
        assert hi >= 1

        # Cooldown: should be at least 1
        lo, hi = wr["cooldown"]
        assert lo >= 1
        assert hi > lo

        # Power: 1-4 for most weapons
        lo, hi = wr["power"]
        assert lo >= 1
        assert hi >= 2

        # Cost: some vanilla weapons have cost=0 (enemy-only excluded, but
        # some player-accessible weapons have low cost)
        lo, hi = wr["cost"]
        assert lo >= 0
        assert hi > lo

    def test_drone_ranges_reasonable(self):
        ranges = loader.derive_balance_ranges()
        dr = ranges["drone"]

        lo, hi = dr["power"]
        assert lo >= 1
        assert hi >= 2

        lo, hi = dr["cost"]
        assert lo >= 10

    def test_augment_ranges_reasonable(self):
        ranges = loader.derive_balance_ranges()
        ar = ranges["augment"]

        lo, hi = ar["cost"]
        assert lo >= 10
        assert hi > lo

    def test_crew_ranges_reasonable(self):
        ranges = loader.derive_balance_ranges()
        cr = ranges["crew"]

        lo, hi = cr["maxHealth"]
        assert lo >= 25
        assert hi >= 100

        lo, hi = cr["moveSpeed"]
        assert lo >= 25
        assert hi >= 100

    def test_ranges_are_cached(self):
        r1 = loader.derive_balance_ranges()
        r2 = loader.derive_balance_ranges()
        assert r1 is r2


class TestGetGenerationRanges:
    """Tests for get_generation_ranges() padding."""

    def test_generation_ranges_wider_than_balance(self):
        balance = loader.derive_balance_ranges()
        generation = loader.get_generation_ranges()

        for category in balance:
            for stat in balance[category]:
                b_lo, b_hi = balance[category][stat]
                g_lo, g_hi = generation[category][stat]
                # Generation hi should always be >= balance hi (padded up)
                assert g_hi >= b_hi, f"{category}.{stat} gen_hi {g_hi} < bal_hi {b_hi}"
                # Generation lo should be <= balance lo, BUT get_generation_ranges
                # clamps lo to 0, so if b_lo is negative, g_lo=0 is expected
                if b_lo >= 0:
                    assert g_lo <= b_lo, f"{category}.{stat} gen_lo {g_lo} > bal_lo {b_lo}"

    def test_generation_ranges_no_negative(self):
        generation = loader.get_generation_ranges()
        for category, ranges in generation.items():
            for stat, (lo, hi) in ranges.items():
                assert lo >= 0, f"{category}.{stat} has negative lo: {lo}"


class TestExtractor:
    """Tests for extract_vanilla_data() with a small XML fixture."""

    @pytest.fixture
    def fixture_dir(self, tmp_path):
        data_dir = tmp_path / "data"
        data_dir.mkdir()

        blueprints = dedent("""\
            <?xml version="1.0" encoding="utf-8"?>
            <FTL>
              <weaponBlueprint name="TEST_LASER">
                <type>LASER</type>
                <title>Test Laser</title>
                <damage>2</damage>
                <shots>3</shots>
                <cooldown>10</cooldown>
                <power>2</power>
                <cost>50</cost>
                <rarity>2</rarity>
                <sp>0</sp>
                <fireChance>1</fireChance>
                <breachChance>0</breachChance>
              </weaponBlueprint>

              <weaponBlueprint name="ENEMY_ONLY" NOLOC="1">
                <type>LASER</type>
                <damage>99</damage>
                <cooldown>5</cooldown>
                <power>1</power>
                <cost>10</cost>
              </weaponBlueprint>

              <weaponBlueprint name="TEST_ION">
                <type>LASER</type>
                <damage>0</damage>
                <ion>1</ion>
                <cooldown>8</cooldown>
                <power>1</power>
                <cost>30</cost>
              </weaponBlueprint>

              <droneBlueprint name="TEST_DRONE">
                <type>COMBAT</type>
                <power>2</power>
                <cost>40</cost>
                <rarity>2</rarity>
              </droneBlueprint>

              <augBlueprint name="TEST_AUG">
                <cost>60</cost>
                <rarity>3</rarity>
                <value>1.f</value>
                <stackable>false</stackable>
              </augBlueprint>

              <crewBlueprint name="human">
                <cost>45</cost>
                <rarity>0</rarity>
              </crewBlueprint>

              <shipBlueprint name="PLAYER_SHIP_TEST" layout="test_layout" img="test_img">
                <weaponSlots>4</weaponSlots>
                <droneSlots>2</droneSlots>
                <health amount="30"/>
                <maxPower amount="8"/>
                <weaponList missiles="6" count="2">
                  <weapon name="TEST_LASER"/>
                  <weapon name="TEST_ION"/>
                </weaponList>
                <aug name="TEST_AUG"/>
                <crewCount amount="3" class="human"/>
              </shipBlueprint>

              <blueprintList name="WEAPONS_TEST">
                <name>TEST_LASER</name>
                <name>TEST_ION</name>
              </blueprintList>
            </FTL>
        """)
        (data_dir / "blueprints.xml").write_text(blueprints)
        return tmp_path

    def test_extract_weapons(self, fixture_dir):
        data = extract_vanilla_data(fixture_dir)

        assert "TEST_LASER" in data["weapons"]
        w = data["weapons"]["TEST_LASER"]
        assert w["type"] == "LASER"
        assert w["damage"] == 2
        assert w["shots"] == 3
        assert w["cooldown"] == 10.0
        assert w["power"] == 2
        assert w["cost"] == 50

    def test_extract_noloc_flag(self, fixture_dir):
        data = extract_vanilla_data(fixture_dir)

        assert "ENEMY_ONLY" in data["weapons"]
        assert data["weapons"]["ENEMY_ONLY"].get("noloc") is True

    def test_extract_ion_classification(self, fixture_dir):
        data = extract_vanilla_data(fixture_dir)

        # ION weapon: vanilla uses LASER + <ion> tag, extractor reclassifies as ION
        assert data["weapons"]["TEST_ION"]["type"] == "ION"
        assert data["weapons"]["TEST_ION"]["ion"] == 1

    def test_extract_drone(self, fixture_dir):
        data = extract_vanilla_data(fixture_dir)

        assert "TEST_DRONE" in data["drones"]
        d = data["drones"]["TEST_DRONE"]
        assert d["type"] == "COMBAT"
        assert d["power"] == 2
        assert d["cost"] == 40

    def test_extract_augment_with_float_notation(self, fixture_dir):
        data = extract_vanilla_data(fixture_dir)

        assert "TEST_AUG" in data["augments"]
        a = data["augments"]["TEST_AUG"]
        assert a["cost"] == 60
        assert a["value"] == 1.0  # Parsed from "1.f"
        assert a["stackable"] is False

    def test_extract_crew_merges_engine_stats(self, fixture_dir):
        data = extract_vanilla_data(fixture_dir)

        assert "human" in data["crew"]
        c = data["crew"]["human"]
        # XML-extracted
        assert c["cost"] == 45
        # Merged engine stats
        assert c["maxHealth"] == 100
        assert c["moveSpeed"] == 100

    def test_extract_ship(self, fixture_dir):
        data = extract_vanilla_data(fixture_dir)

        assert "PLAYER_SHIP_TEST" in data["ships"]
        s = data["ships"]["PLAYER_SHIP_TEST"]
        assert s["layout"] == "test_layout"
        assert s["weaponSlots"] == 4
        assert s["droneSlots"] == 2
        assert s["maxPower"] == 8
        assert s["weapons"] == ["TEST_LASER", "TEST_ION"]
        assert s["augments"] == ["TEST_AUG"]

    def test_extract_blueprint_lists(self, fixture_dir):
        data = extract_vanilla_data(fixture_dir)

        assert "WEAPONS_TEST" in data["blueprint_lists"]
        assert data["blueprint_lists"]["WEAPONS_TEST"] == ["TEST_LASER", "TEST_ION"]

    def test_write_and_reload(self, fixture_dir, tmp_path):
        data = extract_vanilla_data(fixture_dir)
        out = tmp_path / "test_ref.json"
        write_vanilla_reference(data, out)

        assert out.exists()
        import json
        with open(out) as f:
            reloaded = json.load(f)
        assert reloaded["weapons"]["TEST_LASER"]["damage"] == 2

    def test_missing_source_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            extract_vanilla_data(tmp_path / "nonexistent")
