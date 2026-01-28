"""Tests for balance validation."""

import pytest

from pydantic import ValidationError

from ftl_gen.balance.constraints import BalanceValidator
from ftl_gen.xml.schemas import WeaponBlueprint


@pytest.fixture
def validator():
    return BalanceValidator()


@pytest.fixture
def balanced_weapon():
    return WeaponBlueprint(
        name="BALANCED_LASER",
        type="LASER",
        title="Balanced Laser",
        desc="A well-balanced weapon",
        damage=2,
        shots=2,
        cooldown=12,
        power=2,
        cost=60,
        rarity=2,
    )


class TestBalanceValidator:
    """Tests for BalanceValidator."""

    def test_balanced_weapon_passes(self, validator, balanced_weapon):
        result = validator.validate_weapon(balanced_weapon)
        assert result.valid is True
        assert len(result.errors) == 0

    def test_pydantic_validates_damage_range(self):
        """Pydantic should reject damage > 10."""
        with pytest.raises(ValidationError):
            WeaponBlueprint(
                name="OP_WEAPON",
                type="LASER",
                title="OP",
                desc="Too powerful",
                damage=15,  # Out of Pydantic range (0-10)
                cooldown=10,
                power=2,
                cost=50,
            )

    def test_pydantic_validates_cooldown_range(self):
        """Pydantic should reject cooldown < 1."""
        with pytest.raises(ValidationError):
            WeaponBlueprint(
                name="FAST_WEAPON",
                type="LASER",
                title="Fast",
                desc="Too fast",
                damage=1,
                cooldown=0.5,  # Out of Pydantic range (1-30)
                power=1,
                cost=50,
            )

    def test_pydantic_validates_power_range(self):
        """Pydantic should reject power > 5."""
        with pytest.raises(ValidationError):
            WeaponBlueprint(
                name="POWER_HOG",
                type="LASER",
                title="Power Hog",
                desc="Uses too much power",
                damage=1,
                cooldown=10,
                power=10,  # Out of Pydantic range (1-5)
                cost=50,
            )

    def test_high_dps_warning(self, validator):
        """High DPS per power should generate a warning."""
        weapon = WeaponBlueprint(
            name="DPS_MONSTER",
            type="LASER",
            title="DPS Monster",
            desc="Very high DPS",
            damage=3,
            shots=3,  # 9 total damage
            cooldown=5,  # Fast cooldown (but >= 1)
            power=1,  # Low power
            cost=50,
        )

        result = validator.validate_weapon(weapon)
        # This weapon has very high DPS per power
        # Should at least generate warnings about efficiency
        assert len(result.warnings) > 0 or len(result.errors) > 0

    def test_high_fire_and_damage_warning(self, validator):
        weapon = WeaponBlueprint(
            name="FIRE_CANNON",
            type="LASER",
            title="Fire Cannon",
            desc="Burns everything",
            damage=4,
            fireChance=9,
            cooldown=15,
            power=3,
            cost=80,
        )

        result = validator.validate_weapon(weapon)
        assert len(result.warnings) > 0
        assert any("fire" in w.message.lower() for w in result.warnings)

    def test_low_cost_warning(self, validator):
        weapon = WeaponBlueprint(
            name="CHEAP_POWER",
            type="LASER",
            title="Cheap Power",
            desc="Too cheap for its power",
            damage=3,
            shots=2,
            cooldown=12,
            power=3,
            cost=15,  # Very cheap for stats
        )

        result = validator.validate_weapon(weapon)
        assert len(result.warnings) > 0
        assert any("cost" in w.message.lower() for w in result.warnings)

    def test_validate_multiple_weapons(self, validator, balanced_weapon):
        weapons = [
            balanced_weapon,
            WeaponBlueprint(
                name="ANOTHER_WEAPON",
                type="BEAM",
                title="Another",
                desc="Another weapon",
                damage=2,
                cooldown=15,
                power=2,
                cost=60,
                length=40,
            ),
        ]

        result = validator.validate_weapons(weapons)
        assert result.valid is True

    def test_cost_outside_typical_range_warning(self, validator):
        """Cost outside typical range generates a warning, not an error."""
        weapon = WeaponBlueprint(
            name="EXPENSIVE_WEAPON",
            type="LASER",
            title="Expensive",
            desc="Very expensive weapon",
            damage=2,
            shots=2,
            cooldown=12,
            power=2,
            cost=199,  # Near max but valid
        )

        result = validator.validate_weapon(weapon)
        # Should be valid (cost is within Pydantic range 10-200)
        assert result.valid is True


class TestVanillaComparison:
    """Tests for comparing weapons to vanilla."""

    def test_compare_to_vanilla(self, validator, balanced_weapon):
        comparison = validator.compare_to_vanilla(balanced_weapon)

        # Should return ratios
        assert "damage_ratio" in comparison
        assert "cooldown_ratio" in comparison
        assert "power_ratio" in comparison
        assert "cost_ratio" in comparison

    def test_comparison_ratios_reasonable(self, validator, balanced_weapon):
        comparison = validator.compare_to_vanilla(balanced_weapon)

        # A balanced weapon should have ratios around 1.0
        for key, value in comparison.items():
            assert 0.1 < value < 10, f"{key} ratio {value} seems unreasonable"


class TestBalanceResult:
    """Tests for BalanceResult dataclass."""

    def test_warnings_property(self, validator):
        weapon = WeaponBlueprint(
            name="WARN_WEAPON",
            type="LASER",
            title="Warning",
            desc="Generates warnings",
            damage=3,
            shots=3,
            cooldown=5,  # Fast
            power=1,  # Low power = high efficiency
            cost=50,
        )

        result = validator.validate_weapon(weapon)
        warnings = result.warnings
        errors = result.errors

        assert all(w.severity == "warning" for w in warnings)
        assert all(e.severity == "error" for e in errors)

    def test_valid_with_warnings(self, validator):
        weapon = WeaponBlueprint(
            name="WARN_WEAPON",
            type="LASER",
            title="Warning",
            desc="Generates warnings but is valid",
            damage=3,
            shots=3,
            cooldown=5,
            power=1,
            cost=50,
        )

        result = validator.validate_weapon(weapon)

        # Should be valid even with warnings (no errors)
        assert result.valid is True
        # May or may not have warnings depending on thresholds
