"""Balance validation for FTL mod content."""

from dataclasses import dataclass, field

from ftl_gen.constants import BALANCE_RANGES
from ftl_gen.data.loader import load_vanilla_reference
from ftl_gen.xml.schemas import WeaponBlueprint


@dataclass
class BalanceIssue:
    """A balance issue found during validation."""

    severity: str  # "warning" or "error"
    item_name: str
    message: str


@dataclass
class BalanceResult:
    """Result of balance validation."""

    valid: bool
    issues: list[BalanceIssue] = field(default_factory=list)

    @property
    def warnings(self) -> list[BalanceIssue]:
        return [i for i in self.issues if i.severity == "warning"]

    @property
    def errors(self) -> list[BalanceIssue]:
        return [i for i in self.issues if i.severity == "error"]


class BalanceValidator:
    """Validates mod content against balance constraints."""

    DAMAGE_RANGE = BALANCE_RANGES["weapon"]["damage"]
    COOLDOWN_RANGE = BALANCE_RANGES["weapon"]["cooldown"]
    POWER_RANGE = BALANCE_RANGES["weapon"]["power"]
    COST_RANGE = BALANCE_RANGES["weapon"]["cost"]
    SHOTS_RANGE = BALANCE_RANGES["weapon"]["shots"]

    # Max damage per second per power before flagging as OP
    MAX_DPS_THRESHOLD = 1.5
    # Max total damage per power bar before flagging as OP
    MAX_EFFICIENCY = 3.0

    def __init__(self):
        self._vanilla_data = load_vanilla_reference()

    def validate_weapon(self, weapon: WeaponBlueprint) -> BalanceResult:
        """Validate a weapon against balance constraints."""
        issues = []

        # Check stat ranges
        if not self.DAMAGE_RANGE[0] <= weapon.damage <= self.DAMAGE_RANGE[1]:
            issues.append(BalanceIssue(
                severity="error",
                item_name=weapon.name,
                message=f"Damage {weapon.damage} outside valid range {self.DAMAGE_RANGE}"
            ))

        if not self.COOLDOWN_RANGE[0] <= weapon.cooldown <= self.COOLDOWN_RANGE[1]:
            issues.append(BalanceIssue(
                severity="error",
                item_name=weapon.name,
                message=f"Cooldown {weapon.cooldown} outside valid range {self.COOLDOWN_RANGE}"
            ))

        if not self.POWER_RANGE[0] <= weapon.power <= self.POWER_RANGE[1]:
            issues.append(BalanceIssue(
                severity="error",
                item_name=weapon.name,
                message=f"Power {weapon.power} outside valid range {self.POWER_RANGE}"
            ))

        if not self.COST_RANGE[0] <= weapon.cost <= self.COST_RANGE[1]:
            issues.append(BalanceIssue(
                severity="warning",
                item_name=weapon.name,
                message=f"Cost {weapon.cost} outside typical range {self.COST_RANGE}"
            ))

        # Check balance metrics
        if weapon.power > 0:
            # DPS per power
            total_damage = weapon.damage * weapon.shots
            dps = total_damage / weapon.cooldown
            dps_per_power = dps / weapon.power

            if dps_per_power > self.MAX_DPS_THRESHOLD:
                issues.append(BalanceIssue(
                    severity="warning",
                    item_name=weapon.name,
                    message=f"DPS per power ({dps_per_power:.2f}) exceeds threshold ({self.MAX_DPS_THRESHOLD})"
                ))

            # Damage efficiency
            efficiency = total_damage / weapon.power
            if efficiency > self.MAX_EFFICIENCY:
                issues.append(BalanceIssue(
                    severity="warning",
                    item_name=weapon.name,
                    message=f"Damage per power ({efficiency:.1f}) exceeds threshold ({self.MAX_EFFICIENCY})"
                ))

        # Check for overpowered combinations
        if weapon.fire_chance >= 8 and weapon.damage >= 3:
            issues.append(BalanceIssue(
                severity="warning",
                item_name=weapon.name,
                message="High fire chance combined with high damage may be overpowered"
            ))

        if weapon.breach_chance >= 8 and weapon.damage >= 3:
            issues.append(BalanceIssue(
                severity="warning",
                item_name=weapon.name,
                message="High breach chance combined with high damage may be overpowered"
            ))

        # Check cost is appropriate for power
        expected_min_cost = weapon.power * 15 + weapon.damage * 10
        if weapon.cost < expected_min_cost * 0.5:
            issues.append(BalanceIssue(
                severity="warning",
                item_name=weapon.name,
                message=f"Cost {weapon.cost} seems low for weapon stats (expected ~{expected_min_cost}+)"
            ))

        valid = not any(i.severity == "error" for i in issues)
        return BalanceResult(valid=valid, issues=issues)

    def validate_weapons(self, weapons: list[WeaponBlueprint]) -> BalanceResult:
        """Validate a list of weapons."""
        all_issues = []

        for weapon in weapons:
            result = self.validate_weapon(weapon)
            all_issues.extend(result.issues)

        valid = not any(i.severity == "error" for i in all_issues)
        return BalanceResult(valid=valid, issues=all_issues)

    def compare_to_vanilla(self, weapon: WeaponBlueprint) -> dict[str, float]:
        """Compare a weapon to vanilla weapons of the same type.

        Returns a dict with comparison metrics (1.0 = same as average).
        """
        vanilla_weapons = self._vanilla_data.get("weapons", {})

        # Find weapons of same type
        same_type = []
        type_category = weapon.type.lower() + "s"  # e.g., "lasers"
        if type_category in vanilla_weapons:
            same_type = list(vanilla_weapons[type_category].values())

        if not same_type:
            return {}

        # Calculate averages
        avg_damage = sum(w.get("damage", 0) for w in same_type) / len(same_type)
        avg_cooldown = sum(w.get("cooldown", 10) for w in same_type) / len(same_type)
        avg_power = sum(w.get("power", 2) for w in same_type) / len(same_type)
        avg_cost = sum(w.get("cost", 50) for w in same_type) / len(same_type)

        return {
            "damage_ratio": weapon.damage / avg_damage if avg_damage > 0 else 1.0,
            "cooldown_ratio": avg_cooldown / weapon.cooldown if weapon.cooldown > 0 else 1.0,
            "power_ratio": weapon.power / avg_power if avg_power > 0 else 1.0,
            "cost_ratio": weapon.cost / avg_cost if avg_cost > 0 else 1.0,
        }
