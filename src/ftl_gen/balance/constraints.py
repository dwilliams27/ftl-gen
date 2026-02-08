"""Balance validation for FTL mod content."""

from dataclasses import dataclass, field

from ftl_gen.constants import get_balance_ranges
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
    """Validates mod content against balance constraints derived from vanilla data."""

    # Max damage per second per power before flagging as OP
    MAX_DPS_THRESHOLD = 1.5
    # Max total damage per power bar before flagging as OP
    MAX_EFFICIENCY = 3.0

    def __init__(self):
        self._vanilla_data = load_vanilla_reference()
        ranges = get_balance_ranges()
        self._wr = ranges["weapon"]

    def validate_weapon(self, weapon: WeaponBlueprint) -> BalanceResult:
        """Validate a weapon against balance constraints."""
        issues = []

        # Check stat ranges (derived from vanilla data)
        for stat, attr in [
            ("damage", weapon.damage),
            ("cooldown", weapon.cooldown),
            ("power", weapon.power),
        ]:
            lo, hi = self._wr.get(stat, (0, 999))
            if not lo <= attr <= hi:
                issues.append(BalanceIssue(
                    severity="error",
                    item_name=weapon.name,
                    message=f"{stat.title()} {attr} outside vanilla range ({lo}, {hi})"
                ))

        # Cost is a warning, not error
        lo, hi = self._wr.get("cost", (0, 999))
        if not lo <= weapon.cost <= hi:
            issues.append(BalanceIssue(
                severity="warning",
                item_name=weapon.name,
                message=f"Cost {weapon.cost} outside typical range ({lo}, {hi})"
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

        # Flat dict: filter by type
        same_type = [
            w for w in vanilla_weapons.values()
            if w.get("type") == weapon.type and not w.get("noloc")
        ]

        if not same_type:
            return {}

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
