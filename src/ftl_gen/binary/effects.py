"""Augment effect mapping: custom augment names → vanilla mechanical effects.

Since FTL's augment effects are hardcoded in the binary (keyed by name string),
custom augment names have no mechanical effect. This module maps custom names
to vanilla names via binary patching, so custom augments inherit vanilla effects.

Usage:
    mapper = AugmentEffectMapper()
    suggestion = mapper.suggest_mapping("Bonus scrap from battles")
    # → "SCRAP_COLLECTOR"
    spec = mapper.build_patch_spec(mappings, binary_info, binary_data)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from ftl_gen.binary.patcher import PatchSpec
from ftl_gen.binary.recon import BinaryInfo
from ftl_gen.binary.trampoline import AugmentMapping, TrampolineBuilder

logger = logging.getLogger(__name__)

# Complete catalog of vanilla augment effects.
# Keys are the blueprint name strings used by HasAugmentation/GetAugmentationValue.
# Values describe what the augment does mechanically.
VANILLA_EFFECTS: dict[str, str] = {
    "ADV_SCANNERS": "Reveal map layout (stores, hazards, fleet) at unexplored beacons",
    "AUTO_COOLDOWN": "10% faster weapon charge speed",
    "BACKUP_DNA": "Clone crew members on death (requires clone bay)",
    "BATTERY_BOOSTER": "Backup battery provides +2 power instead of +1",
    "CLOAK_FIRE": "Weapons can charge while cloaked",
    "CREW_STIMS": "Crew move 25% faster in combat",
    "CRYSTAL_SHARDS": "Random chance to fire crystal projectile at enemies",
    "DEFENSE_SCRAMBLER": "Enemy defense drones cannot target your projectiles",
    "DRONE_RECOVERY": "Recover drones when jumping (chance to not consume drone part)",
    "DRONE_SPEED": "Combat/defense drones move 25% faster",
    "ENERGY_SHIELD": "Zoltan energy shield (absorbs damage until depleted)",
    "EXPLOSIVE_REPLICATOR": "Chance to not consume a missile when firing missile weapons",
    "FIRE_EXTINGUISHERS": "Fires spread slower and are extinguished faster",
    "FLEET_DISTRACTION": "Fleet pursuit delayed by 1 jump",
    "FTL_BOOSTER": "FTL charge speed increased by 25%",
    "FTL_JAMMER": "Enemy FTL charge speed reduced by 50%",
    "FTL_JUMPER": "Can jump to any beacon in range (ignores nebula pathing)",
    "HACKING_STUN": "Hacked systems stun adjacent crew",
    "ION_ARMOR": "15% chance to negate ion damage",
    "LIFE_SCANNER": "Reveal enemy crew positions and count",
    "LONG_RANGED_SCANNERS": "Reveal map info (hazards, ships) at adjacent beacons",
    "NANO_MEDBAY": "Slowly heal all crew regardless of location",
    "O2_MASKS": "Crew take no suffocation damage",
    "REPAIR_ARM": "Gain hull repair points after winning fights (at cost of some scrap)",
    "ROCK_ARMOR": "All crew take 50% less damage from combat",
    "SCRAP_COLLECTOR": "Bonus scrap from all encounters (+10% base)",
    "SHIELD_RECHARGE": "Shield recharge speed increased by 15%",
    "SLUG_GEL": "Reveal adjacent rooms even without sensors",
    "STASIS_POD": "Chance to recruit defeated enemy crew",
    "SYSTEM_CASING": "15% chance to negate system damage from weapons",
    "TELEPORT_HEAL": "Crew are healed when teleported back to ship",
    "WEAPON_PREIGNITE": "All weapons start fully charged at battle start",
    "ZOLTAN_BYPASS": "Bypass Zoltan energy shields with teleporter and hacking",
}

# Keyword → augment mapping for suggestion engine
_KEYWORD_MAP: dict[str, str] = {
    "scrap": "SCRAP_COLLECTOR",
    "bonus scrap": "SCRAP_COLLECTOR",
    "extra scrap": "SCRAP_COLLECTOR",
    "missile": "EXPLOSIVE_REPLICATOR",
    "ammo": "EXPLOSIVE_REPLICATOR",
    "replicator": "EXPLOSIVE_REPLICATOR",
    "scanner": "LONG_RANGED_SCANNERS",
    "scan": "LONG_RANGED_SCANNERS",
    "map": "LONG_RANGED_SCANNERS",
    "reveal": "LONG_RANGED_SCANNERS",
    "weapon charge": "AUTO_COOLDOWN",
    "charge speed": "AUTO_COOLDOWN",
    "cooldown": "AUTO_COOLDOWN",
    "faster weapon": "AUTO_COOLDOWN",
    "repair": "REPAIR_ARM",
    "hull repair": "REPAIR_ARM",
    "auto repair": "REPAIR_ARM",
    "shield": "SHIELD_RECHARGE",
    "shield recharge": "SHIELD_RECHARGE",
    "drone recovery": "DRONE_RECOVERY",
    "recover drone": "DRONE_RECOVERY",
    "drone speed": "DRONE_SPEED",
    "ftl speed": "FTL_BOOSTER",
    "ftl boost": "FTL_BOOSTER",
    "jump speed": "FTL_BOOSTER",
    "ftl charge": "FTL_BOOSTER",
    "cloak": "CLOAK_FIRE",
    "fire while cloak": "CLOAK_FIRE",
    "preignite": "WEAPON_PREIGNITE",
    "pre-ignite": "WEAPON_PREIGNITE",
    "pre ignite": "WEAPON_PREIGNITE",
    "start charged": "WEAPON_PREIGNITE",
    "crystal": "CRYSTAL_SHARDS",
    "shard": "CRYSTAL_SHARDS",
    "defense scramble": "DEFENSE_SCRAMBLER",
    "scramble": "DEFENSE_SCRAMBLER",
    "anti-drone": "DEFENSE_SCRAMBLER",
    "fire extinguish": "FIRE_EXTINGUISHERS",
    "fire resist": "FIRE_EXTINGUISHERS",
    "oxygen": "O2_MASKS",
    "suffocate": "O2_MASKS",
    "o2": "O2_MASKS",
    "heal": "NANO_MEDBAY",
    "nano": "NANO_MEDBAY",
    "medbay": "NANO_MEDBAY",
    "clone": "BACKUP_DNA",
    "dna": "BACKUP_DNA",
    "backup": "BACKUP_DNA",
    "teleport": "TELEPORT_HEAL",
    "zoltan": "ZOLTAN_BYPASS",
    "bypass": "ZOLTAN_BYPASS",
    "energy shield": "ENERGY_SHIELD",
    "ion": "ION_ARMOR",
    "ion resist": "ION_ARMOR",
    "system protect": "SYSTEM_CASING",
    "system casing": "SYSTEM_CASING",
    "armor": "ROCK_ARMOR",
    "crew damage": "ROCK_ARMOR",
    "crew speed": "CREW_STIMS",
    "stim": "CREW_STIMS",
    "fleet": "FLEET_DISTRACTION",
    "pursuit": "FLEET_DISTRACTION",
    "hack": "HACKING_STUN",
    "stun": "HACKING_STUN",
    "battery": "BATTERY_BOOSTER",
    "power": "BATTERY_BOOSTER",
    "slug": "SLUG_GEL",
    "sensor": "LIFE_SCANNER",
    "life scan": "LIFE_SCANNER",
    "crew detect": "LIFE_SCANNER",
    "stasis": "STASIS_POD",
    "recruit": "STASIS_POD",
    "capture": "STASIS_POD",
    "ftl jam": "FTL_JAMMER",
    "slow ftl": "FTL_JAMMER",
    "enemy ftl": "FTL_JAMMER",
    "any beacon": "FTL_JUMPER",
    "free jump": "FTL_JUMPER",
}


class AugmentEffectMapper:
    """Maps custom augment descriptions to vanilla augment effects."""

    def suggest_mapping(self, augment_desc: str) -> str | None:
        """Suggest a vanilla augment whose effect matches the description.

        Uses keyword matching against augment description text.
        Returns the vanilla augment name, or None if no match found.
        """
        desc_lower = augment_desc.lower()

        # Try longer keywords first (more specific matches)
        for keyword in sorted(_KEYWORD_MAP, key=len, reverse=True):
            if keyword in desc_lower:
                return _KEYWORD_MAP[keyword]

        return None

    def suggest_mapping_for_name(self, augment_name: str) -> str | None:
        """Suggest based on the augment's blueprint name.

        Checks if the name contains vanilla augment substrings.
        """
        name_upper = augment_name.upper()

        for vanilla_name in VANILLA_EFFECTS:
            if vanilla_name in name_upper:
                return vanilla_name

        return None

    def build_patch_spec(
        self,
        mappings: list[AugmentMapping],
        binary_info: BinaryInfo,
        binary_data: bytes,
    ) -> PatchSpec:
        """Build a PatchSpec for the given augment mappings.

        Delegates to TrampolineBuilder for the actual x86_64 code generation.
        """
        builder = TrampolineBuilder(binary_info)
        return builder.build(mappings, binary_data)

    @staticmethod
    def get_vanilla_effects() -> dict[str, str]:
        """Return the full catalog of vanilla augment effects."""
        return dict(VANILLA_EFFECTS)

    @staticmethod
    def get_vanilla_effect(name: str) -> str | None:
        """Get the description of a vanilla augment's effect."""
        return VANILLA_EFFECTS.get(name)
