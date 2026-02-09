# Phase 4: Augment Name Remap (The Trampoline)

**Goal**: Based on Phase 2 findings, build the actual augment dispatch patch.

## Strategy: `HasAugmentation` entry-point trampoline

1. At the entry of `HasAugmentation(std::string name)`, replace first N bytes with `JMP rel32` to a code cave
2. Code cave logic:
   - Save registers
   - Extract C string pointer from `std::string` argument (calling convention TBD by Phase 2)
   - Compare against each custom augment name in mapping table
   - If match: swap the string pointer to the corresponding vanilla name
   - Restore registers, execute displaced original instructions, `JMP` back
3. Same trampoline on `GetAugmentationValue` to ensure the `<value>` field is also remapped

## New file: `src/ftl_gen/binary/effects.py`

```python
VANILLA_EFFECTS = {
    "SCRAP_COLLECTOR": {"desc": "Bonus scrap", "category": "economy"},
    "EXPLOSIVE_REPLICATOR": {"desc": "Chance to save missiles", "category": "combat"},
    "LONG_RANGED_SCANNERS": {"desc": "Reveal map info", "category": "exploration"},
    "AUTO_COOLDOWN": {"desc": "Faster weapon charge", "category": "combat"},
    "REPAIR_ARM": {"desc": "Auto hull repair", "category": "defense"},
    # ... all ~30 vanilla augments
}

class AugmentEffectMapper:
    def suggest_mapping(self, augment: AugmentBlueprint) -> EffectMapping
    def generate_patch_spec(self, augments: list[AugmentBlueprint], binary_info: BinaryInfo) -> PatchSpec
```

## Schema change: `src/ftl_gen/xml/schemas.py`

Add `effect_source: str | None` to `AugmentBlueprint` — when set, binary patcher maps custom name to this vanilla effect.

## Trampoline assembly (x86_64, conceptual — exact bytes from Phase 2)

```asm
cave_entry:
    ; Displaced original instructions (saved from function entry)
    push rbp
    mov rbp, rsp
    ; Load string arg, compare against mapping table
    ; If match, swap pointer
    ; JMP back to original+N
```

**Note**: Exact assembly depends on Phase 2 findings (calling convention, string representation, function prologue). The `effects.py` module will generate the cave bytes dynamically based on the mapping table.
