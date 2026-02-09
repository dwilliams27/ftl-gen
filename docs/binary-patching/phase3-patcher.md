# Phase 3: Core Binary Patcher

**Goal**: Safe, reversible binary patching with verification and code signing.

## New file: `src/ftl_gen/binary/patcher.py`

## JSON Patch Spec Format

```json
{
  "spec_version": "1.0",
  "ftl_version": "1.6.14",
  "platform": "macos-x86_64",
  "binary_sha256": "abc123...",
  "description": "Map custom augments to vanilla effects",
  "patches": [
    {
      "id": "augment_trampoline_install",
      "description": "JMP to code cave at HasAugmentation entry",
      "offset": "0x000b4a20",
      "old_bytes": "554889e548...",
      "new_bytes": "e9db050f00..."
    },
    {
      "id": "augment_trampoline_cave",
      "description": "Name remap logic in code cave",
      "offset": "0x001ff000",
      "old_bytes": "0000000000...",
      "new_bytes": "488d3d..."
    }
  ],
  "augment_mappings": [
    {"custom_name": "CUSTOM_SCRAP_BONUS", "vanilla_effect": "SCRAP_COLLECTOR"}
  ]
}
```

## `BinaryPatcher` class

```python
class BinaryPatcher:
    def __init__(self, binary_path: Path)
    def backup(self) -> Path                        # FTL -> FTL.bak (alongside binary)
    def verify_spec(self, spec: PatchSpec) -> list[str]  # Check all old_bytes match
    def apply(self, spec: PatchSpec) -> PatchResult  # Atomic: verify all -> write all
    def revert(self) -> bool                         # Restore from backup
    def resign(self) -> bool                         # codesign --remove-signature + codesign -s -
    def load_spec(path: Path) -> PatchSpec           # Parse JSON
```

## Safety guarantees

- `old_bytes` verification before ANY writes (abort entirely if mismatch)
- Backup created before first patch (original binary preserved)
- State file `.patch_state.json` in specs/ tracks applied patches + binary hash
- `resign()` strips and ad-hoc re-signs after patching

## CLI commands

- `ftl-gen binary-patch apply --spec <path>` — apply a patch spec
- `ftl-gen binary-patch revert` — restore original binary
- `ftl-gen binary-patch status` — show what's currently applied

## Patch spec storage

`src/ftl_gen/binary/specs/` — directory for patch spec JSON files and state tracking.
