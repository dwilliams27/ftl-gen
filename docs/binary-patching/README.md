# FTL Binary Patching for Custom Augment Effects

FTL's augment effects are hardcoded in the binary — a dispatch mechanism maps augment name strings (e.g., `SCRAP_COLLECTOR`) to effect logic. Custom augment names appear in stores but do nothing. This plan:

1. Builds **agentic Ghidra tooling** to reverse engineer the binary and find the dispatch mechanism
2. Builds a **binary patcher** that adds custom augment name -> vanilla effect mappings
3. **Validates** by having a custom-named augment trigger a visible effect in-game

This is the foundation for deeper binary modding (events, crew spawning, custom mechanics).

## Phases

| Phase | Document | Summary |
|-------|----------|---------|
| 1 | [phase1-recon.md](phase1-recon.md) | Binary Reconnaissance Module — programmatic Mach-O inspection |
| 2 | [phase2-ghidra.md](phase2-ghidra.md) | Agentic Ghidra Analysis — automated RE with Codex + Ghidra headless |
| 3 | [phase3-patcher.md](phase3-patcher.md) | Core Binary Patcher — safe, reversible patching with verification |
| 4 | [phase4-trampoline.md](phase4-trampoline.md) | Augment Name Remap — the HasAugmentation trampoline |
| 5 | [phase5-integration.md](phase5-integration.md) | Pipeline Integration — wire into mod generation/deployment flow |

## Implementation Order

| Step | Phase | What | Depends On |
|------|-------|------|------------|
| 1 | P1 | `binary/recon.py` + `binary-info` CLI | Nothing |
| 2 | P1 | `pyproject.toml` `[binary]` deps | Nothing |
| 3 | P2 | Ghidra headless setup + agentic analysis | Step 1 (need binary path) |
| 4 | P2 | Record findings: function addresses, calling convention, prologue bytes | Step 3 |
| 5 | P3 | `binary/patcher.py` + `binary-patch` CLI | Step 2 |
| 6 | P4 | `binary/effects.py` + trampoline generation | Steps 4 + 5 |
| 7 | P4 | Generate first patch spec for benchmark augment | Step 6 |
| 8 | P5 | Pipeline integration (`cli.py`, `slipstream.py`, `launcher.py`) | Step 7 |
| 9 | P5 | API endpoints + UI toggle | Step 8 |
| 10 | -- | Benchmark: end-to-end custom augment test | Step 8 |

Steps 1-2 are parallelizable. Steps 3-4 are the critical path (reverse engineering). Steps 5-7 can partially overlap with step 4.

## Benchmark / Validation

The end-to-end test that proves the system works:

1. Generate a mod with augment `CUSTOM_SCRAP_BONUS` (custom name, `effect_source="SCRAP_COLLECTOR"`)
2. Mod XML creates the augment with custom name/title/desc
3. Binary patcher applies trampoline: `HasAugmentation("CUSTOM_SCRAP_BONUS")` remaps to `"SCRAP_COLLECTOR"`
4. Slipstream patches ftl.dat, binary patcher patches FTL executable
5. Launch FTL, start game with Engi A test loadout including the augment
6. Collect scrap -> **bonus scrap appears** (proving the custom name triggered the vanilla effect)

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Hardened runtime blocks re-signing | Phase 1 recon detects this immediately; abort early |
| No single dispatch function (scattered call sites) | Trampoline on `HasAugmentation` itself handles this — one patch point |
| Code cave space insufficient | LIEF can extend `__TEXT` segment; or allocate new segment |
| Steam overwrites binary | `old_bytes` verification prevents applying stale patches; warn user |
| `std::string` SSO complicates interception | Ghidra analysis reveals exact ABI; adapt trampoline accordingly |

## Files Summary

### New files (10)
- `src/ftl_gen/binary/__init__.py`
- `src/ftl_gen/binary/recon.py`
- `src/ftl_gen/binary/patcher.py`
- `src/ftl_gen/binary/effects.py`
- `src/ftl_gen/binary/ghidra/__init__.py`
- `src/ftl_gen/binary/ghidra/headless.py`
- `src/ftl_gen/binary/ghidra/scripts/find_augment_strings.py` (Jython)
- `src/ftl_gen/binary/ghidra/scripts/decompile_dispatch.py` (Jython)
- `src/ftl_gen/binary/ghidra/agent.py`
- `src/ftl_gen/api/routes/binary.py`

### Modified files (7)
- `pyproject.toml` — add `[binary]` optional deps
- `src/ftl_gen/config.py` — add `ghidra_home` setting
- `src/ftl_gen/cli.py` — add `binary-info`, `binary-patch` commands; `--binary-patch` flag on `mod`
- `src/ftl_gen/xml/schemas.py` — add `effect_source` to `AugmentBlueprint`
- `src/ftl_gen/core/slipstream.py` — binary patch hook in `patch_and_launch()`
- `src/ftl_gen/core/launcher.py` — binary revert on stop
- `src/ftl_gen/api/app.py` — register binary router

### Test files (3)
- `tests/test_binary_recon.py`
- `tests/test_binary_patcher.py`
- `tests/test_binary_effects.py`
