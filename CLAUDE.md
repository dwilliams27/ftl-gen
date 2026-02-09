# FTL Mod Generator

LLM-powered tool that generates themed FTL: Faster Than Light mods from a text prompt.

**Note to Claude:** Keep this file up to date. When you add features, fix bugs, or learn important context, update the relevant sections. Keep it concise - this is a reference, not documentation.

## What it does

```
"A faction of rogue scientists with unstable laser weapons"
    ↓
Complete mod with weapons, events, drones, augments, sprites
    ↓
Validated and patched into FTL
```

## Project structure

```
src/ftl_gen/
├── cli.py              # Typer CLI commands (shared helpers for single-item + validate/patch/run + diagnose)
├── config.py           # Settings singleton, env vars, Slipstream/FTL discovery
├── constants.py        # Single source of truth: sprite dims, balance ranges, vanilla assets, type sets
├── api/                # FastAPI web UI backend
│   ├── app.py          # FastAPI app factory, static file serving, CORS
│   ├── deps.py         # Dependency injection (Settings, Slipstream)
│   ├── models.py       # API request/response Pydantic models
│   ├── services.py     # ModReader - parses mods from disk/ZIP back into schemas
│   └── routes/         # API route modules
│       ├── config.py   # GET /api/v1/config
│       ├── mods.py     # CRUD for mods (list, detail, delete, download)
│       ├── sprites.py  # Serve sprite PNGs from mods
│       ├── generate.py # Mod generation with SSE progress streaming
│       ├── chaos.py    # Chaos mode endpoints
│       └── validate.py # Validation, diagnostics, crash report, patching
├── core/
│   ├── generator.py    # Main orchestrator (chaos/LLM tracked separately, sprites extracted, progress_callback)
│   ├── launcher.py     # FTLLauncher: monitored FTL launch with log tailing + hang/crash detection
│   ├── mod_builder.py  # .ftl packaging
│   └── slipstream.py   # Slipstream integration + patch_and_launch()
├── chaos/              # Chaos mode - FREE local transforms
│   ├── randomizer.py   # Stat randomization with seed support
│   ├── sprites.py      # Sprite mutations + vanilla sprite extraction
│   └── transforms.py   # Text transforms (word shuffle, zalgo, etc.)
├── llm/
│   ├── client.py       # Claude/OpenAI client
│   ├── prompts.py      # Generation prompts (ranges from constants.py)
│   └── parsers.py      # JSON parsing + description validation (generic _fix/_parse helpers)
├── images/
│   ├── client.py       # Gemini image generation + cost tracking
│   ├── prompts.py      # Sprite generation prompts (green screen)
│   └── sprites.py      # Sprite sheets (weapons: 16x60x12, drones: 50x20x4)
├── xml/
│   ├── schemas.py      # Pydantic models (BlueprintBase -> Weapon/Drone/Augment/Crew/Ship)
│   ├── builders.py     # XML generation (Kestrel test loadout opt-in via --test-loadout)
│   └── validators.py   # Structural XML validation (range checking in Pydantic)
├── binary/             # Binary analysis and patching
│   ├── recon.py        # BinaryRecon: Mach-O analysis, segments, augment strings, code caves
│   ├── patcher.py      # BinaryPatcher: safe patch apply/revert with backup + resign
│   ├── trampoline.py   # TrampolineBuilder: x86_64 code gen for augment name interception
│   ├── effects.py      # AugmentEffectMapper: custom→vanilla augment name mapping
│   └── ghidra/         # Agentic Ghidra analysis (OpenAI function calling)
│       ├── agent.py    # GhidraAgent: LLM-driven RE loop
│       ├── headless.py # GhidraHeadless: headless script execution
│       ├── validator.py # FindingValidator: capstone-based finding verification
│       └── scripts/    # Ghidra Python scripts (decompile, xrefs, strings, bytes)
├── balance/
│   └── constraints.py  # Balance validation (ranges from constants.py)
└── data/
    ├── loader.py       # Cached vanilla data loader (single load point)
    └── vanilla_reference.json

ui/                     # React frontend (Vite + TypeScript + Tailwind)
├── src/
│   ├── api/            # Typed fetch client + TanStack Query hooks
│   ├── components/     # Layout (AppShell, Sidebar), mod cards, blueprint cards
│   ├── pages/          # Dashboard, Mods, ModDetail, Generate, Chaos, Settings
│   ├── lib/            # TypeScript types, utilities
│   └── styles/         # Tailwind globals + FTL dark theme
├── vite.config.ts      # Vite config with API proxy + Tailwind plugin
└── package.json
```

## Architecture decisions

- **Single source of truth**: All balance ranges, sprite dimensions, type sets, and vanilla asset mappings live in `constants.py`. Schemas, prompts, validators, and constraints all import from there.
- **BlueprintBase**: Shared Pydantic base class for Weapon/Drone/Augment/Crew/Ship blueprints. Eliminates duplicated name/title/desc/cost/rarity fields.
- **Generic parsers**: `_fix_blueprint_data()` and `_parse_single()`/`_parse_list()` replace 12 near-identical parse functions. Public API preserved as thin wrappers.
- **Generator decoupling**: Chaos and LLM content tracked in separate lists (no fragile index slicing). Concept expansion skipped when no LLM content requested ($0 for chaos-only).
- **Test loadout opt-in**: `build_kestrel_loadout()` only included when `--test-loadout` flag is passed (was previously always appended).
- **Web UI architecture**: FastAPI backend serves React SPA as static files. Single `ftl-gen ui` command. API uses SSE for streaming generation progress. `ModReader` service parses mods from disk/ZIP back into Pydantic models (reverse of `XMLBuilder`). Vite dev server proxies `/api` to FastAPI for hot reload during development.

## Key dependencies

- **LLM**: Claude API or OpenAI for content generation
- **Images**: Google Gemini for weapon and drone sprites
- **Slipstream**: Java-based mod manager for validation/patching
- **FTL**: The actual game installation
- **Web UI** (optional `[ui]` extra): FastAPI, uvicorn, sse-starlette
- **Frontend**: React 18, Vite, TanStack Query, Tailwind CSS, React Router, lucide-react

## What works

- Weapon/drone/crew generation with valid XML
- Augment generation with optional binary-patched effects (set `effect_source` to inherit vanilla mechanics)
- Event generation with choices and outcomes
- Weapon sprites (12 frames, 16x60) and drone sprites (4 frames, 50x20)
- Green screen background removal for Gemini-generated images
- Description validation (catches impossible mechanics like "heals hull")
- Slipstream validation and patching
- Items appear in stores in-game
- Image caching (`--cache-images`) and cost tracking
- **Chaos mode** - randomize vanilla game data (FREE, no LLM calls)
- **Debugging toolkit** - event loop detection, crash pattern checks, monitored FTL launch, crash reporting
- **Web UI** - local mod browser, generator, chaos mode, diagnose/validate/patch/run (http://localhost:8421)
- **Binary patching** - x86_64 trampoline injection for augment effect remapping

## Binary Patching (Augment Effects)

Custom augment names are cosmetic by default (effects hardcoded in FTL binary). The binary patcher intercepts `HasAugmentation`/`GetAugmentationValue` via x86_64 trampolines to remap custom names → vanilla names at runtime. **E2E verified:** custom "PREIGNITION_MATRIX" augment successfully inherits WEAPON_PREIGNITE effect (weapons start fully charged).

```bash
# Generate a patch spec with explicit mapping
ftl-gen binary-patch generate "My Mod" --map "CUSTOM_AUG:WEAPON_PREIGNITE" -o patch.json

# Or auto-detect from effect_source / description
ftl-gen binary-patch generate "My Mod" -o patch.json

# Apply patch to FTL binary (creates .ftlgen.bak backup)
ftl-gen binary-patch apply patch.json

# Check what's patched
ftl-gen binary-patch status

# Revert to original binary
ftl-gen binary-patch revert
```

**How it works:**
1. Reads augments via `--map` flags (highest priority), `effect_source` field, or auto-suggestion from description
2. Generates x86_64 trampoline code in a code cave (NUL region in `__TEXT`)
3. Overwrites function prologues (13 bytes) with JMP to trampoline
4. Trampoline: when game checks for a vanilla augment name, swaps RSI to point to SSO string of the custom name (so the function finds it in the ship's augment list)
5. Executes displaced prologue, JMPs back

**Key addresses (from Ghidra analysis):**
- `ShipObject::HasAugmentation` @ `0x1000a2740` (13-byte prologue)
- `ShipObject::GetAugmentationValue` @ `0x1000a2870` (13-byte prologue)
- Both use System V AMD64 ABI: `this` in RDI, `std::string*` in RSI

**Safety:** Backup before patch, all-or-nothing verification, atomic write, ad-hoc code re-signing. Works under Rosetta 2 on Apple Silicon.

## TODO: Hook Catalog / Registry

The current binary patcher hardcodes augment-specific constants (function addresses, prologue sizes) directly in `trampoline.py`. The vision is to generalize this into a catalog of known hook targets discovered via Ghidra analysis.

**Target architecture:**
- `binary/hooks/` — per-capability modules (`augments.py`, `events.py`, `crew.py`)
- Each module defines `HookSite` entries (function VA, prologue size, ABI details, displaced bytes)
- `trampoline.py` provides generic primitives: `HookSite`, `StringRemap`, prologue displacement, JMP generation
- Domain logic (what to remap, how to match) lives in the capability modules
- Each mod composes the binary patches it needs by declaring capabilities

**Enables:**
- Custom augment effects (done — `binary/hooks/augments.py` equivalent is current `trampoline.py`)
- Event injection — hook event loading to register custom events without freezing
- Crew spawn pools — hook spawn logic to include custom races
- Custom system behaviors — intercept system update functions

**Migration path:**
1. Extract `HAS_AUGMENTATION_VA`, `GET_AUGMENTATION_VALUE_VA`, prologue sizes into a `HookSite` dataclass
2. Move augment-specific logic from `trampoline.py` → `binary/hooks/augments.py`
3. Keep `TrampolineBuilder` as the generic code generator, parameterized by `HookSite` + `StringRemap` lists
4. Add new hook targets as Ghidra analysis discovers them

## Debugging Toolkit

```bash
# Static analysis - checks for freezes/crashes before patching
ftl-gen diagnose "ModName"

# With monitored launch - patches, launches, watches for hangs
ftl-gen diagnose "ModName" --launch
```

**Static checks (`validators.py`):**
- `detect_event_loops()` — DFS cycle detection on event graph (prevents startup freezes)
- `check_dangling_references()` — flags `<event load="X">` where X is undefined
- `check_common_crash_patterns()` — choices missing outcomes, BEAM without `<length>`, MISSILES without `<missiles>`

**Monitored launch (`core/launcher.py`):**
- `FTLLauncher` — Popen + background log tailing from FTL.log bookmark
- Detects early crash (process exits), hang (no activity 15s after "Blueprints Loaded!"), or success
- `get_crash_report()` — snapshots log lines, errors, process status, macOS .ips crash reports

**Web UI:**
- "Diagnose" button — runs all static checks, shows pass/fail/warn checklist
- "Report Crash" button — appears after Patch & Run, shows FTL.log snapshot with copy-to-clipboard

## What's limited

- **Augments need binary patch** - custom augment names have no mechanical effect by default (hardcoded in binary). Use `ftl-gen binary-patch generate` to create a patch that remaps custom names → vanilla effects via x86_64 trampoline. Set `effect_source` on `AugmentBlueprint` to specify which vanilla effect to inherit. See [docs/xml-modding-limits.md](docs/xml-modding-limits.md)
- **Events don't trigger** - generated but not written to .ftl (causes freeze). See `PATCH_EVENTS=1` guard in `core/mod_builder.py`
- **Ships need layouts** - blueprint only, no room/sprite files
- **Crew won't spawn** - not integrated into spawn pools (hardcoded in binary)
- **No Hyperspace support** - advanced modding features unavailable

## To run

```bash
pip install -e ".[dev]"
cp .env.example .env  # Add API keys
ftl-gen mod "your theme" -w3 -e3 -d0 -a0 -c0 --validate --patch --run
```

**IMPORTANT:** Always specify all content flags (`-w`, `-e`, `-d`, `-a`, `-c`) when running non-interactively. Without them, the CLI prompts for input which doesn't work in automated contexts.

```bash
# Good - explicit counts
ftl-gen mod "space pirates" -w5 -e3 -d2 -a1 -c0

# Bad - triggers interactive prompt
ftl-gen mod "space pirates"
```

## Web UI

```bash
# Install UI dependencies
pip install -e ".[ui]"
cd ui && npm install && npm run build && cd ..

# Start (serves SPA + API on one port)
ftl-gen ui                    # http://localhost:8421
ftl-gen ui --dev              # Dev mode (CORS for Vite HMR)
ftl-gen ui --port 9000        # Custom port

# Development (two terminals)
ftl-gen ui --dev              # Backend on :8421
cd ui && npm run dev          # Vite HMR on :5173 (proxies /api → :8421)
```

**Pages:** Dashboard, Mod Browser, Mod Detail (tabbed: weapons/drones/augments/crew/events/sprites/XML), Generate, Chaos, Settings

**API:** All endpoints at `/api/v1/` — OpenAPI docs at `/api/docs`

## Chaos Mode

Chaos mode randomizes ALL vanilla game items (weapons, drones, augments, crew) using FREE local transforms (no LLM calls, $0.00 cost).

```bash
# Standalone chaos (no new content, just randomized vanilla)
ftl-gen chaos --level 0.5                    # 50% chaos
ftl-gen chaos --level 0.8 --seed 12345       # Reproducible chaos
ftl-gen chaos --level 1.0 --unsafe           # Extreme values allowed

# Chaos + themed LLM content
ftl-gen mod "pirates" --chaos 0.5 -w2 -e0 -d0 -a0 -c0  # Chaotified vanilla + new pirate weapons
```

**How it works:**
- Randomizes stats by ±50% (at chaos=1.0) around original values
- Type-safe: never changes weapon types (prevents game crashes)
- Same names override vanilla items when patched
- Seeded RNG for reproducible results (`--seed`)
- `--unsafe` removes bounds (10%-500% range by default)

**What gets chaotified:**
| Item | Stats |
|------|-------|
| Weapons | damage, cooldown, power, cost, fireChance, breachChance, shots, length, ion |
| Drones | power, cost, cooldown, speed |
| Augments | cost, value |
| Crew | maxHealth, moveSpeed, repairSpeed, damageMultiplier, cost |

## To be fully successful, this project needs

1. **Event sector integration** - Auto-hook events into appropriate sectors based on theme
2. **Ship layout generation** - Generate room layouts and sprites, not just blueprints
3. **Crew spawn integration** - Add custom races to enemy ships and hiring events
4. **Hyperspace support** - Enable advanced features (custom systems, lua scripting)
5. **More sprites** - Crew sprites (~100 frames, complex), ship hulls
6. **Balance testing** - Automated playtest simulation to catch OP/useless items
7. **Mod conflict detection** - Warn when generated content conflicts with popular mods

## TODO: Hyperspace Support

Hyperspace is an FTL hard-coded modding API that extends capabilities far beyond vanilla XML modding:
- Custom weapon behaviors (not just stats)
- Custom crew abilities with unique effects
- New systems
- Lua scripting support
- Advanced event functionality
- Seeded runs

**Requirements:**
- Only works on FTL 1.6.9 (includes auto-downgrade script)
- Requires Windows or Wine on Mac/Linux
- Use FTLMan instead of Slipstream for easier Hyperspace management

**Resources:**
- https://ftl-hyperspace.github.io/FTL-Hyperspace/
- Current version: 1.21.1

**Implementation notes:**
- Would need Wine setup instructions for Mac users
- Generate Hyperspace-specific XML tags for advanced features
- Could enable truly unique weapon mechanics beyond stat modifications

**Alternative: Native macOS deep modding** — see [docs/deep-modding-research.md](docs/deep-modding-research.md) for DYLD interception and static binary patching research approaches that could work without Wine/Windows.
