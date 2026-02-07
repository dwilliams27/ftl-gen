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
├── cli.py              # Typer CLI commands (shared helpers for single-item + validate/patch/run)
├── config.py           # Settings singleton, env vars, Slipstream discovery
├── constants.py        # Single source of truth: sprite dims, balance ranges, vanilla assets, type sets
├── core/
│   ├── generator.py    # Main orchestrator (chaos/LLM tracked separately, sprites extracted)
│   ├── mod_builder.py  # .ftl packaging
│   └── slipstream.py   # Slipstream integration
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
├── balance/
│   └── constraints.py  # Balance validation (ranges from constants.py)
└── data/
    ├── loader.py       # Cached vanilla data loader (single load point)
    └── vanilla_reference.json
```

## Architecture decisions

- **Single source of truth**: All balance ranges, sprite dimensions, type sets, and vanilla asset mappings live in `constants.py`. Schemas, prompts, validators, and constraints all import from there.
- **BlueprintBase**: Shared Pydantic base class for Weapon/Drone/Augment/Crew/Ship blueprints. Eliminates duplicated name/title/desc/cost/rarity fields.
- **Generic parsers**: `_fix_blueprint_data()` and `_parse_single()`/`_parse_list()` replace 12 near-identical parse functions. Public API preserved as thin wrappers.
- **Generator decoupling**: Chaos and LLM content tracked in separate lists (no fragile index slicing). Concept expansion skipped when no LLM content requested ($0 for chaos-only).
- **Test loadout opt-in**: `build_kestrel_loadout()` only included when `--test-loadout` flag is passed (was previously always appended).

## Key dependencies

- **LLM**: Claude API or OpenAI for content generation
- **Images**: Google Gemini for weapon and drone sprites
- **Slipstream**: Java-based mod manager for validation/patching
- **FTL**: The actual game installation

## What works

- Weapon/drone/augment/crew generation with valid XML
- Event generation with choices and outcomes
- Weapon sprites (12 frames, 16x60) and drone sprites (4 frames, 50x20)
- Green screen background removal for Gemini-generated images
- Description validation (catches impossible mechanics like "heals hull")
- Slipstream validation and patching
- Items appear in stores in-game
- Image caching (`--cache-images`) and cost tracking
- **Chaos mode** - randomize vanilla game data (FREE, no LLM calls)

## What's limited

- **Events don't trigger** - defined but not hooked into sectors (see docs/game-integration.md)
- **Ships need layouts** - blueprint only, no room/sprite files
- **Crew won't spawn** - not integrated into spawn pools
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
- `--mutate-sprites` generates chaos-mutated placeholder sprites

**What gets chaotified:**
| Item | Stats |
|------|-------|
| Weapons | damage, cooldown, power, cost, fireChance, breachChance, shots, length, ion |
| Drones | power, cost, cooldown, speed |
| Augments | cost, value |
| Crew | maxHealth, moveSpeed, repairSpeed, damageMultiplier, cost |

**Sprite mutations (--mutate-sprites):**
| Transform | Effect |
|-----------|--------|
| Brightness | ±30% random per sprite |
| Contrast | ±20% random per sprite |
| Hue shift | 0-360° random rotation |
| Saturation | ±40% random |
| Color invert | 10% chance at high chaos |
| Posterize | Reduce color depth at high chaos |
| Noise | Random pixel noise at very high chaos |

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
