# FTL Mod Generator

LLM-powered tool that generates themed FTL: Faster Than Light mods from a text prompt.

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
├── cli.py              # Typer CLI commands
├── config.py           # Settings, env vars
├── core/
│   ├── generator.py    # Main orchestrator
│   ├── mod_builder.py  # .ftl packaging
│   └── slipstream.py   # Slipstream integration
├── llm/
│   ├── client.py       # Claude/OpenAI client
│   ├── prompts.py      # Generation prompts
│   └── parsers.py      # JSON response parsing
├── images/
│   ├── client.py       # Gemini image generation
│   └── sprites.py      # Sprite sheet processing
└── xml/
    ├── schemas.py      # Pydantic models
    └── builders.py     # XML generation
```

## Key dependencies

- **LLM**: Claude API or OpenAI for content generation
- **Images**: Google Gemini for weapon sprites
- **Slipstream**: Java-based mod manager for validation/patching
- **FTL**: The actual game installation

## What works

- Weapon/drone/augment generation with valid XML
- Event generation with choices and outcomes
- Weapon sprite generation (12-frame sheets)
- Slipstream validation and patching
- Items appear in stores in-game

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

## To be fully successful, this project needs

1. **Event sector integration** - Auto-hook events into appropriate sectors based on theme
2. **Ship layout generation** - Generate room layouts and sprites, not just blueprints
3. **Crew spawn integration** - Add custom races to enemy ships and hiring events
4. **Hyperspace support** - Enable advanced features (custom systems, lua scripting)
5. **Better sprite generation** - Drone sprites, crew sprites, ship hulls
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
