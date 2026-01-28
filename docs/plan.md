# FTL Mod Generator - Implementation Plan

## Overview

Build an LLM-powered tool that generates **complete themed FTL mods** - combining weapons, ships, events, and crew into cohesive mod packages. The LLM makes creative decisions about content, balance, and theming while automation handles XML generation and packaging.

**Key features**:
- Generate full mods from a single theme/concept prompt
- Configurable LLM providers (Claude API or OpenAI)
- **Custom sprite generation** via Google Gemini (Nano Banana) API
- Automatic XML generation and validation
- Integration with Slipstream for patching and testing
- Native Mac support (no Wine required for basic modding)

---

## Prerequisites Setup

### 1. Slipstream Mod Manager Installation

Slipstream is required to validate and apply mods. Install on Mac:

```bash
# Download from GitHub releases
curl -L -o slipstream.zip https://github.com/Vhati/Slipstream-Mod-Manager/releases/download/v1.9.1/SlipstreamModManager_1.9.1-Unix.tar.gz

# Extract to standard location
mkdir -p ~/Documents/SlipstreamModManager
tar -xzf slipstream.zip -C ~/Documents/SlipstreamModManager --strip-components=1

# Make executable
chmod +x ~/Documents/SlipstreamModManager/modman-cli.sh
chmod +x ~/Documents/SlipstreamModManager/modman.command
```

**First run**: Launch `modman.command` once to configure FTL game path.

### 2. FTL Game

- Steam or GOG version of FTL: Faster Than Light
- Native Mac version works for basic mods

### 3. Java Runtime

```bash
# Check if Java is installed
java -version

# If not, install via Homebrew
brew install openjdk@11
```

---

## FTL Modding Background

### Mod Structure
- Mods are `.ftl` files (renamed `.zip`)
- Folder structure: `data/` (XML), `img/` (sprites), `mod-appendix/` (metadata)
- Use `.xml.append` files to add/modify content without overwriting base game
- Key files: `blueprints.xml.append` (weapons, ships, drones, crew), `events.xml.append` (encounters)

### Slipstream CLI
```bash
modman --patch mod.ftl        # Apply mods to game
modman --validate mod.ftl     # Check for XML errors
modman --runftl               # Launch FTL
modman --list-mods            # Show available mods
```

---

## Architecture

### Tech Stack
- **Python 3.10+** - Main language
- **anthropic SDK** - Claude API integration
- **openai SDK** - OpenAI API integration (alternative provider)
- **google-genai SDK** - Gemini API for image generation (Nano Banana)
- **Pillow** - Image processing for sprite sheets
- **lxml** - XML generation/parsing
- **pydantic** - Data validation and schemas
- **typer** - CLI framework
- **pytest** - Testing

### API Configuration

```bash
# .env file
# LLM Provider
LLM_PROVIDER=claude          # or "openai"
ANTHROPIC_API_KEY=sk-...     # For Claude
OPENAI_API_KEY=sk-...        # For OpenAI
LLM_MODEL=claude-sonnet-4-20250514  # or "gpt-4o"

# Image Generation (Google Gemini)
GOOGLE_AI_API_KEY=...        # From Google AI Studio
IMAGE_MODEL=gemini-2.0-flash-exp  # Nano Banana model
```

### Project Structure

```
ftl-gen/
├── pyproject.toml
├── README.md
├── .env.example
├── .gitignore
├── src/ftl_gen/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                 # CLI commands
│   ├── config.py              # Settings + env loading
│   ├── core/
│   │   ├── generator.py       # Full mod orchestration
│   │   ├── mod_builder.py     # .ftl packaging
│   │   └── slipstream.py      # Slipstream CLI integration
│   ├── llm/
│   │   ├── client.py          # Multi-provider client (Claude/OpenAI)
│   │   ├── prompts.py         # Theme-based generation prompts
│   │   └── parsers.py         # JSON response parsing
│   ├── images/
│   │   ├── client.py          # Gemini image generation client
│   │   ├── sprites.py         # Sprite sheet creation + processing
│   │   └── prompts.py         # Image generation prompts
│   ├── xml/
│   │   ├── schemas.py         # Pydantic models
│   │   ├── builders.py        # XML generation
│   │   └── validators.py      # XML validation
│   ├── balance/
│   │   └── constraints.py     # Balance rules + validation
│   └── data/
│       └── vanilla_reference.json  # Baseline stats
├── tests/
│   ├── test_xml_builders.py
│   ├── test_llm_client.py
│   ├── test_image_gen.py
│   └── test_mod_builder.py
└── output/                    # Generated mods (gitignored)
```

---

## Key Components

### 1. XML Schemas (Pydantic Models)

**WeaponBlueprint**:
```python
class WeaponBlueprint(BaseModel):
    name: str           # UPPERCASE_WITH_UNDERSCORES
    type: Literal['LASER', 'MISSILES', 'BEAM', 'BOMB', 'BURST']
    title: str          # Display name
    desc: str           # Description
    damage: int         # 0-10
    shots: int          # 1-10
    fireChance: int     # 0-10 (10 = 100%)
    breachChance: int   # 0-10
    cooldown: float     # 1-30 seconds
    power: int          # 1-5
    cost: int           # 10-200 scrap
    rarity: int         # 0-5
```

**EventBlueprint**:
```python
class EventBlueprint(BaseModel):
    name: str
    text: str
    choices: list[EventChoice]

class EventChoice(BaseModel):
    text: str
    req: Optional[str]      # "human", "engi", etc.
    hidden: bool = False
    event: Optional[EventOutcome]
```

### 2. LLM Prompting Strategy

**Two-phase generation**:
1. **Concept expansion**: LLM elaborates user's brief idea
2. **Structured output**: LLM generates JSON matching Pydantic schema

**Balance context**: Include vanilla weapon stats as reference

**Validation loop**: If generated content fails validation, feed errors back to LLM for correction

### 3. CLI Interface

```bash
# Primary command: Generate full themed mod
ftl-gen mod "A faction of sentient crystals with unique weapons and encounters"
ftl-gen mod "Pirates with boarding focus and risky high-reward events"

# Individual content (for iterating on specific pieces)
ftl-gen weapon "A gravity beam that stuns crew"
ftl-gen ship "A stealth cruiser focused on cloaking"
ftl-gen event "A derelict ship encounter with choices"

# Options
--name, -n          # Mod name (auto-generated if not provided)
--output, -o        # Output directory (default: ./output)
--weapons N         # Number of weapons to generate (default: 3)
--events N          # Number of events to generate (default: 5)
--sprites / --no-sprites  # Enable/disable sprite generation (default: enabled)
--validate          # Run Slipstream validation
--patch             # Apply mod to game
--run               # Launch FTL after patching
--interactive, -i   # Refinement mode
--provider          # LLM provider override (claude/openai)
```

**Example workflow**:
```bash
# Generate a mod
ftl-gen mod "Ancient alien technology" --name "AlienTech" --validate

# Review generated files in ./output/AlienTech/
# Then patch and test
ftl-gen patch AlienTech --run
```

### 4. Slipstream Integration

```python
class SlipstreamManager:
    def validate(self, mod_path) -> ValidationResult
    def patch(self, mod_paths) -> bool
    def patch_and_run(self, mod_paths) -> bool
```

Requires Slipstream installed (default: `~/Documents/SlipstreamModManager*/`)

### 5. Image Generation (Nano Banana / Gemini)

**FTL Sprite Requirements**:
- **Weapon sprites**: 16x60 pixels per frame, 12 frames = 192x60 sprite sheet
- **Format**: PNG with transparency
- **Style**: Pixel art to match FTL aesthetic
- **Location**: `img/weapons/` folder in mod

**Generation workflow**:
1. LLM generates weapon concept with visual description
2. Image prompt is crafted for pixel art weapon sprite
3. Gemini generates base image (higher res)
4. Pillow processes: resize, pixelate, create sprite sheet frames
5. Generate `animations.xml.append` with sprite sheet definitions

**Sprite sheet XML** (auto-generated):
```xml
<animSheet name="WEAPON_NAME" w="192" h="60" fw="16" fh="60">
    weapons/WEAPON_NAME_strip12.png
</animSheet>
<weaponAnim name="WEAPON_NAME">
    <sheet>WEAPON_NAME</sheet>
    <desc length="12" x="0" y="0"/>
    <chargedFrame>5</chargedFrame>
    <fireFrame>7</fireFrame>
    <firePoint x="8" y="30"/>
    <mountPoint x="0" y="30"/>
</weaponAnim>
```

**Image generation client**:
```python
class GeminiImageClient:
    async def generate_weapon_sprite(
        self,
        weapon_concept: str,
        weapon_type: str  # LASER, BEAM, etc.
    ) -> bytes:
        """Generate weapon sprite using Gemini."""

    def create_sprite_sheet(
        self,
        base_image: bytes,
        frames: int = 12
    ) -> bytes:
        """Convert single image to animated sprite sheet."""
```

---

## Implementation Steps

### Phase 1: Foundation
1. Set up Python project with pyproject.toml
2. Create Pydantic schemas for weapons, ships, events, crew
3. Implement XML builders that generate `.xml.append` content
4. Create ModBuilder to package folders into `.ftl` files
5. Slipstream integration with auto-detection of installation path

### Phase 2: LLM Integration
1. Create multi-provider LLM client (Claude + OpenAI)
2. Design prompt templates for full mod generation with theme coherence
3. Implement JSON response parsing with schema validation
4. Add retry logic with error feedback to LLM
5. Create "mod orchestrator" that generates cohesive content sets

### Phase 3: Image Generation
1. Create Gemini image client with Nano Banana model
2. Design prompts for pixel art weapon sprites
3. Implement sprite sheet processor (resize, pixelate, animate)
4. Generate animations.xml.append for custom sprites
5. Integrate with mod builder to include img/ folder

### Phase 4: CLI and Full Mod Generation
1. Build typer CLI with `mod` as primary command
2. Implement theme-based generation (LLM creates weapons/events that fit theme)
3. Add `--sprites` flag to enable/disable image generation
4. Add interactive refinement mode for tweaking individual pieces
5. Balance constraint checking with vanilla reference data

### Phase 5: Testing and Polish
1. Unit tests for XML generation
2. Unit tests for sprite sheet processing
3. Integration tests with Slipstream
4. E2E test: generate mod with sprites, validate, patch, run game
5. README with usage examples

---

## Files to Create

| File | Purpose |
|------|---------|
| `pyproject.toml` | Project config, dependencies |
| `.env.example` | Template for API keys and config |
| `src/ftl_gen/xml/schemas.py` | Pydantic models for all blueprint types |
| `src/ftl_gen/xml/builders.py` | XML element generation |
| `src/ftl_gen/llm/prompts.py` | Prompt templates for themed mod generation |
| `src/ftl_gen/llm/client.py` | Multi-provider LLM client (Claude + OpenAI) |
| `src/ftl_gen/images/client.py` | Gemini image generation client |
| `src/ftl_gen/images/sprites.py` | Sprite sheet processing (Pillow) |
| `src/ftl_gen/images/prompts.py` | Pixel art weapon sprite prompts |
| `src/ftl_gen/core/mod_builder.py` | .ftl packaging (now includes img/) |
| `src/ftl_gen/core/slipstream.py` | Slipstream CLI wrapper with auto-detection |
| `src/ftl_gen/core/generator.py` | Mod orchestrator - coordinates themed generation |
| `src/ftl_gen/cli.py` | typer CLI app |
| `src/ftl_gen/balance/constraints.py` | Balance validation |
| `src/ftl_gen/data/vanilla_reference.json` | Baseline weapon/ship stats |

---

## Verification

1. **Unit tests**: `pytest tests/`
2. **XML validation**: Generated mods pass `modman --validate`
3. **E2E test**:
   ```bash
   # Generate a test mod with sprites
   ftl-gen mod "Plasma weapons faction" --name PlasmaTest --sprites --validate

   # Verify output structure
   ls output/PlasmaTest/
   # Should show: data/, img/, mod-appendix/, PlasmaTest.ftl

   # Check sprite files exist
   ls output/PlasmaTest/img/weapons/
   # Should show: *_strip12.png files

   # Patch and run
   ftl-gen patch PlasmaTest --run
   # FTL should launch with mod applied, weapons should display custom sprites
   ```

---

## Dependencies

```toml
[project.dependencies]
anthropic = ">=0.25.0"
openai = ">=1.0.0"
google-genai = ">=1.0.0"  # Gemini API for image generation
pillow = ">=10.0.0"       # Image processing for sprites
lxml = ">=5.0.0"
pydantic = ">=2.0.0"
typer = ">=0.9.0"
python-dotenv = ">=1.0.0"
rich = ">=13.0.0"         # For nice CLI output

[project.optional-dependencies]
dev = ["pytest", "pytest-asyncio", "ruff"]
```

---

## References

- [Steam Guide: Making Mods for FTL](https://steamcommunity.com/sharedfiles/filedetails/?id=277959176)
- [Slipstream Mod Manager](https://github.com/Vhati/Slipstream-Mod-Manager)
- [KK's Modding Tutorial](https://subsetgames.com/forum/viewtopic.php?t=32568)
- [FTL Wiki: Events.xml Structure](https://subsetgames.com/forum/viewtopic.php?t=9436)

---

## Future Enhancements (Out of Scope)

- **Hyperspace support**: For advanced modding features, would require Wine setup
- **Ship hull sprites**: Complex multi-part sprites with gibs; would need more sophisticated image generation
- **Ship layouts**: Requires visual editor; could add integration with Superluminal 2
- **Audio generation**: Custom weapon sounds
