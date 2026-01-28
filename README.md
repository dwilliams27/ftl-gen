# FTL Mod Generator

LLM-powered tool for generating complete themed FTL: Faster Than Light mods. Creates weapons, drones, augments, events, crew races, ships, and custom sprites from a single theme prompt.

## Features

- **Full Mod Generation**: Generate complete mods with weapons, drones, augments, events, and sprites from a theme
- **Multiple LLM Providers**: Claude API or OpenAI
- **Custom Sprite Generation**: Uses Google Gemini (Nano Banana) for pixel art sprites
- **Slipstream Integration**: Validate, patch, and test mods directly
- **Balance Validation**: Ensures generated content is balanced against vanilla

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/ftl-gen.git
cd ftl-gen

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"
```

## Configuration

Copy `.env.example` to `.env` and fill in your API keys:

```bash
cp .env.example .env
```

Required configuration:
- `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`: For LLM content generation
- `GOOGLE_AI_API_KEY`: For sprite generation (optional, placeholders used if not set)

## Usage

### Generate a Complete Mod

```bash
# Basic mod generation (includes weapons, drones, augments, events)
ftl-gen mod "A faction of sentient crystals with unique weapons"

# With all options
ftl-gen mod "Pirates with boarding focus" \
  --name "PirateFleet" \
  --weapons 5 \
  --events 8 \
  --drones 3 \
  --augments 2 \
  --crew 1 \
  --validate
```

### Generate Individual Content

```bash
# Single weapon
ftl-gen weapon "A gravity beam that stuns crew"

# Single event
ftl-gen event "A derelict ship with mysterious cargo"

# Single ship
ftl-gen ship "A stealth cruiser focused on cloaking and evasion"

# Single drone
ftl-gen drone "A combat drone that focuses on shield damage"

# Single augment
ftl-gen augment "An augment that increases weapon charge speed"

# Single crew race
ftl-gen crew-race "A silicon-based lifeform immune to fire"
```

### Mod Management

```bash
# Validate a mod
ftl-gen validate output/MyMod.ftl

# Apply mod to game
ftl-gen patch MyMod --run

# List available mods
ftl-gen list-mods

# Check configuration
ftl-gen info
```

### CLI Options

```
ftl-gen mod [OPTIONS] THEME

Options:
  -n, --name TEXT         Mod name (auto-generated if not provided)
  -o, --output PATH       Output directory (default: ./output)
  --weapons INTEGER       Number of weapons (default: 3)
  --events INTEGER        Number of events (default: 5)
  --drones INTEGER        Number of drones (default: 2)
  --augments INTEGER      Number of augments (default: 2)
  --crew INTEGER          Number of crew races (default: 0, set to 1+ to include)
  --sprites/--no-sprites  Generate weapon sprites (default: enabled)
  --validate              Validate with Slipstream
  --patch                 Apply mod to game
  --run                   Launch FTL after patching
  --provider TEXT         LLM provider override (claude/openai)
```

## Prerequisites

### Slipstream Mod Manager

Required for validating and applying mods:

```bash
# Download and install
curl -L -o slipstream.tar.gz \
  https://github.com/Vhati/Slipstream-Mod-Manager/releases/download/v1.9.1/SlipstreamModManager_1.9.1-Unix.tar.gz

mkdir -p ~/Documents/SlipstreamModManager
tar -xzf slipstream.tar.gz -C ~/Documents/SlipstreamModManager --strip-components=1

chmod +x ~/Documents/SlipstreamModManager/modman-cli.sh
chmod +x ~/Documents/SlipstreamModManager/modman.command
```

Launch `modman.command` once to configure your FTL game path.

### FTL Game

- Steam or GOG version of FTL: Faster Than Light
- Native Mac version works for basic mods

### Java Runtime

```bash
# Check if installed
java -version

# Install via Homebrew if needed
brew install openjdk@11
```

## Output Structure

Generated mods follow the standard FTL mod structure:

```
output/ModName/
├── data/
│   ├── blueprints.xml.append   # Weapons, drones, augments, crew
│   ├── events.xml.append       # Event encounters
│   └── animations.xml.append   # Sprite definitions
├── img/
│   └── weapons/
│       └── weapon_name_strip12.png  # Weapon sprite sheets
├── mod-appendix/
│   └── metadata.xml            # Mod metadata
└── ModName.ftl                 # Packaged mod file
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check src tests

# Format code
ruff format src tests
```

## Architecture

- **cli.py**: Typer CLI interface
- **core/generator.py**: Main mod orchestration
- **core/mod_builder.py**: .ftl packaging
- **core/slipstream.py**: Slipstream integration
- **llm/client.py**: Multi-provider LLM client
- **llm/prompts.py**: Generation prompts for all content types
- **images/client.py**: Gemini image generation
- **images/sprites.py**: Sprite sheet processing
- **xml/schemas.py**: Pydantic models for FTL blueprints
- **xml/builders.py**: XML generation
- **balance/constraints.py**: Balance validation

## License

MIT
