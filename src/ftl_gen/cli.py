"""CLI interface for FTL Mod Generator."""

from pathlib import Path
from typing import Annotated, Optional

import typer
from lxml import etree
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ftl_gen import __version__
from ftl_gen.chaos import ChaosConfig, SpriteMutator, randomize_all
from ftl_gen.chaos.sprites import VanillaSpriteExtractor, mutate_vanilla_sprites
from ftl_gen.config import Settings, get_settings
from ftl_gen.core.generator import ModGenerator
from ftl_gen.core.mod_builder import ModBuilder
from ftl_gen.core.slipstream import SlipstreamManager
from ftl_gen.xml.builders import XMLBuilder

app = typer.Typer(
    name="ftl-gen",
    help="LLM-powered FTL mod generator with custom sprite generation",
    no_args_is_help=True,
)

console = Console()


def version_callback(value: bool):
    if value:
        console.print(f"ftl-gen version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", "-v", callback=version_callback, is_eager=True),
    ] = False,
):
    """FTL Mod Generator - Create themed FTL mods with AI."""
    pass


# --- Shared helpers ---


def _validate_patch_run(
    ftl_path: Path,
    settings: Settings,
    validate: bool,
    patch: bool,
    run: bool,
) -> None:
    """Handle validate/patch/run workflow (shared by mod and chaos commands)."""
    if validate:
        console.print("\n[bold]Validating mod...[/]")
        slipstream = SlipstreamManager(settings)
        if slipstream.is_available():
            result = slipstream.validate(ftl_path)
            if result.warnings:
                for warning in result.warnings:
                    console.print(f"  [yellow]Warning: {warning}[/]")
            if result.errors:
                for error in result.errors:
                    console.print(f"  [red]Error: {error}[/]")
            if result.ok:
                console.print("[green]Validation passed[/]")
            else:
                console.print("[red]Validation failed[/]")
                if not patch:
                    raise typer.Exit(1)
        else:
            console.print("[yellow]Slipstream not available, skipping validation[/]")

    if patch or run:
        console.print("\n[bold]Applying mod...[/]")
        slipstream = SlipstreamManager(settings)
        if not slipstream.is_available():
            console.print("[red]Slipstream not available[/]")
            raise typer.Exit(1)

        if run:
            result = slipstream.patch_and_run([ftl_path])
        else:
            result = slipstream.patch([ftl_path])

        if result.success:
            console.print("[green]Mod applied successfully[/]")
        else:
            console.print(f"[red]Failed to apply mod: {result.message}[/]")
            raise typer.Exit(1)


# Dispatch table for single-item generation
_SINGLE_ITEM_GENERATORS = {
    "weapon": "generate_single_weapon",
    "event": "generate_single_event",
    "drone": "generate_single_drone",
    "augment": "generate_single_augment",
    "crew": "generate_single_crew",
    "ship": "generate_single_ship",
}


def _generate_single_item(description: str, item_type: str, output: Path | None) -> object:
    """Generate a single item and return the blueprint."""
    settings = get_settings()
    if output:
        settings.output_dir = output

    generator = ModGenerator(settings)
    method = getattr(generator, _SINGLE_ITEM_GENERATORS[item_type])
    return method(description)


def _display_single_item(item_type: str, bp: object) -> None:
    """Display a generated item as a table + XML."""
    xml_builder = XMLBuilder()

    if item_type == "weapon":
        table = Table(title=f"Generated Weapon: {bp.title}")
        table.add_column("Property", style="cyan")
        table.add_column("Value")
        table.add_row("Name", bp.name)
        table.add_row("Type", bp.type)
        table.add_row("Damage", str(bp.damage))
        table.add_row("Shots", str(bp.shots))
        table.add_row("Cooldown", f"{bp.cooldown}s")
        table.add_row("Power", str(bp.power))
        table.add_row("Cost", f"{bp.cost} scrap")
        table.add_row("Description", bp.desc)
        console.print(table)
        xml = xml_builder.build_weapon(bp)

    elif item_type == "event":
        console.print(Panel(bp.text, title=f"Event: {bp.name}"))
        if bp.choices:
            console.print("\n[bold]Choices:[/]")
            for i, choice in enumerate(bp.choices, 1):
                req_str = f" [dim](requires: {choice.req})[/dim]" if choice.req else ""
                console.print(f"  {i}. {choice.text}{req_str}")
                if choice.event and choice.event.text:
                    console.print(f"     [dim]→ {choice.event.text[:100]}...[/dim]")
        xml = xml_builder.build_event(bp)

    elif item_type == "drone":
        table = Table(title=f"Generated Drone: {bp.title}")
        table.add_column("Property", style="cyan")
        table.add_column("Value")
        table.add_row("Name", bp.name)
        table.add_row("Type", bp.type)
        table.add_row("Power", str(bp.power))
        table.add_row("Cost", f"{bp.cost} scrap")
        if bp.cooldown:
            table.add_row("Cooldown", f"{bp.cooldown}s")
        if bp.speed:
            table.add_row("Speed", str(bp.speed))
        table.add_row("Description", bp.desc)
        console.print(table)
        xml = xml_builder.build_drone(bp)

    elif item_type == "augment":
        table = Table(title=f"Generated Augment: {bp.title}")
        table.add_column("Property", style="cyan")
        table.add_column("Value")
        table.add_row("Name", bp.name)
        table.add_row("Cost", f"{bp.cost} scrap")
        table.add_row("Rarity", str(bp.rarity))
        table.add_row("Stackable", "Yes" if bp.stackable else "No")
        if bp.value is not None:
            table.add_row("Value", str(bp.value))
        table.add_row("Description", bp.desc)
        console.print(table)
        xml = xml_builder.build_augment(bp)

    elif item_type == "crew":
        table = Table(title=f"Generated Crew Race: {bp.title}")
        table.add_column("Property", style="cyan")
        table.add_column("Value")
        table.add_row("Name", bp.name)
        table.add_row("Cost", f"{bp.cost} scrap")
        table.add_row("Max Health", str(bp.max_health))
        table.add_row("Move Speed", str(bp.move_speed))
        table.add_row("Repair Speed", str(bp.repair_speed))
        table.add_row("Damage Multiplier", f"{bp.damage_multiplier}x")
        table.add_row("Suffocation", "Immune" if bp.suffocation_modifier == 0 else f"{bp.suffocation_modifier}x")
        abilities = []
        if bp.provide_power:
            abilities.append("Provides power")
        if not bp.can_burn:
            abilities.append("Fire immune")
        if not bp.can_suffocate:
            abilities.append("No oxygen needed")
        if abilities:
            table.add_row("Special", ", ".join(abilities))
        table.add_row("Description", bp.desc[:80] + "..." if len(bp.desc) > 80 else bp.desc)
        console.print(table)
        xml = xml_builder.build_crew(bp)

    elif item_type == "ship":
        table = Table(title=f"Generated Ship: {bp.class_name}")
        table.add_column("Property", style="cyan")
        table.add_column("Value")
        table.add_row("Name", bp.name)
        table.add_row("Class", bp.class_name)
        table.add_row("Ship Name", bp.ship_name)
        table.add_row("Max Power", str(bp.max_power))
        table.add_row("Max Hull", str(bp.max_hull))
        table.add_row("Shields", str(bp.shields))
        table.add_row("Engines", str(bp.engines))
        table.add_row("Weapons", str(bp.weapons))
        table.add_row("Crew", ", ".join(bp.crew) if bp.crew else "None")
        table.add_row("Description", bp.desc[:80] + "..." if len(bp.desc) > 80 else bp.desc)
        console.print(table)

        console.print("\n[bold]Systems:[/]")
        systems = {
            "shields": bp.shields, "engines": bp.engines, "oxygen": bp.oxygen,
            "weapons": bp.weapons, "drones": bp.drones, "medbay": bp.medbay,
            "clonebay": bp.clonebay, "teleporter": bp.teleporter,
            "cloaking": bp.cloaking, "hacking": bp.hacking, "mind": bp.mind,
        }
        for sys_name, level in systems.items():
            if level > 0:
                console.print(f"  {sys_name}: {level}")
        return  # Ships don't have a simple XML build

    else:
        return

    console.print("\n[bold]XML Blueprint:[/]")
    console.print(etree.tostring(xml, pretty_print=True, encoding="unicode"))


def _prompt_content_counts() -> dict[str, int]:
    """Interactively prompt user for content counts."""
    console.print("\n[bold]What would you like to generate?[/]\n")

    counts = {}
    counts["weapons"] = typer.prompt("  Weapons (laser, beam, missile, etc.)", default=3, type=int)
    counts["events"] = typer.prompt("  Events (encounters with choices)", default=3, type=int)
    counts["drones"] = typer.prompt("  Drones (combat, defense, repair)", default=0, type=int)
    counts["augments"] = typer.prompt("  Augments (passive bonuses)", default=0, type=int)
    counts["crew"] = typer.prompt("  Crew races (custom species)", default=0, type=int)

    console.print()
    return counts


# --- Commands ---


@app.command()
def mod(
    theme: Annotated[str, typer.Argument(help="Theme or concept for the mod")],
    name: Annotated[Optional[str], typer.Option("--name", "-n", help="Mod name")] = None,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output directory")] = None,
    weapons: Annotated[Optional[int], typer.Option("--weapons", "-w", help="Number of weapons")] = None,
    events: Annotated[Optional[int], typer.Option("--events", "-e", help="Number of events")] = None,
    drones: Annotated[Optional[int], typer.Option("--drones", "-d", help="Number of drones")] = None,
    augments: Annotated[Optional[int], typer.Option("--augments", "-a", help="Number of augments")] = None,
    crew: Annotated[Optional[int], typer.Option("--crew", "-c", help="Number of crew races")] = None,
    sprites: Annotated[bool, typer.Option("--sprites/--no-sprites", help="Generate sprites")] = True,
    cache_images: Annotated[bool, typer.Option("--cache-images", help="Use cached images if available")] = False,
    validate: Annotated[bool, typer.Option("--validate", help="Validate with Slipstream")] = False,
    patch: Annotated[bool, typer.Option("--patch", help="Apply mod to game")] = False,
    run: Annotated[bool, typer.Option("--run", help="Launch FTL after patching")] = False,
    provider: Annotated[Optional[str], typer.Option("--provider", help="LLM provider (claude/openai)")] = None,
    chaos_level: Annotated[Optional[float], typer.Option("--chaos", help="Chaos level 0.0-1.0 (randomizes vanilla items)")] = None,
    seed: Annotated[Optional[int], typer.Option("--seed", help="Random seed for reproducible chaos")] = None,
    unsafe: Annotated[bool, typer.Option("--unsafe", help="Remove safety bounds (allow extreme values)")] = False,
    test_loadout: Annotated[bool, typer.Option("--test-loadout", help="Add modified Kestrel loadout with first weapon")] = False,
):
    """Generate a complete themed mod.

    Examples:
        ftl-gen mod "A faction of sentient crystals"
        ftl-gen mod "Space pirates" -w5 -e3 -d2
        ftl-gen mod "Chaos pirates" --chaos 0.7 -w2 -e0 --seed 12345
    """
    settings = get_settings()

    if all(x is None for x in [weapons, events, drones, augments, crew]):
        counts = _prompt_content_counts()
        weapons = counts["weapons"]
        events = counts["events"]
        drones = counts["drones"]
        augments = counts["augments"]
        crew = counts["crew"]
    else:
        weapons = weapons or 0
        events = events or 0
        drones = drones or 0
        augments = augments or 0
        crew = crew or 0

    if output:
        settings.output_dir = output
    if provider:
        settings.llm_provider = provider  # type: ignore

    console.print(Panel(f"[bold]Generating mod:[/] {theme}", title="FTL Mod Generator"))

    chaos_config = None
    if chaos_level is not None:
        if not 0.0 <= chaos_level <= 1.0:
            console.print("[red]Error: --chaos must be between 0.0 and 1.0[/]")
            raise typer.Exit(1)
        chaos_config = ChaosConfig(level=chaos_level, seed=seed, unsafe=unsafe)
        console.print(f"[dim]Chaos mode: level={chaos_level}, seed={seed or 'random'}, unsafe={unsafe}[/]")

    try:
        generator = ModGenerator(settings)
        ftl_path = generator.generate_mod(
            theme=theme,
            mod_name=name,
            num_weapons=weapons,
            num_events=events,
            num_drones=drones,
            num_augments=augments,
            num_crew=crew,
            generate_sprites=sprites,
            use_cached_images=cache_images,
            chaos_config=chaos_config,
            test_loadout=test_loadout,
        )

        _validate_patch_run(ftl_path, settings, validate, patch, run)

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@app.command()
def weapon(
    description: Annotated[str, typer.Argument(help="Weapon description or concept")],
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output directory")] = None,
):
    """Generate a single weapon.

    Example: ftl-gen weapon "A gravity beam that stuns crew"
    """
    try:
        bp = _generate_single_item(description, "weapon", output)
        _display_single_item("weapon", bp)
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@app.command()
def event(
    description: Annotated[str, typer.Argument(help="Event description or concept")],
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output directory")] = None,
):
    """Generate a single event.

    Example: ftl-gen event "A derelict ship with a mysterious cargo"
    """
    try:
        bp = _generate_single_item(description, "event", output)
        _display_single_item("event", bp)
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@app.command()
def ship(
    description: Annotated[str, typer.Argument(help="Ship description or concept")],
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output directory")] = None,
):
    """Generate a single ship blueprint.

    Example: ftl-gen ship "A stealth cruiser focused on cloaking and evasion"
    """
    try:
        bp = _generate_single_item(description, "ship", output)
        _display_single_item("ship", bp)
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@app.command()
def drone(
    description: Annotated[str, typer.Argument(help="Drone description or concept")],
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output directory")] = None,
):
    """Generate a single drone blueprint.

    Example: ftl-gen drone "A combat drone that focuses on shield damage"
    """
    try:
        bp = _generate_single_item(description, "drone", output)
        _display_single_item("drone", bp)
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@app.command()
def augment(
    description: Annotated[str, typer.Argument(help="Augment description or concept")],
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output directory")] = None,
):
    """Generate a single augment blueprint.

    Example: ftl-gen augment "An augment that increases weapon charge speed"
    """
    try:
        bp = _generate_single_item(description, "augment", output)
        _display_single_item("augment", bp)
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@app.command("crew-race")
def crew_race(
    description: Annotated[str, typer.Argument(help="Crew race description or concept")],
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output directory")] = None,
):
    """Generate a single crew race blueprint.

    Example: ftl-gen crew-race "A silicon-based lifeform immune to fire"
    """
    try:
        bp = _generate_single_item(description, "crew", output)
        _display_single_item("crew", bp)
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@app.command("patch")
def patch_mod(
    mod_name: Annotated[str, typer.Argument(help="Mod name or path to .ftl file")],
    run: Annotated[bool, typer.Option("--run", help="Launch FTL after patching")] = False,
):
    """Apply a mod to the game.

    Example: ftl-gen patch MyMod --run
    """
    settings = get_settings()
    slipstream = SlipstreamManager(settings)

    if not slipstream.is_available():
        console.print("[red]Slipstream not found. Please install it first.[/]")
        raise typer.Exit(1)

    mod_path = Path(mod_name)
    if not mod_path.exists():
        mod_path = settings.output_dir / f"{mod_name}.ftl"
    if not mod_path.exists():
        mod_path = settings.output_dir / mod_name
        if mod_path.is_dir():
            mod_path = settings.output_dir / f"{mod_name}.ftl"
    if not mod_path.exists():
        if slipstream.mods_dir:
            mod_path = slipstream.mods_dir / f"{mod_name}.ftl"

    if not mod_path.exists():
        console.print(f"[red]Mod not found: {mod_name}[/]")
        console.print(f"[dim]Searched in: {settings.output_dir}[/]")
        raise typer.Exit(1)

    console.print(f"[bold]Patching mod:[/] {mod_path}")

    if run:
        result = slipstream.patch_and_run([mod_path])
    else:
        result = slipstream.patch([mod_path])

    if result.success:
        console.print("[green]Success![/]")
    else:
        console.print(f"[red]Failed: {result.message}[/]")
        raise typer.Exit(1)


@app.command("validate")
def validate_mod(
    mod_path: Annotated[Path, typer.Argument(help="Path to .ftl mod file")],
):
    """Validate a mod using Slipstream.

    Example: ftl-gen validate output/MyMod.ftl
    """
    settings = get_settings()
    slipstream = SlipstreamManager(settings)

    if not slipstream.is_available():
        console.print("[red]Slipstream not found. Please install it first.[/]")
        raise typer.Exit(1)

    if not mod_path.exists():
        console.print(f"[red]File not found: {mod_path}[/]")
        raise typer.Exit(1)

    console.print(f"[bold]Validating:[/] {mod_path}")
    result = slipstream.validate(mod_path)

    if result.warnings:
        console.print("\n[yellow]Warnings:[/]")
        for warning in result.warnings:
            console.print(f"  - {warning}")

    if result.errors:
        console.print("\n[red]Errors:[/]")
        for error in result.errors:
            console.print(f"  - {error}")

    if result.ok:
        console.print("\n[green]Validation passed![/]")
    else:
        console.print("\n[red]Validation failed[/]")
        raise typer.Exit(1)


@app.command("list")
def list_mods(
    slipstream_mods: Annotated[bool, typer.Option("--slipstream", "-s", help="Show Slipstream mods instead")] = False,
):
    """List generated mods in the mods/ directory."""
    settings = get_settings()

    if slipstream_mods:
        slipstream = SlipstreamManager(settings)
        if not slipstream.is_available():
            console.print("[red]Slipstream not found.[/]")
            raise typer.Exit(1)

        mods = slipstream.list_mods()
        if not mods:
            console.print("[yellow]No mods in Slipstream directory[/]")
            return

        console.print("[bold]Slipstream mods:[/]")
        for m in mods:
            console.print(f"  {m}")
        return

    mods_dir = settings.output_dir
    if not mods_dir.exists():
        console.print(f"[yellow]Mods directory not found: {mods_dir}[/]")
        return

    ftl_files = sorted(mods_dir.glob("*.ftl"))
    mod_dirs = sorted([d for d in mods_dir.iterdir() if d.is_dir() and not d.name.startswith(".")])

    if not ftl_files and not mod_dirs:
        console.print("[yellow]No mods found. Generate one with:[/]")
        console.print("  ftl-gen mod \"your theme\"")
        return

    console.print(f"[bold]Generated mods ({mods_dir}):[/]")
    for ftl in ftl_files:
        size_kb = ftl.stat().st_size / 1024
        console.print(f"  {ftl.stem} [dim]({size_kb:.1f} KB)[/]")


@app.command()
def info():
    """Show configuration and status information."""
    settings = get_settings()
    slipstream = SlipstreamManager(settings)

    table = Table(title="FTL-Gen Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value")
    table.add_column("Status")

    llm_status = "[green]OK[/]" if settings.get_llm_api_key else "[red]Missing API Key[/]"
    table.add_row("LLM Provider", settings.llm_provider, llm_status)
    table.add_row("LLM Model", settings.llm_model, "")

    img_status = "[green]OK[/]" if settings.google_ai_api_key else "[yellow]Not configured[/]"
    table.add_row("Image Generation", settings.image_model, img_status)

    slip_status = "[green]Found[/]" if slipstream.is_available() else "[red]Not found[/]"
    slip_path = str(slipstream.path) if slipstream.path else "Not found"
    table.add_row("Slipstream", slip_path, slip_status)

    table.add_row("Output Directory", str(settings.output_dir), "")

    console.print(table)


@app.command()
def chaos(
    level: Annotated[float, typer.Option("--level", "-l", help="Chaos level 0.0-1.0")] = 0.5,
    seed: Annotated[Optional[int], typer.Option("--seed", "-s", help="Random seed for reproducibility")] = None,
    unsafe: Annotated[bool, typer.Option("--unsafe", help="Remove safety bounds")] = False,
    mutate_sprites: Annotated[bool, typer.Option("--mutate-sprites", help="Generate mutated placeholder sprites")] = False,
    name: Annotated[Optional[str], typer.Option("--name", "-n", help="Mod name")] = None,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output directory")] = None,
    validate: Annotated[bool, typer.Option("--validate", help="Validate with Slipstream")] = False,
    patch: Annotated[bool, typer.Option("--patch", help="Apply mod to game")] = False,
    run: Annotated[bool, typer.Option("--run", help="Launch FTL after patching")] = False,
    test_loadout: Annotated[bool, typer.Option("--test-loadout", help="Add modified Kestrel loadout with first weapon")] = False,
):
    """Generate a chaos-only mod (no LLM, $0.00 cost).

    Randomizes ALL vanilla weapons, drones, augments, and crew stats.
    Same names = overrides vanilla items when patched.

    Examples:
        ftl-gen chaos --level 0.5
        ftl-gen chaos --level 0.8 --seed 12345
        ftl-gen chaos --level 1.0 --unsafe --mutate-sprites --validate --patch --run
    """
    if not 0.0 <= level <= 1.0:
        console.print("[red]Error: --level must be between 0.0 and 1.0[/]")
        raise typer.Exit(1)

    settings = get_settings()
    if output:
        settings.output_dir = output

    mod_name = name or f"ChaosMode_{int(level * 100)}"

    console.print(Panel(
        f"[bold]Chaos Mode[/]\n"
        f"Level: {level} | Seed: {seed or 'random'} | Unsafe: {unsafe}",
        title="FTL Chaos Generator"
    ))
    console.print("[dim]Cost: $0.00 (no LLM calls)[/]\n")

    try:
        chaos_config = ChaosConfig(level=level, seed=seed, unsafe=unsafe)

        console.print("[bold]Randomizing vanilla items...[/]")
        chaos_result = randomize_all(chaos_config)

        console.print(f"  [green]Randomized {len(chaos_result.weapons)} weapons[/]")
        console.print(f"  [green]Randomized {len(chaos_result.drones)} drones[/]")
        console.print(f"  [green]Randomized {len(chaos_result.augments)} augments[/]")
        console.print(f"  [green]Randomized {len(chaos_result.crew)} crew races[/]")
        console.print(f"  [dim]Seed used: {chaos_result.seed_used}[/]")

        sprite_files: dict[str, bytes] = {}
        if mutate_sprites:
            console.print("\n[bold]Extracting and mutating vanilla sprites...[/]")

            extractor = VanillaSpriteExtractor()
            if not extractor.is_available:
                console.print("[yellow]Warning: Slipstream not found, cannot extract vanilla sprites[/]")
                console.print("[dim]Falling back to placeholder sprites[/]")
                from ftl_gen.images.sprites import SpriteProcessor
                sprite_processor = SpriteProcessor()
                sprite_mutator = SpriteMutator(level, seed)

                for w in chaos_result.weapons:
                    filename = f"{w.name.lower()}_strip12.png"
                    placeholder = sprite_processor.create_placeholder_sprite_sheet(w.name)
                    mutated = sprite_mutator.mutate_sprite(placeholder)
                    sprite_files[filename] = mutated
                    w.weapon_art = w.name.lower()

                console.print(f"  [yellow]Generated {len(sprite_files)} placeholder sprites[/]")
            else:
                import tempfile
                temp_dir = Path(tempfile.mkdtemp(prefix="ftl_chaos_"))
                console.print(f"  [dim]Extracting FTL resources to {temp_dir}...[/]")

                weapon_sprites, drone_sprites = mutate_vanilla_sprites(
                    chaos_level=level,
                    seed=seed,
                    slipstream_path=extractor.slipstream_path,
                    temp_dir=temp_dir,
                )

                for sprite_path, sprite_data in weapon_sprites.items():
                    sprite_files[sprite_path] = sprite_data
                for sprite_path, sprite_data in drone_sprites.items():
                    sprite_files[sprite_path] = sprite_data

                console.print(f"  [magenta]Mutated {len(weapon_sprites)} weapon sprites[/]")
                console.print(f"  [magenta]Mutated {len(drone_sprites)} drone sprites[/]")

        from ftl_gen.llm.parsers import build_mod_content

        content = build_mod_content(
            mod_name=mod_name,
            description=f"Chaos mode mod with {int(level * 100)}% randomization. Seed: {chaos_result.seed_used}",
            weapons=chaos_result.weapons,
            drones=chaos_result.drones,
            augments=chaos_result.augments,
            crew=chaos_result.crew,
            events=[],
        )

        mod_builder = ModBuilder(settings.output_dir)
        ftl_path = mod_builder.build(content, sprite_files if sprite_files else None, test_loadout=test_loadout)

        console.print(f"\n[bold green]Mod generated:[/] {ftl_path}")

        _validate_patch_run(ftl_path, settings, validate, patch, run)

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
