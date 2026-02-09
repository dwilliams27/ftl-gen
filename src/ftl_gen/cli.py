"""CLI interface for FTL Mod Generator."""

from pathlib import Path
from typing import Annotated, Optional

import typer
from lxml import etree
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ftl_gen import __version__
from ftl_gen.chaos import ChaosConfig, randomize_all
from ftl_gen.config import Settings, get_settings
from ftl_gen.core.generator import ModGenerator
from ftl_gen.core.mod_builder import ModBuilder
from ftl_gen.core.slipstream import SlipstreamManager
from ftl_gen.xml.builders import XMLBuilder
from ftl_gen.xml.validators import (
    XMLValidator,
    check_common_crash_patterns,
    check_dangling_references,
    detect_event_loops,
)

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

        # Run event loop detection on the mod's events XML
        mod_dir = ftl_path.parent / ftl_path.stem
        events_file = mod_dir / "data" / "events.xml.append"
        blueprints_file = mod_dir / "data" / "blueprints.xml.append"

        events_xml = events_file.read_text() if events_file.exists() else None
        blueprints_xml = blueprints_file.read_text() if blueprints_file.exists() else None

        if events_xml:
            cycles = detect_event_loops(events_xml)
            if cycles:
                console.print("[red bold]Event loops detected (will freeze the game!):[/]")
                for cycle in cycles:
                    console.print(f"  [red]{' -> '.join(cycle)}[/]")
                if not patch:
                    raise typer.Exit(1)

        crash_patterns = check_common_crash_patterns(blueprints_xml, events_xml)
        if crash_patterns:
            console.print("[yellow]Potential crash patterns found:[/]")
            for pattern in crash_patterns:
                console.print(f"  [yellow]{pattern}[/]")

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
    test_weapon: Annotated[bool, typer.Option("--test-weapon", help="Replace Engi A weapon with first mod weapon")] = False,
    test_drone: Annotated[bool, typer.Option("--test-drone", help="Replace Engi A drone with first mod drone")] = False,
    test_augment: Annotated[bool, typer.Option("--test-augment", help="Replace Engi A augment with first mod augment")] = False,
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
            test_weapon=test_weapon,
            test_drone=test_drone,
            test_augment=test_augment,
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


def _rebuild_mod(
    mod_name: str,
    mods_dir: Path,
    *,
    test_weapon: bool = False,
    test_drone: bool = False,
    test_augment: bool = False,
) -> Path:
    """Rebuild a mod's .ftl from its directory sources.

    Always rebuilds so the .ftl reflects the current build pipeline.
    """
    from ftl_gen.api.services import ModReader
    from ftl_gen.llm.parsers import build_mod_content

    reader = ModReader(mods_dir)
    mod = reader.get_mod(mod_name)
    if not mod:
        console.print(f"[red]Mod not found: {mod_name}[/]")
        raise typer.Exit(1)

    # Collect sprite files, converting old drone sheets and ensuring
    # all three body images exist (_base, _on, _charged)
    sprite_files = {}
    for sprite_path in mod.sprite_files:
        data = reader.get_sprite_data(mod_name, sprite_path)
        if not data:
            continue
        if sprite_path.startswith("drones/") and sprite_path.endswith("_sheet.png"):
            from ftl_gen.images.sprites import SpriteProcessor
            proc = SpriteProcessor()
            drone_name = sprite_path.replace("drones/", "").replace("_sheet.png", "")
            try:
                body = proc.create_drone_body_images(data)
                for suffix, img_data in body.items():
                    sprite_files[f"ship/drones/{drone_name}{suffix}.png"] = img_data
            except Exception:
                pass
        else:
            sprite_files[sprite_path] = data

    # Ensure _charged.png exists for any drone that has _base.png
    from ftl_gen.images.sprites import SpriteProcessor
    base_drones = [p.replace("ship/drones/", "").replace("_base.png", "")
                   for p in sprite_files if p.endswith("_base.png") and p.startswith("ship/drones/")]
    for drone_name in base_drones:
        charged_key = f"ship/drones/{drone_name}_charged.png"
        if charged_key not in sprite_files:
            base_key = f"ship/drones/{drone_name}_base.png"
            proc = SpriteProcessor()
            body = proc.create_drone_body_images(sprite_files[base_key])
            sprite_files[charged_key] = body["_charged"]

    content = build_mod_content(
        mod_name=mod_name,
        description=mod.description,
        weapons=mod.weapons,
        drones=mod.drones,
        augments=mod.augments,
        crew=mod.crew,
        events=mod.events,
    )

    builder = ModBuilder(mods_dir)
    return builder.build(
        content, sprite_files or None,
        test_weapon=test_weapon, test_drone=test_drone, test_augment=test_augment,
    )


@app.command("patch")
def patch_mod(
    mod_name: Annotated[str, typer.Argument(help="Mod name or path to .ftl file")],
    run: Annotated[bool, typer.Option("--run", help="Launch FTL after patching")] = False,
    test_weapon: Annotated[bool, typer.Option("--test-weapon", help="Replace Engi A weapon with first mod weapon")] = False,
    test_drone: Annotated[bool, typer.Option("--test-drone", help="Replace Engi A drone with first mod drone")] = False,
    test_augment: Annotated[bool, typer.Option("--test-augment", help="Replace Engi A augment with first mod augment")] = False,
):
    """Apply a mod to the game. Always rebuilds the .ftl first.

    Example: ftl-gen patch MyMod --run --test-weapon --test-drone
    """
    settings = get_settings()
    slipstream = SlipstreamManager(settings)

    if not slipstream.is_available():
        console.print("[red]Slipstream not found. Please install it first.[/]")
        raise typer.Exit(1)

    # Find the mod — check mods_dir for directory or .ftl
    mods_dir = settings.output_dir
    mod_dir = mods_dir / mod_name
    ftl_path = mods_dir / f"{mod_name}.ftl"

    if not mod_dir.is_dir() and not ftl_path.exists():
        # Try slipstream mods dir
        if slipstream.mods_dir:
            mods_dir = slipstream.mods_dir
            mod_dir = mods_dir / mod_name
            ftl_path = mods_dir / f"{mod_name}.ftl"

    if not mod_dir.is_dir() and not ftl_path.exists():
        console.print(f"[red]Mod not found: {mod_name}[/]")
        console.print(f"[dim]Searched in: {settings.output_dir}[/]")
        raise typer.Exit(1)

    # Always rebuild to pick up latest build pipeline changes
    console.print(f"[bold]Rebuilding mod:[/] {mod_name}")
    mod_path = _rebuild_mod(
        mod_name, mods_dir,
        test_weapon=test_weapon, test_drone=test_drone, test_augment=test_augment,
    )
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
def ui(
    port: Annotated[int, typer.Option("--port", "-p", help="Port to serve on")] = 8421,
    dev: Annotated[bool, typer.Option("--dev", help="Development mode (CORS + reload + Vite HMR)")] = False,
    host: Annotated[str, typer.Option("--host", help="Host to bind to")] = "127.0.0.1",
):
    """Launch the web UI.

    In dev mode, starts both the Python API server (with auto-reload) and
    the Vite dev server (with HMR) in a single command.

    Examples:
        ftl-gen ui                # Production: serve built SPA on :8421
        ftl-gen ui --dev          # Dev: API on :8421 + Vite HMR on :5173
        ftl-gen ui --port 9000    # Custom API port
    """
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        console.print("[red]Web UI dependencies not installed.[/]")
        console.print("Install with: [bold]pip install -e \".[ui]\"[/]")
        raise typer.Exit(1)

    if dev:
        _ui_dev(host, port)
    else:
        _ui_prod(host, port)


def _ui_prod(host: str, port: int):
    """Start production server serving built SPA + API."""
    import uvicorn

    from ftl_gen.api.app import create_app

    app_instance = create_app(dev=False)
    console.print(f"[bold green]FTL-Gen Web UI[/] http://{host}:{port}")
    console.print(f"[dim]API docs: http://{host}:{port}/api/docs[/]")
    uvicorn.run(app_instance, host=host, port=port, log_level="info")


def _ui_dev(host: str, port: int):
    """Start dev mode: uvicorn with reload + Vite dev server."""
    import signal
    import subprocess
    import sys
    import threading

    # Find ui/ directory (sibling to src/)
    ui_dir = Path(__file__).resolve().parent.parent.parent / "ui"
    if not (ui_dir / "package.json").exists():
        console.print(f"[red]ui/ directory not found at {ui_dir}[/]")
        console.print("[dim]Run from the project root.[/]")
        raise typer.Exit(1)

    src_dir = str(Path(__file__).resolve().parent.parent)

    console.print("[bold green]FTL-Gen Dev Mode[/]")
    console.print(f"  [cyan]API:[/]      http://{host}:{port}  (auto-reload)")
    console.print(f"  [magenta]Frontend:[/] http://localhost:5173  (Vite HMR)")
    console.print(f"  [dim]API docs:  http://{host}:{port}/api/docs[/]")
    console.print()

    procs: list[subprocess.Popen] = []

    def stream_output(proc: subprocess.Popen, prefix: str, color: str):
        """Stream subprocess output with a colored prefix."""
        assert proc.stdout is not None
        for line in proc.stdout:
            text = line.decode("utf-8", errors="replace").rstrip()
            if text:
                console.print(f"[{color}]{prefix}[/] {text}")

    def shutdown(*_args):
        for p in procs:
            try:
                p.terminate()
            except OSError:
                pass
        # Give them a moment, then force
        for p in procs:
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Start uvicorn with --reload
    api_proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            "ftl_gen.api.app:create_dev_app",
            "--factory",
            "--host", host,
            "--port", str(port),
            "--reload",
            "--reload-dir", src_dir,
            "--log-level", "warning",
            "--header", "X-Dev-Mode:true",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    procs.append(api_proc)

    # Start Vite dev server
    vite_proc = subprocess.Popen(
        ["npm", "run", "dev"],
        cwd=str(ui_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    procs.append(vite_proc)

    # Stream output from both in background threads
    api_thread = threading.Thread(
        target=stream_output, args=(api_proc, "api", "cyan"), daemon=True
    )
    vite_thread = threading.Thread(
        target=stream_output, args=(vite_proc, "vite", "magenta"), daemon=True
    )
    api_thread.start()
    vite_thread.start()

    # Wait for either to exit
    while True:
        for p in procs:
            ret = p.poll()
            if ret is not None:
                name = "API" if p is api_proc else "Vite"
                console.print(f"\n[yellow]{name} process exited (code {ret})[/]")
                shutdown()
        try:
            threading.Event().wait(0.5)
        except KeyboardInterrupt:
            shutdown()


@app.command()
def chaos(
    level: Annotated[float, typer.Option("--level", "-l", help="Chaos level 0.0-1.0")] = 0.5,
    seed: Annotated[Optional[int], typer.Option("--seed", "-s", help="Random seed for reproducibility")] = None,
    unsafe: Annotated[bool, typer.Option("--unsafe", help="Remove safety bounds")] = False,
    name: Annotated[Optional[str], typer.Option("--name", "-n", help="Mod name")] = None,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output directory")] = None,
    validate: Annotated[bool, typer.Option("--validate", help="Validate with Slipstream")] = False,
    patch: Annotated[bool, typer.Option("--patch", help="Apply mod to game")] = False,
    run: Annotated[bool, typer.Option("--run", help="Launch FTL after patching")] = False,
    test_weapon: Annotated[bool, typer.Option("--test-weapon", help="Replace Engi A weapon with first chaos weapon")] = False,
    test_drone: Annotated[bool, typer.Option("--test-drone", help="Replace Engi A drone with first chaos drone")] = False,
    test_augment: Annotated[bool, typer.Option("--test-augment", help="Replace Engi A augment with first chaos augment")] = False,
):
    """Generate a chaos-only mod (no LLM, $0.00 cost).

    Randomizes ALL vanilla weapons, drones, augments, and crew stats.
    Same names = overrides vanilla items when patched.

    Examples:
        ftl-gen chaos --level 0.5
        ftl-gen chaos --level 0.8 --seed 12345
        ftl-gen chaos --level 1.0 --unsafe --validate --patch --run
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
        ftl_path = mod_builder.build(
            content,
            test_weapon=test_weapon, test_drone=test_drone, test_augment=test_augment,
        )

        console.print(f"\n[bold green]Mod generated:[/] {ftl_path}")

        _validate_patch_run(ftl_path, settings, validate, patch, run)

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@app.command()
def extract(
    source: Annotated[Path, typer.Option("--source", "-s", help="Path to Slipstream-extracted directory")] = Path("slipstream-extract"),
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output path for vanilla_reference.json")] = None,
):
    """Extract vanilla game data into vanilla_reference.json.

    Parses blueprints.xml + dlcBlueprints.xml from a Slipstream-extracted
    FTL data directory and writes a comprehensive reference file.

    Examples:
        ftl-gen extract --source slipstream-extract/
        ftl-gen extract --source /path/to/extract --output custom_ref.json
    """
    from ftl_gen.data.extractor import extract_vanilla_data, write_vanilla_reference

    if not source.exists():
        console.print(f"[red]Source directory not found: {source}[/]")
        console.print("[dim]Extract FTL data with Slipstream first[/]")
        raise typer.Exit(1)

    try:
        console.print(f"[bold]Extracting vanilla data from:[/] {source}")
        data = extract_vanilla_data(source)

        n_weapons = len(data["weapons"])
        n_drones = len(data["drones"])
        n_augments = len(data["augments"])
        n_crew = len(data["crew"])
        n_ships = len(data["ships"])
        n_lists = len(data["blueprint_lists"])

        console.print(f"  [green]Weapons:[/] {n_weapons}")
        console.print(f"  [green]Drones:[/] {n_drones}")
        console.print(f"  [green]Augments:[/] {n_augments}")
        console.print(f"  [green]Crew:[/] {n_crew}")
        console.print(f"  [green]Ships:[/] {n_ships}")
        console.print(f"  [green]Blueprint lists:[/] {n_lists}")

        out_path = write_vanilla_reference(data, output)
        console.print(f"\n[bold green]Written to:[/] {out_path}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@app.command("diagnose")
def diagnose_mod(
    mod_name: Annotated[str, typer.Argument(help="Mod name")],
    launch: Annotated[bool, typer.Option("--launch", help="Patch, launch FTL, and monitor")] = False,
):
    """Run diagnostic checks on a mod.

    Checks for event loops, dangling references, and crash patterns.

    Examples:
        ftl-gen diagnose "My Mod"
        ftl-gen diagnose "My Mod" --launch
    """
    settings = get_settings()
    mod_path = settings.output_dir / f"{mod_name}.ftl"
    mod_dir = settings.output_dir / mod_name

    if not mod_path.exists() and not mod_dir.exists():
        console.print(f"[red]Mod not found: {mod_name}[/]")
        raise typer.Exit(1)

    console.print(f"[bold]Diagnosing:[/] {mod_name}\n")

    events_file = mod_dir / "data" / "events.xml.append"
    blueprints_file = mod_dir / "data" / "blueprints.xml.append"

    events_xml = events_file.read_text() if events_file.exists() else None
    blueprints_xml = blueprints_file.read_text() if blueprints_file.exists() else None

    all_ok = True

    # Event loops
    if events_xml:
        cycles = detect_event_loops(events_xml)
        if cycles:
            console.print("[red]FAIL[/] Event loop detection")
            for cycle in cycles:
                console.print(f"  [red]{' -> '.join(cycle)}[/]")
            all_ok = False
        else:
            console.print("[green]PASS[/] No event loops")

        dangling = check_dangling_references(events_xml)
        if dangling:
            console.print("[yellow]WARN[/] Dangling event references")
            for d in dangling:
                console.print(f"  [yellow]{d}[/]")
        else:
            console.print("[green]PASS[/] No dangling references")
    else:
        console.print("[dim]SKIP[/] No events file")

    # Crash patterns
    crash_patterns = check_common_crash_patterns(blueprints_xml, events_xml)
    if crash_patterns:
        console.print("[red]FAIL[/] Crash pattern check")
        for pattern in crash_patterns:
            console.print(f"  [red]{pattern}[/]")
        all_ok = False
    else:
        console.print("[green]PASS[/] No crash patterns")

    # XML validation
    validator = XMLValidator()
    if blueprints_file.exists():
        result = validator.validate_file(blueprints_file)
        if result.ok:
            console.print("[green]PASS[/] Blueprints XML valid")
        else:
            console.print("[red]FAIL[/] Blueprints XML invalid")
            for err in result.errors:
                console.print(f"  [red]{err}[/]")
            all_ok = False

    if all_ok:
        console.print("\n[bold green]All checks passed![/]")
    else:
        console.print("\n[bold red]Some checks failed[/]")

    if launch:
        console.print("\n[bold]Patching and launching...[/]")
        slipstream = SlipstreamManager(settings)
        if not slipstream.is_available():
            console.print("[red]Slipstream not available[/]")
            raise typer.Exit(1)
        result = slipstream.patch_and_run([mod_path])
        if result.success:
            console.print("[green]Launched successfully[/]")
        else:
            console.print(f"[red]Failed: {result.message}[/]")
            raise typer.Exit(1)


if __name__ == "__main__":
    app()
