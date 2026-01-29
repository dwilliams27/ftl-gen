"""CLI interface for FTL Mod Generator."""

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ftl_gen import __version__
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


def _prompt_content_counts() -> dict[str, int]:
    """Interactively prompt user for content counts."""
    console.print("\n[bold]What would you like to generate?[/]\n")

    counts = {}

    counts["weapons"] = typer.prompt(
        "  Weapons (laser, beam, missile, etc.)",
        default=3,
        type=int,
    )
    counts["events"] = typer.prompt(
        "  Events (encounters with choices)",
        default=3,
        type=int,
    )
    counts["drones"] = typer.prompt(
        "  Drones (combat, defense, repair)",
        default=0,
        type=int,
    )
    counts["augments"] = typer.prompt(
        "  Augments (passive bonuses)",
        default=0,
        type=int,
    )
    counts["crew"] = typer.prompt(
        "  Crew races (custom species)",
        default=0,
        type=int,
    )

    console.print()
    return counts


@app.command()
def mod(
    theme: Annotated[str, typer.Argument(help="Theme or concept for the mod")],
    name: Annotated[Optional[str], typer.Option("--name", "-n", help="Mod name")] = None,
    output: Annotated[
        Optional[Path], typer.Option("--output", "-o", help="Output directory")
    ] = None,
    weapons: Annotated[Optional[int], typer.Option("--weapons", "-w", help="Number of weapons")] = None,
    events: Annotated[Optional[int], typer.Option("--events", "-e", help="Number of events")] = None,
    drones: Annotated[Optional[int], typer.Option("--drones", "-d", help="Number of drones")] = None,
    augments: Annotated[Optional[int], typer.Option("--augments", "-a", help="Number of augments")] = None,
    crew: Annotated[Optional[int], typer.Option("--crew", "-c", help="Number of crew races")] = None,
    sprites: Annotated[bool, typer.Option("--sprites/--no-sprites", help="Generate sprites")] = True,
    validate: Annotated[bool, typer.Option("--validate", help="Validate with Slipstream")] = False,
    patch: Annotated[bool, typer.Option("--patch", help="Apply mod to game")] = False,
    run: Annotated[bool, typer.Option("--run", help="Launch FTL after patching")] = False,
    provider: Annotated[
        Optional[str], typer.Option("--provider", help="LLM provider (claude/openai)")
    ] = None,
):
    """Generate a complete themed mod.

    Examples:
        ftl-gen mod "A faction of sentient crystals"
        ftl-gen mod "Space pirates" -w5 -e3 -d2
    """
    settings = get_settings()

    # If no content counts specified, prompt interactively
    if all(x is None for x in [weapons, events, drones, augments, crew]):
        counts = _prompt_content_counts()
        weapons = counts["weapons"]
        events = counts["events"]
        drones = counts["drones"]
        augments = counts["augments"]
        crew = counts["crew"]
    else:
        # Use provided values, default to 0 for unspecified
        weapons = weapons if weapons is not None else 0
        events = events if events is not None else 0
        drones = drones if drones is not None else 0
        augments = augments if augments is not None else 0
        crew = crew if crew is not None else 0

    if output:
        settings.output_dir = output
    if provider:
        settings.llm_provider = provider  # type: ignore

    console.print(Panel(f"[bold]Generating mod:[/] {theme}", title="FTL Mod Generator"))

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
        )

        if validate:
            console.print("\n[bold]Validating mod...[/]")
            if generator.validate_mod(ftl_path):
                console.print("[green]Validation passed[/]")
            else:
                console.print("[red]Validation failed[/]")
                if not patch:
                    raise typer.Exit(1)

        if patch or run:
            console.print("\n[bold]Applying mod...[/]")
            if run:
                generator.patch_and_run(ftl_path)
            else:
                slipstream = SlipstreamManager(settings)
                result = slipstream.patch([ftl_path])
                if result.success:
                    console.print("[green]Mod applied successfully[/]")
                else:
                    console.print(f"[red]Failed to apply mod: {result.message}[/]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@app.command()
def weapon(
    description: Annotated[str, typer.Argument(help="Weapon description or concept")],
    output: Annotated[
        Optional[Path], typer.Option("--output", "-o", help="Output directory")
    ] = None,
):
    """Generate a single weapon.

    Example:
        ftl-gen weapon "A gravity beam that stuns crew"
    """
    settings = get_settings()
    if output:
        settings.output_dir = output

    try:
        generator = ModGenerator(settings)
        weapon_bp = generator.generate_single_weapon(description)

        # Display result
        table = Table(title=f"Generated Weapon: {weapon_bp.title}")
        table.add_column("Property", style="cyan")
        table.add_column("Value")

        table.add_row("Name", weapon_bp.name)
        table.add_row("Type", weapon_bp.type)
        table.add_row("Damage", str(weapon_bp.damage))
        table.add_row("Shots", str(weapon_bp.shots))
        table.add_row("Cooldown", f"{weapon_bp.cooldown}s")
        table.add_row("Power", str(weapon_bp.power))
        table.add_row("Cost", f"{weapon_bp.cost} scrap")
        table.add_row("Description", weapon_bp.desc)

        console.print(table)

        # Generate XML
        xml_builder = XMLBuilder()
        xml = xml_builder.build_weapon(weapon_bp)
        from lxml import etree
        console.print("\n[bold]XML Blueprint:[/]")
        console.print(etree.tostring(xml, pretty_print=True, encoding="unicode"))

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@app.command()
def event(
    description: Annotated[str, typer.Argument(help="Event description or concept")],
    output: Annotated[
        Optional[Path], typer.Option("--output", "-o", help="Output directory")
    ] = None,
):
    """Generate a single event.

    Example:
        ftl-gen event "A derelict ship with a mysterious cargo"
    """
    settings = get_settings()
    if output:
        settings.output_dir = output

    try:
        generator = ModGenerator(settings)
        event_bp = generator.generate_single_event(description)

        # Display result
        console.print(Panel(event_bp.text, title=f"Event: {event_bp.name}"))

        if event_bp.choices:
            console.print("\n[bold]Choices:[/]")
            for i, choice in enumerate(event_bp.choices, 1):
                req_str = f" [dim](requires: {choice.req})[/dim]" if choice.req else ""
                console.print(f"  {i}. {choice.text}{req_str}")
                if choice.event and choice.event.text:
                    console.print(f"     [dim]→ {choice.event.text[:100]}...[/dim]")

        # Generate XML
        xml_builder = XMLBuilder()
        xml = xml_builder.build_event(event_bp)
        from lxml import etree
        console.print("\n[bold]XML Blueprint:[/]")
        console.print(etree.tostring(xml, pretty_print=True, encoding="unicode"))

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@app.command()
def ship(
    description: Annotated[str, typer.Argument(help="Ship description or concept")],
    output: Annotated[
        Optional[Path], typer.Option("--output", "-o", help="Output directory")
    ] = None,
):
    """Generate a single ship blueprint.

    Example:
        ftl-gen ship "A stealth cruiser focused on cloaking and evasion"
    """
    settings = get_settings()
    if output:
        settings.output_dir = output

    try:
        generator = ModGenerator(settings)
        ship_bp = generator.generate_single_ship(description)

        # Display result
        table = Table(title=f"Generated Ship: {ship_bp.class_name}")
        table.add_column("Property", style="cyan")
        table.add_column("Value")

        table.add_row("Name", ship_bp.name)
        table.add_row("Class", ship_bp.class_name)
        table.add_row("Ship Name", ship_bp.ship_name)
        table.add_row("Max Power", str(ship_bp.max_power))
        table.add_row("Max Hull", str(ship_bp.max_hull))
        table.add_row("Shields", str(ship_bp.shields))
        table.add_row("Engines", str(ship_bp.engines))
        table.add_row("Weapons", str(ship_bp.weapons))
        table.add_row("Crew", ", ".join(ship_bp.crew) if ship_bp.crew else "None")
        table.add_row("Description", ship_bp.desc[:80] + "..." if len(ship_bp.desc) > 80 else ship_bp.desc)

        console.print(table)

        # Show systems
        console.print("\n[bold]Systems:[/]")
        systems = {
            "shields": ship_bp.shields, "engines": ship_bp.engines, "oxygen": ship_bp.oxygen,
            "weapons": ship_bp.weapons, "drones": ship_bp.drones, "medbay": ship_bp.medbay,
            "clonebay": ship_bp.clonebay, "teleporter": ship_bp.teleporter,
            "cloaking": ship_bp.cloaking, "hacking": ship_bp.hacking, "mind": ship_bp.mind,
        }
        active_systems = {k: v for k, v in systems.items() if v > 0}
        for sys_name, level in active_systems.items():
            console.print(f"  {sys_name}: {level}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@app.command()
def drone(
    description: Annotated[str, typer.Argument(help="Drone description or concept")],
    output: Annotated[
        Optional[Path], typer.Option("--output", "-o", help="Output directory")
    ] = None,
):
    """Generate a single drone blueprint.

    Example:
        ftl-gen drone "A combat drone that focuses on shield damage"
    """
    settings = get_settings()
    if output:
        settings.output_dir = output

    try:
        generator = ModGenerator(settings)
        drone_bp = generator.generate_single_drone(description)

        # Display result
        table = Table(title=f"Generated Drone: {drone_bp.title}")
        table.add_column("Property", style="cyan")
        table.add_column("Value")

        table.add_row("Name", drone_bp.name)
        table.add_row("Type", drone_bp.type)
        table.add_row("Power", str(drone_bp.power))
        table.add_row("Cost", f"{drone_bp.cost} scrap")
        if drone_bp.cooldown:
            table.add_row("Cooldown", f"{drone_bp.cooldown}s")
        if drone_bp.speed:
            table.add_row("Speed", str(drone_bp.speed))
        table.add_row("Description", drone_bp.desc)

        console.print(table)

        # Generate XML
        xml_builder = XMLBuilder()
        xml = xml_builder.build_drone(drone_bp)
        from lxml import etree
        console.print("\n[bold]XML Blueprint:[/]")
        console.print(etree.tostring(xml, pretty_print=True, encoding="unicode"))

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@app.command()
def augment(
    description: Annotated[str, typer.Argument(help="Augment description or concept")],
    output: Annotated[
        Optional[Path], typer.Option("--output", "-o", help="Output directory")
    ] = None,
):
    """Generate a single augment blueprint.

    Example:
        ftl-gen augment "An augment that increases weapon charge speed"
    """
    settings = get_settings()
    if output:
        settings.output_dir = output

    try:
        generator = ModGenerator(settings)
        aug_bp = generator.generate_single_augment(description)

        # Display result
        table = Table(title=f"Generated Augment: {aug_bp.title}")
        table.add_column("Property", style="cyan")
        table.add_column("Value")

        table.add_row("Name", aug_bp.name)
        table.add_row("Cost", f"{aug_bp.cost} scrap")
        table.add_row("Rarity", str(aug_bp.rarity))
        table.add_row("Stackable", "Yes" if aug_bp.stackable else "No")
        if aug_bp.value is not None:
            table.add_row("Value", str(aug_bp.value))
        table.add_row("Description", aug_bp.desc)

        console.print(table)

        # Generate XML
        xml_builder = XMLBuilder()
        xml = xml_builder.build_augment(aug_bp)
        from lxml import etree
        console.print("\n[bold]XML Blueprint:[/]")
        console.print(etree.tostring(xml, pretty_print=True, encoding="unicode"))

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@app.command("crew-race")
def crew_race(
    description: Annotated[str, typer.Argument(help="Crew race description or concept")],
    output: Annotated[
        Optional[Path], typer.Option("--output", "-o", help="Output directory")
    ] = None,
):
    """Generate a single crew race blueprint.

    Example:
        ftl-gen crew-race "A silicon-based lifeform immune to fire"
    """
    settings = get_settings()
    if output:
        settings.output_dir = output

    try:
        generator = ModGenerator(settings)
        crew_bp = generator.generate_single_crew(description)

        # Display result
        table = Table(title=f"Generated Crew Race: {crew_bp.title}")
        table.add_column("Property", style="cyan")
        table.add_column("Value")

        table.add_row("Name", crew_bp.name)
        table.add_row("Cost", f"{crew_bp.cost} scrap")
        table.add_row("Max Health", str(crew_bp.max_health))
        table.add_row("Move Speed", str(crew_bp.move_speed))
        table.add_row("Repair Speed", str(crew_bp.repair_speed))
        table.add_row("Damage Multiplier", f"{crew_bp.damage_multiplier}x")
        table.add_row("Suffocation", "Immune" if crew_bp.suffocation_modifier == 0 else f"{crew_bp.suffocation_modifier}x")

        # Special abilities
        abilities = []
        if crew_bp.provide_power:
            abilities.append("Provides power")
        if not crew_bp.can_burn:
            abilities.append("Fire immune")
        if not crew_bp.can_suffocate:
            abilities.append("No oxygen needed")
        if abilities:
            table.add_row("Special", ", ".join(abilities))

        table.add_row("Description", crew_bp.desc[:80] + "..." if len(crew_bp.desc) > 80 else crew_bp.desc)

        console.print(table)

        # Generate XML
        xml_builder = XMLBuilder()
        xml = xml_builder.build_crew(crew_bp)
        from lxml import etree
        console.print("\n[bold]XML Blueprint:[/]")
        console.print(etree.tostring(xml, pretty_print=True, encoding="unicode"))

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@app.command("patch")
def patch_mod(
    mod_name: Annotated[str, typer.Argument(help="Mod name or path to .ftl file")],
    run: Annotated[bool, typer.Option("--run", help="Launch FTL after patching")] = False,
):
    """Apply a mod to the game.

    Example:
        ftl-gen patch MyMod --run
    """
    settings = get_settings()
    slipstream = SlipstreamManager(settings)

    if not slipstream.is_available():
        console.print("[red]Slipstream not found. Please install it first.[/]")
        raise typer.Exit(1)

    # Find mod file - check mods/ directory first
    mod_path = Path(mod_name)
    if not mod_path.exists():
        # Try mods directory (default)
        mod_path = settings.output_dir / f"{mod_name}.ftl"
    if not mod_path.exists():
        # Try without .ftl extension
        mod_path = settings.output_dir / mod_name
        if mod_path.is_dir():
            mod_path = settings.output_dir / f"{mod_name}.ftl"
    if not mod_path.exists():
        # Try Slipstream mods directory
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

    Example:
        ftl-gen validate output/MyMod.ftl
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
        for mod in mods:
            console.print(f"  {mod}")
        return

    # List local mods
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

    # LLM Provider
    llm_status = "[green]OK[/]" if settings.get_llm_api_key else "[red]Missing API Key[/]"
    table.add_row("LLM Provider", settings.llm_provider, llm_status)
    table.add_row("LLM Model", settings.llm_model, "")

    # Image Generation
    img_status = "[green]OK[/]" if settings.google_ai_api_key else "[yellow]Not configured[/]"
    table.add_row("Image Generation", settings.image_model, img_status)

    # Slipstream
    slip_status = "[green]Found[/]" if slipstream.is_available() else "[red]Not found[/]"
    slip_path = str(slipstream.path) if slipstream.path else "Not found"
    table.add_row("Slipstream", slip_path, slip_status)

    # Output
    table.add_row("Output Directory", str(settings.output_dir), "")

    console.print(table)


if __name__ == "__main__":
    app()
