"""Full mod generation orchestrator."""

import hashlib
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ftl_gen.config import Settings, get_settings
from ftl_gen.core.mod_builder import ModBuilder
from ftl_gen.core.slipstream import SlipstreamManager
from ftl_gen.images.client import get_image_client
from ftl_gen.images.sprites import SpriteProcessor
from ftl_gen.llm.client import LLMClient
from ftl_gen.llm.parsers import (
    build_mod_content,
    parse_augments_response,
    parse_crew_races_response,
    parse_drones_response,
    parse_events_response,
    parse_mod_concept,
    parse_weapons_response,
)
from ftl_gen.llm.prompts import (
    SYSTEM_PROMPT,
    augments_prompt,
    crew_prompt,
    drones_prompt,
    events_prompt,
    mod_concept_prompt,
    weapons_prompt,
)
from ftl_gen.xml.schemas import (
    AugmentBlueprint,
    CrewBlueprint,
    DroneBlueprint,
    EventBlueprint,
    ShipBlueprint,
    WeaponBlueprint,
)

console = Console()


class ModGenerator:
    """Orchestrates complete mod generation from a theme."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.llm = LLMClient(self.settings)
        self.mod_builder = ModBuilder(self.settings.output_dir)
        self.slipstream = SlipstreamManager(self.settings)
        self.image_client = get_image_client(self.settings)
        self.sprite_processor = SpriteProcessor()

    def generate_mod(
        self,
        theme: str,
        mod_name: str | None = None,
        num_weapons: int = 3,
        num_events: int = 5,
        num_drones: int = 2,
        num_augments: int = 2,
        num_crew: int = 0,
        generate_sprites: bool = True,
        use_cached_images: bool = False,
    ) -> Path:
        """Generate a complete mod from a theme.

        Args:
            theme: Theme/concept for the mod
            mod_name: Optional mod name (auto-generated if not provided)
            num_weapons: Number of weapons to generate
            num_events: Number of events to generate
            num_drones: Number of drones to generate
            num_augments: Number of augments to generate
            num_crew: Number of crew races to generate (0 = none)
            generate_sprites: Whether to generate weapon sprites

        Returns:
            Path to generated .ftl file
        """
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            # Step 1: Expand concept
            task = progress.add_task("Expanding mod concept...", total=None)
            concept = self._expand_concept(theme)
            progress.update(task, completed=True)

            # Use generated name if not provided
            if not mod_name:
                mod_name = concept.get("name", "GeneratedMod")

            console.print(f"[bold blue]Generating mod:[/] {mod_name}")
            console.print(f"[dim]{concept.get('description', '')}[/dim]")

            # Step 2: Generate weapons
            task = progress.add_task(f"Generating {num_weapons} weapons...", total=None)
            weapons = self._generate_weapons(
                theme, concept.get("weapon_concepts", []), num_weapons
            )
            progress.update(task, completed=True)
            console.print(f"  [green]Generated {len(weapons)} weapons[/]")

            # Step 3: Generate drones
            drones: list[DroneBlueprint] = []
            if num_drones > 0:
                task = progress.add_task(f"Generating {num_drones} drones...", total=None)
                drones = self._generate_drones(
                    theme, concept.get("drone_concepts", []), num_drones
                )
                progress.update(task, completed=True)
                console.print(f"  [green]Generated {len(drones)} drones[/]")

            # Step 4: Generate augments
            augments: list[AugmentBlueprint] = []
            if num_augments > 0:
                task = progress.add_task(f"Generating {num_augments} augments...", total=None)
                augments = self._generate_augments(
                    theme, concept.get("augment_concepts", []), num_augments
                )
                progress.update(task, completed=True)
                console.print(f"  [green]Generated {len(augments)} augments[/]")

            # Step 5: Generate crew races
            crew: list[CrewBlueprint] = []
            if num_crew > 0:
                task = progress.add_task(f"Generating {num_crew} crew race(s)...", total=None)
                crew = self._generate_crew(
                    theme, concept.get("crew_concepts", []), num_crew
                )
                progress.update(task, completed=True)
                console.print(f"  [green]Generated {len(crew)} crew race(s)[/]")

            # Step 6: Generate events
            task = progress.add_task(f"Generating {num_events} events...", total=None)
            events = self._generate_events(
                theme, concept.get("event_concepts", []), num_events
            )
            progress.update(task, completed=True)
            console.print(f"  [green]Generated {len(events)} events[/]")

            # Step 7: Generate sprites
            sprite_files: dict[str, bytes] = {}
            if generate_sprites and weapons:
                task = progress.add_task("Generating weapon sprites...", total=None)
                sprite_files = self._generate_sprites(weapons, use_cached_images)
                progress.update(task, completed=True)
                console.print(f"  [green]Generated {len(sprite_files)} sprite sheets[/]")

                # Link weapon art to sprite animations
                for weapon in weapons:
                    weapon.weapon_art = weapon.name.lower()

            # Step 8: Build mod
            task = progress.add_task("Building mod package...", total=None)
            content = build_mod_content(
                mod_name=mod_name,
                description=concept.get("description", f"A mod based on: {theme}"),
                weapons=weapons,
                events=events,
                drones=drones,
                augments=augments,
                crew=crew,
            )
            ftl_path = self.mod_builder.build(content, sprite_files)
            progress.update(task, completed=True)

        console.print(f"\n[bold green]Mod generated:[/] {ftl_path}")

        # Show LLM usage and cost
        llm_usage = self.llm.usage.total
        img_usage = self.image_client.usage

        costs = []
        if llm_usage.total_tokens > 0:
            costs.append(f"LLM: {llm_usage.total_tokens:,} tokens · ${llm_usage.cost:.4f}")
        if img_usage.images_generated > 0:
            costs.append(f"Images: {img_usage.images_generated} · ${img_usage.total_cost:.4f}")

        total_cost = llm_usage.cost + img_usage.total_cost
        if costs:
            console.print(f"[dim]{' | '.join(costs)} | Total: ${total_cost:.4f}[/]")

        return ftl_path

    def _expand_concept(self, theme: str) -> dict[str, Any]:
        """Expand the theme into a detailed mod concept."""
        prompt = mod_concept_prompt(theme)
        response = self.llm.generate(prompt, system=SYSTEM_PROMPT)
        return parse_mod_concept(response)

    def _generate_weapons(
        self,
        theme: str,
        concepts: list[dict],
        count: int,
    ) -> list[WeaponBlueprint]:
        """Generate weapon blueprints."""
        # Ensure we have enough concepts
        while len(concepts) < count:
            concepts.append({
                "name": f"WEAPON_{len(concepts) + 1}",
                "type": "LASER",
                "concept": f"A themed weapon for {theme}",
            })

        prompt = weapons_prompt(theme, concepts, count)
        response = self.llm.generate(prompt, system=SYSTEM_PROMPT, max_tokens=4096)
        return parse_weapons_response(response)

    def _generate_events(
        self,
        theme: str,
        concepts: list[dict],
        count: int,
    ) -> list[EventBlueprint]:
        """Generate event blueprints."""
        # Ensure we have enough concepts
        while len(concepts) < count:
            concepts.append({
                "name": f"EVENT_{len(concepts) + 1}",
                "summary": f"An encounter related to {theme}",
            })

        prompt = events_prompt(theme, concepts, count)
        response = self.llm.generate(prompt, system=SYSTEM_PROMPT, max_tokens=8192)
        return parse_events_response(response)

    def _generate_drones(
        self,
        theme: str,
        concepts: list[dict],
        count: int,
    ) -> list[DroneBlueprint]:
        """Generate drone blueprints."""
        while len(concepts) < count:
            concepts.append({
                "name": f"DRONE_{len(concepts) + 1}",
                "type": "COMBAT",
                "concept": f"A themed drone for {theme}",
            })

        prompt = drones_prompt(theme, concepts, count)
        response = self.llm.generate(prompt, system=SYSTEM_PROMPT, max_tokens=4096)
        return parse_drones_response(response)

    def _generate_augments(
        self,
        theme: str,
        concepts: list[dict],
        count: int,
    ) -> list[AugmentBlueprint]:
        """Generate augment blueprints."""
        while len(concepts) < count:
            concepts.append({
                "name": f"AUGMENT_{len(concepts) + 1}",
                "concept": f"A themed augment for {theme}",
            })

        prompt = augments_prompt(theme, concepts, count)
        response = self.llm.generate(prompt, system=SYSTEM_PROMPT, max_tokens=4096)
        return parse_augments_response(response)

    def _generate_crew(
        self,
        theme: str,
        concepts: list[dict],
        count: int,
    ) -> list[CrewBlueprint]:
        """Generate crew race blueprints."""
        while len(concepts) < count:
            concepts.append({
                "name": f"crew_{len(concepts) + 1}",
                "concept": f"A themed crew race for {theme}",
            })

        prompt = crew_prompt(theme, concepts, count)
        response = self.llm.generate(prompt, system=SYSTEM_PROMPT, max_tokens=4096)
        return parse_crew_races_response(response)

    def _get_cache_dir(self) -> Path:
        """Get the image cache directory."""
        cache_dir = self.settings.output_dir / ".image_cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        return cache_dir

    def _get_cache_key(self, weapon: WeaponBlueprint) -> str:
        """Generate a cache key for a weapon sprite.

        Uses weapon type only so cache can be reused across different weapon names.
        This allows faster iteration when testing sprite processing.
        """
        return f"weapon_{weapon.type.lower()}"

    def _generate_sprites(
        self,
        weapons: list[WeaponBlueprint],
        use_cache: bool = False,
    ) -> dict[str, bytes]:
        """Generate sprite sheets for weapons."""
        sprite_files = {}
        cache_dir = self._get_cache_dir() if use_cache else None

        for weapon in weapons:
            filename = f"{weapon.name.lower()}_strip12.png"
            cache_key = self._get_cache_key(weapon) if use_cache else None
            cached_path = cache_dir / f"{cache_key}.png" if cache_dir and cache_key else None

            # Check cache first
            if cached_path and cached_path.exists():
                console.print(f"  [dim]Using cached sprite for {weapon.name}[/]")
                sprite_files[filename] = cached_path.read_bytes()
                continue

            try:
                # Generate base image
                image_data = self.image_client.generate_weapon_sprite(
                    weapon_name=weapon.name,
                    weapon_type=weapon.type,
                    description=weapon.desc,
                )

                # Create sprite sheet
                sheet_data = self.sprite_processor.create_weapon_sprite_sheet(image_data)

                # Cache the result
                if cached_path:
                    cached_path.write_bytes(sheet_data)

                sprite_files[filename] = sheet_data

            except Exception as e:
                console.print(f"[yellow]Warning: Could not generate sprite for {weapon.name}: {e}[/]")
                # Use placeholder
                sheet_data = self.sprite_processor.create_placeholder_sprite_sheet(weapon.name)
                sprite_files[filename] = sheet_data

        return sprite_files

    def generate_single_weapon(self, description: str) -> WeaponBlueprint:
        """Generate a single weapon from a description."""
        from ftl_gen.llm.parsers import parse_weapon_response
        from ftl_gen.llm.prompts import single_weapon_prompt

        prompt = single_weapon_prompt(description)
        response = self.llm.generate(prompt, system=SYSTEM_PROMPT)
        return parse_weapon_response(response)

    def generate_single_event(self, description: str) -> EventBlueprint:
        """Generate a single event from a description."""
        from ftl_gen.llm.parsers import parse_event_response
        from ftl_gen.llm.prompts import single_event_prompt

        prompt = single_event_prompt(description)
        response = self.llm.generate(prompt, system=SYSTEM_PROMPT)
        return parse_event_response(response)

    def generate_single_drone(self, description: str) -> DroneBlueprint:
        """Generate a single drone from a description."""
        from ftl_gen.llm.parsers import parse_drone_response
        from ftl_gen.llm.prompts import single_drone_prompt

        prompt = single_drone_prompt(description)
        response = self.llm.generate(prompt, system=SYSTEM_PROMPT)
        return parse_drone_response(response)

    def generate_single_augment(self, description: str) -> AugmentBlueprint:
        """Generate a single augment from a description."""
        from ftl_gen.llm.parsers import parse_augment_response
        from ftl_gen.llm.prompts import single_augment_prompt

        prompt = single_augment_prompt(description)
        response = self.llm.generate(prompt, system=SYSTEM_PROMPT)
        return parse_augment_response(response)

    def generate_single_crew(self, description: str) -> CrewBlueprint:
        """Generate a single crew race from a description."""
        from ftl_gen.llm.parsers import parse_crew_response
        from ftl_gen.llm.prompts import single_crew_prompt

        prompt = single_crew_prompt(description)
        response = self.llm.generate(prompt, system=SYSTEM_PROMPT)
        return parse_crew_response(response)

    def generate_single_ship(self, description: str) -> ShipBlueprint:
        """Generate a single ship from a description."""
        from ftl_gen.llm.parsers import parse_ship_response
        from ftl_gen.llm.prompts import single_ship_prompt

        prompt = single_ship_prompt(description)
        response = self.llm.generate(prompt, system=SYSTEM_PROMPT, max_tokens=4096)
        return parse_ship_response(response)

    def validate_mod(self, mod_path: Path) -> bool:
        """Validate a generated mod using Slipstream."""
        if not self.slipstream.is_available():
            console.print("[yellow]Slipstream not available, skipping validation[/]")
            return True

        result = self.slipstream.validate(mod_path)

        if result.warnings:
            for warning in result.warnings:
                console.print(f"[yellow]Warning: {warning}[/]")

        if result.errors:
            for error in result.errors:
                console.print(f"[red]Error: {error}[/]")

        return result.ok

    def patch_and_run(self, mod_path: Path) -> bool:
        """Apply mod and launch FTL."""
        if not self.slipstream.is_available():
            console.print("[red]Slipstream not available[/]")
            return False

        result = self.slipstream.patch_and_run([mod_path])

        if result.success:
            console.print("[green]FTL launched with mod applied[/]")
        else:
            console.print(f"[red]Failed: {result.message}[/]")

        return result.success
