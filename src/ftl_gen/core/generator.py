"""Full mod generation orchestrator."""

from collections.abc import Callable
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ftl_gen.chaos import ChaosConfig, SpriteMutator, randomize_all
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

    def _save_partial(
        self,
        mod_name: str,
        description: str,
        weapons: list[WeaponBlueprint] | None = None,
        events: list[EventBlueprint] | None = None,
        drones: list[DroneBlueprint] | None = None,
        augments: list[AugmentBlueprint] | None = None,
        crew: list[CrewBlueprint] | None = None,
        sprite_files: dict[str, bytes] | None = None,
        *,
        test_loadout: bool = False,
    ) -> Path:
        """Save current progress as a partial mod.

        Called after each generation step to preserve work in case of later failure.
        """
        content = build_mod_content(
            mod_name=mod_name,
            description=description,
            weapons=weapons or [],
            events=events or [],
            drones=drones or [],
            augments=augments or [],
            crew=crew or [],
        )
        return self.mod_builder.build(content, sprite_files, test_loadout=test_loadout)

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
        chaos_config: ChaosConfig | None = None,
        test_loadout: bool = False,
        progress_callback: Callable[..., None] | None = None,
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
            use_cached_images: Whether to use cached sprite images
            chaos_config: Optional chaos configuration for randomizing vanilla items
            test_loadout: If True, add a modified Kestrel loadout with the first weapon

        Returns:
            Path to generated .ftl file
        """
        total_llm_content = num_weapons + num_events + num_drones + num_augments + num_crew

        def _notify(step: str, status: str, **kwargs):
            if progress_callback:
                progress_callback(step, status, **kwargs)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            # Step 0: Apply chaos to vanilla items if configured
            chaos_weapons: list[WeaponBlueprint] = []
            chaos_drones: list[DroneBlueprint] = []
            chaos_augments: list[AugmentBlueprint] = []
            chaos_crew: list[CrewBlueprint] = []

            if chaos_config:
                _notify("chaos", "started")
                task = progress.add_task("Applying chaos to vanilla items...", total=None)
                chaos_result = randomize_all(chaos_config)
                chaos_weapons = chaos_result.weapons
                chaos_drones = chaos_result.drones
                chaos_augments = chaos_result.augments
                chaos_crew = chaos_result.crew
                progress.remove_task(task)
                console.print(f"  [magenta]Chaotified {len(chaos_weapons)} weapons, {len(chaos_drones)} drones, {len(chaos_augments)} augments, {len(chaos_crew)} crew[/]")
                console.print(f"  [dim]Chaos seed: {chaos_result.seed_used}[/]")
                _notify("chaos", "completed")

            # Step 1: Expand concept (skip if no LLM content requested - saves an LLM call)
            if total_llm_content > 0:
                _notify("concept", "started")
                task = progress.add_task("Expanding mod concept...", total=None)
                concept = self._expand_concept(theme)
                progress.remove_task(task)
                _notify("concept", "completed")
            else:
                concept = {}

            # Use generated name if not provided
            if not mod_name:
                mod_name = concept.get("name", "GeneratedMod")
            description = concept.get("description", f"A mod based on: {theme}")
            if chaos_config:
                description += f" [Chaos mode: {int(chaos_config.level * 100)}%]"

            console.print(f"[bold blue]Generating mod:[/] {mod_name}")
            console.print(f"[dim]{description}[/dim]")

            # Track LLM-generated content separately from chaos content
            llm_weapons: list[WeaponBlueprint] = []
            llm_drones: list[DroneBlueprint] = []
            llm_augments: list[AugmentBlueprint] = []
            llm_crew: list[CrewBlueprint] = []
            events: list[EventBlueprint] = []

            # Step 2: Generate LLM content
            if num_weapons > 0:
                _notify("weapons", "started")
                task = progress.add_task(f"Generating {num_weapons} weapons...", total=None)
                llm_weapons = self._generate_weapons(
                    theme, concept.get("weapon_concepts", []), num_weapons
                )
                progress.remove_task(task)
                console.print(f"  [green]Generated {len(llm_weapons)} new weapons[/]")
                _notify("weapons", "completed", items_so_far=len(llm_weapons))

            if num_drones > 0:
                _notify("drones", "started")
                task = progress.add_task(f"Generating {num_drones} drones...", total=None)
                llm_drones = self._generate_drones(
                    theme, concept.get("drone_concepts", []), num_drones
                )
                progress.remove_task(task)
                console.print(f"  [green]Generated {len(llm_drones)} new drones[/]")
                _notify("drones", "completed", items_so_far=len(llm_drones))

            if num_augments > 0:
                _notify("augments", "started")
                task = progress.add_task(f"Generating {num_augments} augments...", total=None)
                llm_augments = self._generate_augments(
                    theme, concept.get("augment_concepts", []), num_augments
                )
                progress.remove_task(task)
                console.print(f"  [green]Generated {len(llm_augments)} new augments[/]")
                _notify("augments", "completed", items_so_far=len(llm_augments))

            if num_crew > 0:
                _notify("crew", "started")
                task = progress.add_task(f"Generating {num_crew} crew race(s)...", total=None)
                llm_crew = self._generate_crew(
                    theme, concept.get("crew_concepts", []), num_crew
                )
                progress.remove_task(task)
                console.print(f"  [green]Generated {len(llm_crew)} new crew race(s)[/]")
                _notify("crew", "completed", items_so_far=len(llm_crew))

            if num_events > 0:
                _notify("events", "started")
                task = progress.add_task(f"Generating {num_events} events...", total=None)
                events = self._generate_events(
                    theme, concept.get("event_concepts", []), num_events
                )
                progress.remove_task(task)
                console.print(f"  [green]Generated {len(events)} events[/]")
                _notify("events", "completed", items_so_far=len(events))

            # Combine chaos + LLM content into final lists
            all_weapons = chaos_weapons + llm_weapons
            all_drones = chaos_drones + llm_drones
            all_augments = chaos_augments + llm_augments
            all_crew = chaos_crew + llm_crew

            # Checkpoint: save after all content generation, before sprites
            if total_llm_content > 0:
                self._save_partial(
                    mod_name, description, weapons=all_weapons, drones=all_drones,
                    augments=all_augments, crew=all_crew, events=events,
                )

            # Step 3: Generate sprites (only for LLM-generated items)
            _notify("sprites", "started")
            sprite_files = self._generate_all_sprites(
                progress, llm_weapons, llm_drones, generate_sprites, use_cached_images
            )
            _notify("sprites", "completed")

            # Step 3b: Apply chaos mutations to all generated sprites
            if chaos_config and sprite_files:
                task = progress.add_task("Mutating sprites with chaos...", total=None)
                sprite_mutator = SpriteMutator(chaos_config.level, chaos_config.seed)
                mutated_count = 0
                for filename, sprite_data in sprite_files.items():
                    try:
                        sprite_files[filename] = sprite_mutator.mutate_sprite(sprite_data)
                        mutated_count += 1
                    except Exception as e:
                        console.print(f"[yellow]Warning: Could not mutate {filename}: {e}[/]")
                progress.remove_task(task)
                console.print(f"  [magenta]Mutated {mutated_count} sprites with chaos[/]")

            # Step 4: Build final mod package
            _notify("building", "started")
            task = progress.add_task("Building mod package...", total=None)
            ftl_path = self._save_partial(
                mod_name, description,
                weapons=all_weapons, drones=all_drones, augments=all_augments,
                crew=all_crew, events=events, sprite_files=sprite_files,
                test_loadout=test_loadout,
            )
            progress.remove_task(task)
            _notify("building", "completed")

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

    def _generate_all_sprites(
        self,
        progress: Progress,
        llm_weapons: list[WeaponBlueprint],
        llm_drones: list[DroneBlueprint],
        generate_sprites: bool,
        use_cache: bool,
    ) -> dict[str, bytes]:
        """Generate sprites for all LLM-generated weapons and drones.

        Chaos weapons/drones already have sprites in the game so they are skipped.
        """
        sprite_files: dict[str, bytes] = {}

        if generate_sprites and llm_weapons:
            task = progress.add_task("Generating weapon sprites...", total=None)
            weapon_sprites = self._generate_weapon_sprites(llm_weapons, use_cache)
            sprite_files.update(weapon_sprites)
            progress.remove_task(task)
            console.print(f"  [green]Generated {len(weapon_sprites)} weapon sprites[/]")

            # Link weapon art to sprite animations
            for weapon in llm_weapons:
                weapon.weapon_art = weapon.name.lower()

        if generate_sprites and llm_drones:
            task = progress.add_task("Generating drone sprites...", total=None)
            drone_sprites = self._generate_drone_sprites(llm_drones, use_cache)
            sprite_files.update(drone_sprites)
            progress.remove_task(task)
            console.print(f"  [green]Generated {len(drone_sprites)} drone sprites[/]")

            # Link drone image to sprite animations
            for drone in llm_drones:
                drone.drone_image = drone.name.lower()

        return sprite_files

    def _get_cache_dir(self) -> Path:
        """Get the image cache directory."""
        cache_dir = self.settings.output_dir / ".image_cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        return cache_dir

    def _get_weapon_cache_key(self, weapon: WeaponBlueprint) -> str:
        """Generate a cache key for a weapon sprite.

        Uses weapon type only so cache can be reused across different weapon names.
        This allows faster iteration when testing sprite processing.
        """
        return f"weapon_{weapon.type.lower()}"

    def _get_drone_cache_key(self, drone: DroneBlueprint) -> str:
        """Generate a cache key for a drone sprite.

        Uses drone type only so cache can be reused across different drone names.
        """
        return f"drone_{drone.type.lower()}"

    def _generate_weapon_sprites(
        self,
        weapons: list[WeaponBlueprint],
        use_cache: bool = False,
    ) -> dict[str, bytes]:
        """Generate sprite sheets for weapons."""
        sprite_files = {}
        cache_dir = self._get_cache_dir() if use_cache else None

        for weapon in weapons:
            filename = f"{weapon.name.lower()}_strip12.png"
            cache_key = self._get_weapon_cache_key(weapon) if use_cache else None
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

    def _generate_drone_sprites(
        self,
        drones: list[DroneBlueprint],
        use_cache: bool = False,
    ) -> dict[str, bytes]:
        """Generate sprite sheets for drones."""
        sprite_files = {}
        cache_dir = self._get_cache_dir() if use_cache else None

        for drone in drones:
            # FTL drone naming: dronename_sheet.png (4 frames of 50x20)
            filename = f"{drone.name.lower()}_sheet.png"
            cache_key = self._get_drone_cache_key(drone) if use_cache else None
            cached_path = cache_dir / f"{cache_key}.png" if cache_dir and cache_key else None

            # Check cache first
            if cached_path and cached_path.exists():
                console.print(f"  [dim]Using cached sprite for {drone.name}[/]")
                sprite_files[filename] = cached_path.read_bytes()
                continue

            try:
                # Generate base image
                image_data = self.image_client.generate_drone_sprite(
                    drone_name=drone.name,
                    drone_type=drone.type,
                    description=drone.desc,
                )

                # Create sprite sheet
                sheet_data = self.sprite_processor.create_drone_sprite_sheet(image_data)

                # Cache the result
                if cached_path:
                    cached_path.write_bytes(sheet_data)

                sprite_files[filename] = sheet_data

            except Exception as e:
                console.print(f"[yellow]Warning: Could not generate sprite for {drone.name}: {e}[/]")
                # Use placeholder
                sheet_data = self.sprite_processor.create_placeholder_drone_sprite_sheet(drone.name)
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
