"""Build .ftl mod packages from generated content."""

import shutil
import zipfile
from pathlib import Path

from ftl_gen.xml.builders import XMLBuilder
from ftl_gen.xml.schemas import ModContent


class ModBuilder:
    """Builds FTL mod packages (.ftl files)."""

    def __init__(self, output_dir: Path | None = None):
        self.output_dir = output_dir or Path("./output")
        self.xml_builder = XMLBuilder()

    def build(
        self,
        content: ModContent,
        sprite_files: dict[str, bytes] | None = None,
        output_name: str | None = None,
        *,
        test_weapon: bool = False,
        test_drone: bool = False,
        test_augment: bool = False,
    ) -> Path:
        """Build a complete mod package.

        Args:
            content: ModContent with all blueprints
            sprite_files: Dict mapping filenames to PNG data
            output_name: Override mod folder/file name
            test_weapon: If True, replace Engi A weapon with first mod weapon
            test_drone: If True, replace Engi A drone with first mod drone
            test_augment: If True, replace Engi A augment with first mod augment

        Returns:
            Path to generated .ftl file
        """
        mod_name = output_name or content.metadata.name
        mod_name = self._sanitize_name(mod_name)

        # Create mod directory structure
        mod_dir = self.output_dir / mod_name
        self._create_directory_structure(mod_dir)

        # Generate XML files
        self._write_xml_files(mod_dir, content, test_weapon=test_weapon, test_drone=test_drone, test_augment=test_augment)

        # Write sprite files if provided
        if sprite_files:
            self._write_sprite_files(mod_dir, sprite_files, content)

        # Write metadata
        self._write_metadata(mod_dir, content)

        # Package as .ftl
        ftl_path = self._package_ftl(mod_dir, mod_name)

        return ftl_path

    def _sanitize_name(self, name: str) -> str:
        """Sanitize mod name for filesystem use."""
        # Remove/replace invalid characters
        invalid_chars = '<>:"/\\|?*'
        sanitized = name
        for char in invalid_chars:
            sanitized = sanitized.replace(char, "")
        return sanitized.strip()

    def _create_directory_structure(self, mod_dir: Path) -> None:
        """Create the standard FTL mod directory structure."""
        # Remove existing if present
        if mod_dir.exists():
            shutil.rmtree(mod_dir)

        # Create directories
        (mod_dir / "data").mkdir(parents=True)
        (mod_dir / "img" / "weapons").mkdir(parents=True)
        (mod_dir / "img" / "ship" / "drones").mkdir(parents=True)
        (mod_dir / "mod-appendix").mkdir(parents=True)

    def _write_xml_files(
        self,
        mod_dir: Path,
        content: ModContent,
        *,
        test_weapon: bool = False,
        test_drone: bool = False,
        test_augment: bool = False,
    ) -> None:
        """Generate and write XML files."""
        data_dir = mod_dir / "data"

        # blueprints.xml.append - weapons, drones, augments, crew
        if content.weapons or content.drones or content.augments or content.crew:
            blueprints_xml = self.xml_builder.build_blueprints_append(
                content, test_weapon=test_weapon, test_drone=test_drone, test_augment=test_augment
            )
            (data_dir / "blueprints.xml.append").write_text(blueprints_xml)

        # events.xml.append - events
        # TODO: Events cause FTL to freeze at "Blueprints Loaded!" — they need
        # deeper sector integration to work. Skipped for now; set
        # PATCH_EVENTS=1 env var to re-enable for testing.
        import os
        if content.events and os.environ.get("PATCH_EVENTS") == "1":
            events_xml = self.xml_builder.build_events_append(content)
            (data_dir / "events.xml.append").write_text(events_xml)

        # animations.xml.append - weapon sprites only
        # (drones use static body images in img/ship/drones/, not animation sheets)
        weapon_names = [w.name for w in content.weapons] if content.weapons else []

        if weapon_names:
            weapon_anim_xml = self.xml_builder.build_animations_append(weapon_names)
            (data_dir / "animations.xml.append").write_text(weapon_anim_xml)

    def _write_sprite_files(
        self,
        mod_dir: Path,
        sprite_files: dict[str, bytes],
        content: ModContent,
    ) -> None:
        """Write sprite files to img directory."""
        img_dir = mod_dir / "img"
        weapons_dir = img_dir / "weapons"

        for filename, data in sprite_files.items():
            # Check if filename includes a path (e.g., "ship/drones/x_base.png")
            if "/" in filename:
                filepath = img_dir / filename
                filepath.parent.mkdir(parents=True, exist_ok=True)
            else:
                # Weapon sprite (flat filename)
                filepath = weapons_dir / filename
            filepath.write_bytes(data)

    def _write_metadata(self, mod_dir: Path, content: ModContent) -> None:
        """Write mod metadata file."""
        metadata_xml = self.xml_builder.build_metadata_append(content)
        (mod_dir / "mod-appendix" / "metadata.xml").write_text(metadata_xml)

    def _package_ftl(self, mod_dir: Path, mod_name: str) -> Path:
        """Package the mod directory as a .ftl file."""
        ftl_path = self.output_dir / f"{mod_name}.ftl"

        # Remove existing
        if ftl_path.exists():
            ftl_path.unlink()

        # Create zip file with .ftl extension
        with zipfile.ZipFile(ftl_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in mod_dir.rglob("*"):
                if file_path.is_file():
                    # Use relative path within the zip
                    arcname = file_path.relative_to(mod_dir)
                    zf.write(file_path, arcname)

        return ftl_path

