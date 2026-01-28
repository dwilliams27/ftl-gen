"""Slipstream Mod Manager integration."""

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ftl_gen.config import Settings


@dataclass
class ValidationResult:
    """Result of mod validation."""

    valid: bool
    errors: list[str]
    warnings: list[str]
    output: str

    @property
    def ok(self) -> bool:
        return self.valid and not self.errors


@dataclass
class PatchResult:
    """Result of mod patching."""

    success: bool
    message: str
    output: str


class SlipstreamManager:
    """Manages Slipstream Mod Manager integration."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or Settings()
        self._path: Path | None = None

    @property
    def path(self) -> Path | None:
        """Get Slipstream installation path."""
        if self._path is None:
            self._path = self.settings.find_slipstream()
        return self._path

    @property
    def cli_path(self) -> Path | None:
        """Get path to Slipstream CLI script."""
        if self.path:
            cli = self.path / "modman-cli.sh"
            if cli.exists():
                return cli
        return None

    @property
    def mods_dir(self) -> Path | None:
        """Get Slipstream mods directory."""
        if self.path:
            mods = self.path / "mods"
            if mods.exists():
                return mods
        return None

    def is_available(self) -> bool:
        """Check if Slipstream is installed and accessible."""
        return self.cli_path is not None and self.cli_path.exists()

    def _run_command(self, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
        """Run a Slipstream CLI command."""
        if not self.cli_path:
            raise RuntimeError("Slipstream CLI not found")

        cmd = [str(self.cli_path)] + list(args)

        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=self.path,
        )

    def validate(self, mod_path: Path) -> ValidationResult:
        """Validate a mod file.

        Args:
            mod_path: Path to .ftl mod file

        Returns:
            ValidationResult with status and any errors
        """
        if not self.is_available():
            return ValidationResult(
                valid=False,
                errors=["Slipstream not available"],
                warnings=[],
                output="",
            )

        if not mod_path.exists():
            return ValidationResult(
                valid=False,
                errors=[f"Mod file not found: {mod_path}"],
                warnings=[],
                output="",
            )

        try:
            result = self._run_command("--validate", str(mod_path))
            output = result.stdout + result.stderr

            # Parse output for errors/warnings
            errors = []
            warnings = []

            for line in output.split("\n"):
                line_lower = line.lower()
                if "error" in line_lower:
                    errors.append(line.strip())
                elif "warning" in line_lower:
                    warnings.append(line.strip())

            valid = result.returncode == 0 and not errors

            return ValidationResult(
                valid=valid,
                errors=errors,
                warnings=warnings,
                output=output,
            )

        except subprocess.TimeoutExpired:
            return ValidationResult(
                valid=False,
                errors=["Validation timed out"],
                warnings=[],
                output="",
            )
        except Exception as e:
            return ValidationResult(
                valid=False,
                errors=[str(e)],
                warnings=[],
                output="",
            )

    def patch(self, mod_paths: list[Path]) -> PatchResult:
        """Apply mods to the game.

        Args:
            mod_paths: List of paths to .ftl mod files

        Returns:
            PatchResult with status
        """
        if not self.is_available():
            return PatchResult(
                success=False,
                message="Slipstream not available",
                output="",
            )

        # Build argument list
        args = ["--patch"]
        for mod_path in mod_paths:
            if not mod_path.exists():
                return PatchResult(
                    success=False,
                    message=f"Mod file not found: {mod_path}",
                    output="",
                )
            args.append(str(mod_path))

        try:
            result = self._run_command(*args, timeout=120)
            output = result.stdout + result.stderr

            return PatchResult(
                success=result.returncode == 0,
                message="Mods patched successfully" if result.returncode == 0 else "Patch failed",
                output=output,
            )

        except subprocess.TimeoutExpired:
            return PatchResult(
                success=False,
                message="Patching timed out",
                output="",
            )
        except Exception as e:
            return PatchResult(
                success=False,
                message=str(e),
                output="",
            )

    def patch_and_run(self, mod_paths: list[Path]) -> PatchResult:
        """Apply mods and launch FTL.

        Args:
            mod_paths: List of paths to .ftl mod files

        Returns:
            PatchResult with status
        """
        # First patch
        patch_result = self.patch(mod_paths)
        if not patch_result.success:
            return patch_result

        # Then run
        return self.run_ftl()

    def run_ftl(self) -> PatchResult:
        """Launch FTL."""
        if not self.is_available():
            return PatchResult(
                success=False,
                message="Slipstream not available",
                output="",
            )

        try:
            result = self._run_command("--runftl")
            output = result.stdout + result.stderr

            return PatchResult(
                success=result.returncode == 0,
                message="FTL launched" if result.returncode == 0 else "Launch failed",
                output=output,
            )

        except subprocess.TimeoutExpired:
            # Running FTL might not return immediately, that's ok
            return PatchResult(
                success=True,
                message="FTL launch initiated",
                output="",
            )
        except Exception as e:
            return PatchResult(
                success=False,
                message=str(e),
                output="",
            )

    def list_mods(self) -> list[str]:
        """List available mods in Slipstream mods directory."""
        if not self.mods_dir or not self.mods_dir.exists():
            return []

        mods = []
        for item in self.mods_dir.iterdir():
            if item.suffix == ".ftl" or item.is_dir():
                mods.append(item.name)

        return sorted(mods)

    def install_mod(self, mod_path: Path) -> bool:
        """Copy a mod to Slipstream's mods directory.

        Args:
            mod_path: Path to .ftl mod file

        Returns:
            True if successful
        """
        if not self.mods_dir:
            return False

        dest = self.mods_dir / mod_path.name
        shutil.copy2(mod_path, dest)
        return dest.exists()
