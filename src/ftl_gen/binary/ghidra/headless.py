"""Wrapper around Ghidra's headless CLI for non-interactive binary analysis.

Provides a Python interface to Ghidra's headless analyzer, allowing us to
import binaries, run auto-analysis, and execute Python scripts that extract
structured data (strings, decompiled code, cross-references, raw bytes).

Ghidra 12+ uses PyGhidra (CPython + JPype) for Python scripting. We use
`analyzeHeadless` for binary import and `pyghidraRun --headless` for running
Python scripts.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


class GhidraError(Exception):
    """Raised when a Ghidra headless operation fails."""


class GhidraHeadless:
    """Wraps Ghidra's headless CLI for programmatic binary analysis.

    Usage:
        ghidra = GhidraHeadless(ghidra_home=Path("/opt/homebrew/Cellar/ghidra/12.0.2/libexec"))
        ghidra.import_binary(Path("/path/to/FTL"))
        strings = ghidra.find_strings(["SCRAP_COLLECTOR", "REPAIR_ARM"])
        pseudocode = ghidra.decompile_at(0x8b420)
    """

    SCRIPTS_DIR = Path(__file__).parent / "scripts"

    def __init__(
        self,
        ghidra_home: Path,
        project_dir: Path | None = None,
        project_name: str = "FTL_Analysis",
    ):
        self.ghidra_home = ghidra_home
        self.analyze_headless = ghidra_home / "support" / "analyzeHeadless"
        self.pyghidra_run = ghidra_home / "support" / "pyghidraRun"
        self.project_name = project_name
        self._binary_name: str | None = None

        if not self.analyze_headless.exists():
            raise GhidraError(
                f"analyzeHeadless not found at {self.analyze_headless}. "
                f"Check GHIDRA_HOME path: {ghidra_home}"
            )

        if project_dir is None:
            self._tmp_dir = tempfile.mkdtemp(prefix="ftl_ghidra_")
            self.project_dir = Path(self._tmp_dir)
        else:
            self._tmp_dir = None
            self.project_dir = project_dir
            self.project_dir.mkdir(parents=True, exist_ok=True)

    @property
    def _project_exists(self) -> bool:
        """Check if a Ghidra project already exists."""
        gpr_file = self.project_dir / f"{self.project_name}.gpr"
        return gpr_file.exists()

    @property
    def _use_pyghidra(self) -> bool:
        """Check if pyghidraRun is available (Ghidra 12+)."""
        return self.pyghidra_run.exists()

    def import_binary(self, binary_path: Path, timeout: int = 600) -> None:
        """Import a binary and run Ghidra's auto-analysis.

        This is a one-time operation (~2-5 min for FTL). Subsequent script
        runs use -process with -noanalysis for speed.
        """
        if not binary_path.exists():
            raise GhidraError(f"Binary not found: {binary_path}")

        self._binary_name = binary_path.name

        if self._project_exists:
            logger.info("Ghidra project already exists, skipping import")
            return

        logger.info("Importing binary into Ghidra (this may take 2-5 minutes)...")

        cmd = [
            str(self.analyze_headless),
            str(self.project_dir),
            self.project_name,
            "-import", str(binary_path),
            "-overwrite",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0:
            raise GhidraError(
                f"Ghidra import failed (exit {result.returncode}):\n"
                f"{result.stderr[-2000:]}"
            )

        logger.info("Binary imported and analyzed successfully")

    def run_script(
        self,
        script_path: Path,
        args: list[str] | None = None,
        timeout: int = 120,
    ) -> str:
        """Run a Python script against the analyzed binary.

        Uses pyghidraRun --headless (Ghidra 12+) or falls back to
        analyzeHeadless for older versions.

        Args:
            script_path: Path to the .py script
            args: Arguments passed to the script via getScriptArgs()
            timeout: Max seconds to wait

        Returns:
            The script's stdout output (typically JSON)
        """
        if self._binary_name is None:
            raise GhidraError("No binary imported. Call import_binary() first.")

        if not script_path.exists():
            raise GhidraError(f"Script not found: {script_path}")

        if self._use_pyghidra:
            cmd = [
                str(self.pyghidra_run),
                "--headless",
                str(self.project_dir),
                self.project_name,
                "-process", self._binary_name,
                "-noanalysis",
                "-scriptPath", str(script_path.parent),
                "-postScript", script_path.name,
            ]
        else:
            cmd = [
                str(self.analyze_headless),
                str(self.project_dir),
                self.project_name,
                "-process", self._binary_name,
                "-noanalysis",
                "-scriptPath", str(script_path.parent),
                "-postScript", script_path.name,
            ]

        if args:
            cmd.extend(args)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0:
            # Check if it's a script error vs infrastructure error
            stderr_tail = result.stderr[-2000:] if result.stderr else ""
            stdout_tail = result.stdout[-2000:] if result.stdout else ""
            raise GhidraError(
                f"Script execution failed (exit {result.returncode}):\n"
                f"{stderr_tail}\n{stdout_tail}"
            )

        # Extract JSON output from Ghidra's verbose stdout.
        # Our scripts print JSON lines prefixed with "RESULT:" to distinguish
        # from Ghidra's own log output.
        return self._extract_results(result.stdout)

    def _extract_results(self, stdout: str) -> str:
        """Extract RESULT: prefixed lines from Ghidra stdout.

        Handles both direct output and Ghidra's log-wrapped output like:
            INFO  script.py> RESULT:{...} (GhidraScript)
        """
        results = []
        for line in stdout.splitlines():
            # Direct prefix
            if line.startswith("RESULT:"):
                results.append(line[7:].strip())
            # Ghidra log-wrapped: "INFO  script.py> RESULT:{...} (GhidraScript)"
            elif "RESULT:" in line:
                idx = line.index("RESULT:")
                tail = line[idx + 7:]
                # Strip trailing Ghidra log suffix like " (GhidraScript)"
                paren_idx = tail.rfind(" (")
                if paren_idx > 0:
                    tail = tail[:paren_idx]
                results.append(tail.strip())
        return "\n".join(results)

    # --- High-level convenience methods ---

    def find_strings(self, patterns: list[str]) -> list[dict]:
        """Find strings matching patterns, return addresses + xrefs.

        Returns list of dicts like:
            {"value": "SCRAP_COLLECTOR", "address": "0x1a3f40", "xrefs": ["0x8b420"]}
        """
        script = self.SCRIPTS_DIR / "find_strings.py"
        # Pass patterns as comma-separated arg
        raw = self.run_script(script, [",".join(patterns)])
        if not raw:
            return []
        return [json.loads(line) for line in raw.splitlines() if line.strip()]

    def decompile_at(self, address: int) -> dict:
        """Decompile the function containing the given address.

        Returns dict like:
            {"function": "FUN_0008b400", "address": "0x8b400", "pseudocode": "..."}
        """
        script = self.SCRIPTS_DIR / "decompile_function.py"
        raw = self.run_script(script, [f"0x{address:x}"])
        if not raw:
            return {"function": "unknown", "address": f"0x{address:x}", "pseudocode": ""}
        return json.loads(raw.splitlines()[0])

    def get_xrefs_to(self, address: int) -> list[dict]:
        """Get all code cross-references TO an address.

        Returns list of dicts like:
            {"from_address": "0x8b420", "from_function": "FUN_xxx", "type": "CALL"}
        """
        script = self.SCRIPTS_DIR / "get_xrefs.py"
        raw = self.run_script(script, [f"0x{address:x}", "to"])
        if not raw:
            return []
        return [json.loads(line) for line in raw.splitlines() if line.strip()]

    def get_xrefs_from(self, address: int) -> list[dict]:
        """Get all code cross-references FROM a function.

        Returns list of dicts like:
            {"to_address": "0x8b420", "to_function": "FUN_xxx", "type": "CALL"}
        """
        script = self.SCRIPTS_DIR / "get_xrefs.py"
        raw = self.run_script(script, [f"0x{address:x}", "from"])
        if not raw:
            return []
        return [json.loads(line) for line in raw.splitlines() if line.strip()]

    def get_bytes(self, address: int, length: int) -> str:
        """Read raw bytes from the binary at a virtual address.

        Returns hex string like "554889e54883ec20".
        """
        script = self.SCRIPTS_DIR / "get_bytes.py"
        raw = self.run_script(script, [f"0x{address:x}", str(length)])
        if not raw:
            return ""
        data = json.loads(raw.splitlines()[0])
        return data.get("hex", "")

    def search_strings(self, pattern: str) -> list[dict]:
        """Search for strings in the binary matching a pattern.

        Returns list of dicts like:
            {"value": "SCRAP_COLLECTOR", "address": "0x1a3f40", "xrefs": ["0x8b420"]}
        """
        script = self.SCRIPTS_DIR / "find_strings.py"
        raw = self.run_script(script, [pattern])
        if not raw:
            return []
        return [json.loads(line) for line in raw.splitlines() if line.strip()]

    def list_functions(self, pattern: str, max_results: int = 20) -> list[dict]:
        """Search for functions by name pattern in Ghidra's function manager.

        Unlike search_strings which finds string data, this finds actual CODE
        entry points from the symbol table. Essential for resolving mangled
        C++ names to decompilable addresses.

        Returns list of dicts like:
            {"name": "GetEvent", "address": "0x1002a3f40", "size": 256,
             "signature": "...", "calling_convention": "__thiscall"}
        """
        script = self.SCRIPTS_DIR / "list_functions.py"
        raw = self.run_script(script, [pattern, str(max_results)])
        if not raw:
            return []
        results = []
        for line in raw.splitlines():
            if line.strip():
                data = json.loads(line)
                if "error" not in data and "info" not in data:
                    results.append(data)
                elif "info" in data:
                    logger.info("list_functions: %s", data["info"])
        return results
