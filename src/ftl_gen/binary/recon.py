"""Binary reconnaissance for the FTL Mach-O executable.

Provides programmatic inspection of the FTL binary: architecture, segments,
augment name strings, code caves, code signing status, and linked libraries.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Vanilla FTL augment names to search for in the binary.
# These are the blueprint name strings used by HasAugmentation() / GetAugmentationValue().
VANILLA_AUGMENT_NAMES = [
    "ADV_SCANNERS",
    "AUTO_COOLDOWN",
    "BACKUP_DNA",
    "BATTERY_BOOSTER",
    "CLOAK_FIRE",
    "CREW_STIMS",
    "CRYSTAL_SHARDS",
    "DEFENSE_SCRAMBLER",
    "DRONE_RECOVERY",
    "DRONE_SPEED",
    "ENERGY_SHIELD",
    "EXPLOSIVE_REPLICATOR",
    "FIRE_EXTINGUISHERS",
    "FLEET_DISTRACTION",
    "FTL_BOOSTER",
    "FTL_JAMMER",
    "FTL_JUMPER",
    "HACKING_STUN",
    "ION_ARMOR",
    "LIFE_SCANNER",
    "NANO_MEDBAY",
    "O2_MASKS",
    "REPAIR_ARM",
    "ROCK_ARMOR",
    "SCRAP_COLLECTOR",
    "SHIELD_RECHARGE",
    "SLUG_GEL",
    "STASIS_POD",
    "SYSTEM_CASING",
    "TELEPORT_HEAL",
    "WEAPON_PREIGNITE",
    "ZOLTAN_BYPASS",
]


@dataclass
class SegmentInfo:
    """Information about a Mach-O segment."""

    name: str
    virtual_address: int
    virtual_size: int
    file_offset: int
    file_size: int
    sections: list[str] = field(default_factory=list)


@dataclass
class StringRef:
    """A string found in the binary with its location."""

    value: str
    virtual_address: int
    file_offset: int
    section: str


@dataclass
class CodeCave:
    """A contiguous region of NUL bytes in an executable segment."""

    file_offset: int
    size: int
    segment: str


@dataclass
class BinaryInfo:
    """Complete reconnaissance report for an FTL binary."""

    path: Path
    architecture: str
    pie: bool
    code_signed: bool
    hardened_runtime: bool
    signing_identity: str | None
    segments: list[SegmentInfo]
    augment_strings: list[StringRef]
    code_caves: list[CodeCave]
    linked_libraries: list[str]
    file_size: int

    @property
    def total_cave_space(self) -> int:
        """Total bytes available in code caves."""
        return sum(c.size for c in self.code_caves)


class BinaryRecon:
    """Mach-O binary analysis for FTL.

    Uses the `lief` library for binary parsing and `codesign`/`otool`
    for macOS-specific metadata.
    """

    # Minimum size (bytes) for a NUL region to count as a code cave
    MIN_CAVE_SIZE = 64

    def __init__(self, binary_path: Path):
        self.binary_path = binary_path.resolve()
        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {self.binary_path}")

    def analyze(self) -> BinaryInfo:
        """Run full binary reconnaissance and return a BinaryInfo report."""
        try:
            import lief
        except ImportError:
            raise ImportError(
                "lief is required for binary analysis. "
                "Install with: pip install -e '.[binary]'"
            )

        binary = lief.parse(str(self.binary_path))
        if binary is None:
            raise ValueError(f"Failed to parse binary: {self.binary_path}")

        architecture = self._get_architecture(binary)
        pie = self._check_pie(binary)
        segments = self._get_segments(binary)
        augment_strings = self._find_augment_strings(binary)
        code_caves = self._find_code_caves(binary)
        code_signed, hardened_runtime, signing_identity = self._check_signing()
        linked_libraries = self._get_linked_libraries()

        return BinaryInfo(
            path=self.binary_path,
            architecture=architecture,
            pie=pie,
            code_signed=code_signed,
            hardened_runtime=hardened_runtime,
            signing_identity=signing_identity,
            segments=segments,
            augment_strings=augment_strings,
            code_caves=code_caves,
            linked_libraries=linked_libraries,
            file_size=self.binary_path.stat().st_size,
        )

    def _get_architecture(self, binary) -> str:
        """Determine the binary's CPU architecture."""
        import lief

        header = binary.header
        cpu_type = header.cpu_type
        if cpu_type == lief.MachO.Header.CPU_TYPE.X86_64:
            return "x86_64"
        elif cpu_type == lief.MachO.Header.CPU_TYPE.X86:
            return "x86"
        elif cpu_type == lief.MachO.Header.CPU_TYPE.ARM64:
            return "arm64"
        elif cpu_type == lief.MachO.Header.CPU_TYPE.ARM:
            return "arm"
        return f"unknown({cpu_type})"

    def _check_pie(self, binary) -> bool:
        """Check if the binary is position-independent (PIE)."""
        import lief

        return binary.header.has(lief.MachO.Header.FLAGS.PIE)

    def _get_segments(self, binary) -> list[SegmentInfo]:
        """Extract segment information from the Mach-O binary."""
        segments = []
        for seg in binary.segments:
            sections = [sec.name for sec in seg.sections]
            segments.append(SegmentInfo(
                name=seg.name,
                virtual_address=seg.virtual_address,
                virtual_size=seg.virtual_size,
                file_offset=seg.file_offset,
                file_size=seg.file_size,
                sections=sections,
            ))
        return segments

    def _find_augment_strings(self, binary) -> list[StringRef]:
        """Search for vanilla augment name strings in the binary.

        Scans the __cstring section (and other string sections) for exact
        matches of known augment names. Returns their virtual addresses
        and file offsets for cross-referencing in Ghidra/disassembler.
        """
        found: list[StringRef] = []
        raw_data = self.binary_path.read_bytes()

        # Search all sections that might contain C strings
        string_section_names = {"__cstring", "__const", "__rodata"}

        for seg in binary.segments:
            for section in seg.sections:
                if section.name not in string_section_names:
                    continue

                sec_offset = section.offset
                sec_size = section.size
                sec_va = section.virtual_address
                sec_data = raw_data[sec_offset:sec_offset + sec_size]

                for aug_name in VANILLA_AUGMENT_NAMES:
                    target = aug_name.encode("ascii")
                    # Search for NUL-terminated string
                    search_pos = 0
                    while True:
                        idx = sec_data.find(target, search_pos)
                        if idx == -1:
                            break
                        # Verify it's NUL-terminated (not a substring of a longer string)
                        end_pos = idx + len(target)
                        if end_pos < len(sec_data) and sec_data[end_pos:end_pos + 1] == b"\x00":
                            # Also check that the preceding byte is NUL or start of section
                            if idx == 0 or sec_data[idx - 1:idx] == b"\x00":
                                file_offset = sec_offset + idx
                                virtual_address = sec_va + idx
                                found.append(StringRef(
                                    value=aug_name,
                                    virtual_address=virtual_address,
                                    file_offset=file_offset,
                                    section=section.name,
                                ))
                        search_pos = idx + 1

        # Sort by augment name for consistent output
        found.sort(key=lambda s: s.value)
        return found

    # Mach-O VM protection bits (mach/vm_prot.h)
    _VM_PROT_EXECUTE = 0x4

    def _find_code_caves(self, binary) -> list[CodeCave]:
        """Find contiguous NUL regions in executable segments.

        Code caves are used to inject trampoline code without extending
        the binary. We look for runs of 0x00 bytes in segments that have
        execute permission.
        """
        caves: list[CodeCave] = []
        raw_data = self.binary_path.read_bytes()

        for seg in binary.segments:
            # Only look in executable segments
            if not (seg.init_protection & self._VM_PROT_EXECUTE):
                continue

            seg_offset = seg.file_offset
            seg_size = seg.file_size
            seg_data = raw_data[seg_offset:seg_offset + seg_size]

            # Scan for runs of NUL bytes
            i = 0
            while i < len(seg_data):
                if seg_data[i] == 0:
                    run_start = i
                    while i < len(seg_data) and seg_data[i] == 0:
                        i += 1
                    run_len = i - run_start
                    if run_len >= self.MIN_CAVE_SIZE:
                        caves.append(CodeCave(
                            file_offset=seg_offset + run_start,
                            size=run_len,
                            segment=seg.name,
                        ))
                else:
                    i += 1

        # Sort by size descending (largest caves first)
        caves.sort(key=lambda c: c.size, reverse=True)
        return caves

    def _check_signing(self) -> tuple[bool, bool, str | None]:
        """Check code signing status using macOS `codesign` tool.

        Returns (code_signed, hardened_runtime, signing_identity).
        """
        try:
            result = subprocess.run(
                ["codesign", "-dvv", str(self.binary_path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stderr  # codesign outputs to stderr

            code_signed = result.returncode == 0
            hardened_runtime = "flags=0x10000(runtime)" in output
            signing_identity = None

            for line in output.splitlines():
                if line.startswith("Authority="):
                    signing_identity = line.split("=", 1)[1]
                    break
                if line.startswith("Signature=adhoc"):
                    signing_identity = "adhoc"
                    break

            return code_signed, hardened_runtime, signing_identity

        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("codesign not available, skipping signing check")
            return False, False, None

    @staticmethod
    def va_to_file_offset(binary_info: BinaryInfo, va: int) -> int:
        """Convert a virtual address to a file offset using segment info.

        Ghidra and disassemblers report virtual addresses. Binary patching
        operates on file offsets. This bridges the two.

        Raises ValueError if the VA doesn't fall in any segment.
        """
        for seg in binary_info.segments:
            seg_end = seg.virtual_address + seg.virtual_size
            if seg.virtual_address <= va < seg_end:
                return va - seg.virtual_address + seg.file_offset
        raise ValueError(
            f"VA 0x{va:x} not in any segment. "
            f"Segments: {[(s.name, hex(s.virtual_address)) for s in binary_info.segments]}"
        )

    @staticmethod
    def file_offset_to_va(binary_info: BinaryInfo, file_offset: int) -> int:
        """Convert a file offset to a virtual address using segment info.

        Raises ValueError if the offset doesn't fall in any segment.
        """
        for seg in binary_info.segments:
            seg_end = seg.file_offset + seg.file_size
            if seg.file_offset <= file_offset < seg_end:
                return file_offset - seg.file_offset + seg.virtual_address
        raise ValueError(
            f"File offset 0x{file_offset:x} not in any segment."
        )

    def _get_linked_libraries(self) -> list[str]:
        """Get linked libraries using `otool -L`."""
        try:
            result = subprocess.run(
                ["otool", "-L", str(self.binary_path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return []

            libs = []
            for line in result.stdout.splitlines()[1:]:  # Skip first line (binary path)
                line = line.strip()
                if line:
                    # Format: "/path/to/lib.dylib (compatibility version X, current version Y)"
                    lib_path = line.split(" (")[0].strip()
                    if lib_path:
                        libs.append(lib_path)
            return libs

        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("otool not available, skipping library check")
            return []
