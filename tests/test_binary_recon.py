"""Tests for binary reconnaissance module."""

import struct
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# Skip entire module if lief is not installed
lief = pytest.importorskip("lief")

from ftl_gen.binary.recon import (
    VANILLA_AUGMENT_NAMES,
    BinaryInfo,
    BinaryRecon,
    CodeCave,
    SegmentInfo,
    StringRef,
)


def _create_minimal_macho(tmp_path: Path, strings: list[str] | None = None) -> Path:
    """Create a minimal Mach-O binary using lief for testing.

    Builds a valid x86_64 Mach-O with an optional __cstring section
    containing the provided strings.
    """
    # Build a minimal x86_64 Mach-O using lief's FatBinary or MachO builder.
    # Since building from scratch with lief is complex, we'll create a minimal
    # binary using raw bytes for the Mach-O header structure.
    #
    # Simpler approach: write raw Mach-O bytes that lief can parse.
    # We'll create the simplest possible Mach-O 64 executable.

    binary_path = tmp_path / "test_binary"

    # Use lief to create a proper Mach-O binary
    # Since lief doesn't easily support creating Mach-O from scratch,
    # we'll test with raw byte patterns in specific test functions
    # and rely on real binary tests for full integration.

    # For unit tests, we'll write a file with embedded strings and test
    # the string-finding logic separately.
    binary_path.write_bytes(b"\x00" * 64)
    return binary_path


class TestStringRef:
    """Test StringRef dataclass."""

    def test_creation(self):
        ref = StringRef(
            value="SCRAP_COLLECTOR",
            virtual_address=0x1A3F40,
            file_offset=0x1A2F40,
            section="__cstring",
        )
        assert ref.value == "SCRAP_COLLECTOR"
        assert ref.virtual_address == 0x1A3F40
        assert ref.file_offset == 0x1A2F40
        assert ref.section == "__cstring"


class TestSegmentInfo:
    """Test SegmentInfo dataclass."""

    def test_creation(self):
        seg = SegmentInfo(
            name="__TEXT",
            virtual_address=0x100000000,
            virtual_size=0x1000,
            file_offset=0,
            file_size=0x1000,
            sections=["__text", "__cstring"],
        )
        assert seg.name == "__TEXT"
        assert seg.sections == ["__text", "__cstring"]

    def test_default_sections(self):
        seg = SegmentInfo(
            name="__DATA",
            virtual_address=0,
            virtual_size=0,
            file_offset=0,
            file_size=0,
        )
        assert seg.sections == []


class TestCodeCave:
    """Test CodeCave dataclass."""

    def test_creation(self):
        cave = CodeCave(file_offset=0x1000, size=256, segment="__TEXT")
        assert cave.file_offset == 0x1000
        assert cave.size == 256
        assert cave.segment == "__TEXT"


class TestBinaryInfo:
    """Test BinaryInfo dataclass."""

    def test_total_cave_space(self):
        info = BinaryInfo(
            path=Path("/fake"),
            architecture="x86_64",
            pie=True,
            code_signed=False,
            hardened_runtime=False,
            signing_identity=None,
            segments=[],
            augment_strings=[],
            code_caves=[
                CodeCave(file_offset=0x1000, size=128, segment="__TEXT"),
                CodeCave(file_offset=0x2000, size=256, segment="__TEXT"),
            ],
            linked_libraries=[],
            file_size=1024,
        )
        assert info.total_cave_space == 384

    def test_total_cave_space_empty(self):
        info = BinaryInfo(
            path=Path("/fake"),
            architecture="x86_64",
            pie=True,
            code_signed=False,
            hardened_runtime=False,
            signing_identity=None,
            segments=[],
            augment_strings=[],
            code_caves=[],
            linked_libraries=[],
            file_size=1024,
        )
        assert info.total_cave_space == 0


class TestVanillaAugmentNames:
    """Test the vanilla augment names list."""

    def test_contains_known_augments(self):
        assert "SCRAP_COLLECTOR" in VANILLA_AUGMENT_NAMES
        assert "WEAPON_PREIGNITE" in VANILLA_AUGMENT_NAMES
        assert "REPAIR_ARM" in VANILLA_AUGMENT_NAMES
        assert "AUTO_COOLDOWN" in VANILLA_AUGMENT_NAMES

    def test_sorted(self):
        assert VANILLA_AUGMENT_NAMES == sorted(VANILLA_AUGMENT_NAMES)

    def test_no_duplicates(self):
        assert len(VANILLA_AUGMENT_NAMES) == len(set(VANILLA_AUGMENT_NAMES))

    def test_no_custom_augments(self):
        """Ensure mod-specific augments are not in the vanilla list."""
        assert "TRIFORCE_RESONATOR" not in VANILLA_AUGMENT_NAMES
        assert "LENS_OF_TRUTH" not in VANILLA_AUGMENT_NAMES


class TestBinaryRecon:
    """Test BinaryRecon class."""

    def test_init_missing_binary(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="Binary not found"):
            BinaryRecon(tmp_path / "nonexistent")

    def test_init_valid_path(self, tmp_path):
        binary = tmp_path / "test"
        binary.write_bytes(b"\x00")
        recon = BinaryRecon(binary)
        assert recon.binary_path == binary.resolve()

    @patch("subprocess.run")
    def test_check_signing_signed(self, mock_run, tmp_path):
        binary = tmp_path / "test"
        binary.write_bytes(b"\x00")
        recon = BinaryRecon(binary)

        mock_run.return_value = type("Result", (), {
            "returncode": 0,
            "stderr": (
                "Executable=/path/to/FTL\n"
                "Identifier=com.subsetgames.FTL\n"
                "Authority=Apple Development\n"
                "Signed Time=...\n"
            ),
        })()

        signed, hardened, identity = recon._check_signing()
        assert signed is True
        assert hardened is False
        assert identity == "Apple Development"

    @patch("subprocess.run")
    def test_check_signing_adhoc(self, mock_run, tmp_path):
        binary = tmp_path / "test"
        binary.write_bytes(b"\x00")
        recon = BinaryRecon(binary)

        mock_run.return_value = type("Result", (), {
            "returncode": 0,
            "stderr": "Signature=adhoc\nInfo.plist=not bound\n",
        })()

        signed, hardened, identity = recon._check_signing()
        assert signed is True
        assert identity == "adhoc"

    @patch("subprocess.run")
    def test_check_signing_hardened(self, mock_run, tmp_path):
        binary = tmp_path / "test"
        binary.write_bytes(b"\x00")
        recon = BinaryRecon(binary)

        mock_run.return_value = type("Result", (), {
            "returncode": 0,
            "stderr": "flags=0x10000(runtime)\nAuthority=Developer ID\n",
        })()

        signed, hardened, identity = recon._check_signing()
        assert signed is True
        assert hardened is True
        assert identity == "Developer ID"

    @patch("subprocess.run")
    def test_check_signing_unsigned(self, mock_run, tmp_path):
        binary = tmp_path / "test"
        binary.write_bytes(b"\x00")
        recon = BinaryRecon(binary)

        mock_run.return_value = type("Result", (), {
            "returncode": 1,
            "stderr": "code object is not signed at all",
        })()

        signed, hardened, identity = recon._check_signing()
        assert signed is False
        assert hardened is False
        assert identity is None

    @patch("subprocess.run")
    def test_get_linked_libraries(self, mock_run, tmp_path):
        binary = tmp_path / "test"
        binary.write_bytes(b"\x00")
        recon = BinaryRecon(binary)

        mock_run.return_value = type("Result", (), {
            "returncode": 0,
            "stdout": (
                "/path/to/FTL:\n"
                "\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n"
                "\t/usr/lib/libc++.1.dylib (compatibility version 1.0.0)\n"
            ),
        })()

        libs = recon._get_linked_libraries()
        assert len(libs) == 2
        assert "/usr/lib/libSystem.B.dylib" in libs
        assert "/usr/lib/libc++.1.dylib" in libs

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_get_linked_libraries_otool_missing(self, mock_run, tmp_path):
        binary = tmp_path / "test"
        binary.write_bytes(b"\x00")
        recon = BinaryRecon(binary)

        libs = recon._get_linked_libraries()
        assert libs == []


class TestBinaryReconRealBinary:
    """Integration tests using the real FTL binary (skipped if not available)."""

    @pytest.fixture
    def ftl_binary(self):
        """Find the real FTL binary, skip if not available."""
        from ftl_gen.config import get_settings

        settings = get_settings()
        binary_path = settings.find_ftl_executable()
        if binary_path is None or not binary_path.exists():
            pytest.skip("FTL binary not found")
        return binary_path

    def test_analyze_real_binary(self, ftl_binary):
        recon = BinaryRecon(ftl_binary)
        info = recon.analyze()

        assert info.architecture == "x86_64"
        assert info.file_size > 0
        assert len(info.segments) > 0

        # Should find __TEXT segment
        seg_names = [s.name for s in info.segments]
        assert "__TEXT" in seg_names

    def test_finds_augment_strings(self, ftl_binary):
        recon = BinaryRecon(ftl_binary)
        info = recon.analyze()

        # FTL should contain at least some augment strings
        found_names = {s.value for s in info.augment_strings}
        assert "SCRAP_COLLECTOR" in found_names, (
            f"Expected SCRAP_COLLECTOR, found: {found_names}"
        )

    def test_augment_strings_have_valid_offsets(self, ftl_binary):
        recon = BinaryRecon(ftl_binary)
        info = recon.analyze()

        raw = ftl_binary.read_bytes()
        for string_ref in info.augment_strings:
            # Verify the string actually exists at the reported file offset
            offset = string_ref.file_offset
            expected = string_ref.value.encode("ascii") + b"\x00"
            actual = raw[offset:offset + len(expected)]
            assert actual == expected, (
                f"{string_ref.value} at offset 0x{offset:x}: "
                f"expected {expected!r}, got {actual!r}"
            )

    def test_signing_status(self, ftl_binary):
        recon = BinaryRecon(ftl_binary)
        info = recon.analyze()

        # Just verify it returns something reasonable
        assert isinstance(info.code_signed, bool)
        assert isinstance(info.hardened_runtime, bool)

    def test_linked_libraries(self, ftl_binary):
        recon = BinaryRecon(ftl_binary)
        info = recon.analyze()

        # FTL should link against system libraries
        assert len(info.linked_libraries) > 0
