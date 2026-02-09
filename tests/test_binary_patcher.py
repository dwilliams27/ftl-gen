"""Tests for binary patcher, trampoline builder, and augment effect mapper."""

import hashlib
import json
import struct
import tempfile
from pathlib import Path
from unittest.mock import patch as mock_patch

import pytest

from ftl_gen.binary.patcher import BinaryPatcher, Patch, PatchResult, PatchSpec
from ftl_gen.binary.recon import BinaryInfo, CodeCave, SegmentInfo


def _can_import(module_name: str) -> bool:
    try:
        __import__(module_name)
        return True
    except ImportError:
        return False


# ============================================================
# Fixtures
# ============================================================


@pytest.fixture
def fake_binary(tmp_path):
    """Create a simple fake binary file for testing."""
    # 4 KB binary with known content
    data = bytearray(4096)
    # Write some recognizable patterns
    data[0:4] = b"\xCF\xFA\xED\xFE"  # Mach-O magic
    data[0x100:0x110] = b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x54\x53\x48\x83\xec\x20"  # prologue-like
    data[0x200:0x210] = b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x54\x53\x48\x83\xec\x20"  # another prologue
    data[0x800:0x900] = b"\x00" * 256  # Code cave (NUL bytes)

    binary_path = tmp_path / "FTL"
    binary_path.write_bytes(bytes(data))
    return binary_path


@pytest.fixture
def fake_binary_sha(fake_binary):
    """SHA256 of the fake binary."""
    return hashlib.sha256(fake_binary.read_bytes()).hexdigest()


@pytest.fixture
def simple_spec(fake_binary_sha):
    """A simple patch spec that modifies bytes at offset 0x100."""
    return PatchSpec(
        spec_version="1.0",
        binary_sha256=fake_binary_sha,
        description="Test patch",
        patches=[
            Patch(
                id="test_patch_1",
                description="Replace prologue at 0x100",
                file_offset=0x100,
                old_bytes=b"\x55\x48\x89\xe5\x41",
                new_bytes=b"\xe9\x00\x01\x00\x00",  # jmp +0x100
            ),
        ],
        metadata={"test": True},
    )


@pytest.fixture
def multi_patch_spec(fake_binary_sha):
    """A spec with multiple patches."""
    return PatchSpec(
        spec_version="1.0",
        binary_sha256=fake_binary_sha,
        description="Multi-patch test",
        patches=[
            Patch(
                id="patch_a",
                description="Patch at 0x100",
                file_offset=0x100,
                old_bytes=b"\x55\x48\x89\xe5",
                new_bytes=b"\xe9\x00\x01\x00",
            ),
            Patch(
                id="patch_b",
                description="Patch at 0x200",
                file_offset=0x200,
                old_bytes=b"\x55\x48\x89\xe5",
                new_bytes=b"\xe9\x00\x02\x00",
            ),
        ],
    )


# ============================================================
# BinaryPatcher: backup tests
# ============================================================


class TestBackup:
    def test_backup_creates_copy(self, fake_binary):
        patcher = BinaryPatcher(fake_binary)
        backup_path = patcher.backup()

        assert backup_path.exists()
        assert backup_path.name == "FTL.ftlgen.bak"
        assert backup_path.read_bytes() == fake_binary.read_bytes()

    def test_backup_doesnt_overwrite_existing(self, fake_binary):
        patcher = BinaryPatcher(fake_binary)

        # First backup
        patcher.backup()
        original_data = patcher.backup_path.read_bytes()

        # Modify the binary
        data = bytearray(fake_binary.read_bytes())
        data[0] = 0xFF
        fake_binary.write_bytes(bytes(data))

        # Second backup should NOT overwrite
        patcher.backup()
        assert patcher.backup_path.read_bytes() == original_data

    def test_backup_path_naming(self, fake_binary):
        patcher = BinaryPatcher(fake_binary)
        assert patcher.backup_path == fake_binary.with_suffix(".ftlgen.bak")


# ============================================================
# BinaryPatcher: verify_spec tests
# ============================================================


class TestVerifySpec:
    def test_verify_passes_matching_bytes(self, fake_binary, simple_spec):
        patcher = BinaryPatcher(fake_binary)
        errors = patcher.verify_spec(simple_spec)
        assert errors == []

    def test_verify_fails_byte_mismatch(self, fake_binary, fake_binary_sha):
        patcher = BinaryPatcher(fake_binary)
        bad_spec = PatchSpec(
            spec_version="1.0",
            binary_sha256=fake_binary_sha,
            description="Bad patch",
            patches=[
                Patch(
                    id="bad",
                    description="Wrong old_bytes",
                    file_offset=0x100,
                    old_bytes=b"\xDE\xAD\xBE\xEF",  # Doesn't match
                    new_bytes=b"\x01\x02\x03\x04",
                ),
            ],
        )
        errors = patcher.verify_spec(bad_spec)
        assert len(errors) == 1
        assert "bad" in errors[0]
        assert "don't match" in errors[0]

    def test_verify_warns_sha256_mismatch(self, fake_binary):
        patcher = BinaryPatcher(fake_binary)
        spec = PatchSpec(
            spec_version="1.0",
            binary_sha256="0000000000000000000000000000000000000000000000000000000000000000",
            description="Wrong SHA",
            patches=[
                Patch(
                    id="p1",
                    description="test",
                    file_offset=0x100,
                    old_bytes=b"\x55\x48\x89\xe5\x41",
                    new_bytes=b"\xe9\x00\x01\x00\x00",
                ),
            ],
        )
        errors = patcher.verify_spec(spec)
        assert len(errors) == 1
        assert "SHA256 mismatch" in errors[0]

    def test_verify_fails_offset_beyond_file(self, fake_binary, fake_binary_sha):
        patcher = BinaryPatcher(fake_binary)
        spec = PatchSpec(
            spec_version="1.0",
            binary_sha256=fake_binary_sha,
            description="OOB patch",
            patches=[
                Patch(
                    id="oob",
                    description="Beyond EOF",
                    file_offset=0xFFFF,
                    old_bytes=b"\x00",
                    new_bytes=b"\xFF",
                ),
            ],
        )
        errors = patcher.verify_spec(spec)
        assert len(errors) == 1
        assert "exceeds binary size" in errors[0]


# ============================================================
# BinaryPatcher: apply tests
# ============================================================


class TestApply:
    def test_apply_writes_new_bytes(self, fake_binary, simple_spec):
        patcher = BinaryPatcher(fake_binary)

        with mock_patch.object(patcher, "resign", return_value=True):
            result = patcher.apply(simple_spec)

        assert result.success
        assert result.patches_applied == 1
        assert result.backup_path is not None
        assert result.backup_path.exists()

        # Verify the patch was written
        patched_data = fake_binary.read_bytes()
        assert patched_data[0x100:0x105] == b"\xe9\x00\x01\x00\x00"

    def test_apply_creates_backup(self, fake_binary, simple_spec):
        patcher = BinaryPatcher(fake_binary)
        original_data = fake_binary.read_bytes()

        with mock_patch.object(patcher, "resign", return_value=True):
            result = patcher.apply(simple_spec)

        assert result.backup_path.read_bytes() == original_data

    def test_apply_atomic_aborts_on_verification_failure(self, fake_binary, fake_binary_sha):
        """If ANY patch fails verification, NONE should be applied."""
        patcher = BinaryPatcher(fake_binary)
        original_data = fake_binary.read_bytes()

        bad_spec = PatchSpec(
            spec_version="1.0",
            binary_sha256=fake_binary_sha,
            description="Mixed good/bad",
            patches=[
                Patch(
                    id="good",
                    description="Valid patch",
                    file_offset=0x100,
                    old_bytes=b"\x55\x48\x89\xe5",
                    new_bytes=b"\xe9\x00\x01\x00",
                ),
                Patch(
                    id="bad",
                    description="Bad patch",
                    file_offset=0x300,
                    old_bytes=b"\xDE\xAD\xBE\xEF",  # Won't match
                    new_bytes=b"\x01\x02\x03\x04",
                ),
            ],
        )

        result = patcher.apply(bad_spec)
        assert not result.success
        assert result.patches_applied == 0
        # Binary should be unchanged
        assert fake_binary.read_bytes() == original_data

    def test_apply_multi_patch(self, fake_binary, multi_patch_spec):
        patcher = BinaryPatcher(fake_binary)

        with mock_patch.object(patcher, "resign", return_value=True):
            result = patcher.apply(multi_patch_spec)

        assert result.success
        assert result.patches_applied == 2

        patched = fake_binary.read_bytes()
        assert patched[0x100:0x104] == b"\xe9\x00\x01\x00"
        assert patched[0x200:0x204] == b"\xe9\x00\x02\x00"


# ============================================================
# BinaryPatcher: revert tests
# ============================================================


class TestRevert:
    def test_revert_restores_original(self, fake_binary, simple_spec):
        patcher = BinaryPatcher(fake_binary)
        original_data = fake_binary.read_bytes()

        with mock_patch.object(patcher, "resign", return_value=True):
            patcher.apply(simple_spec)

        # Binary should be changed
        assert fake_binary.read_bytes() != original_data

        with mock_patch.object(patcher, "resign", return_value=True):
            assert patcher.revert()

        # Binary should be restored
        assert fake_binary.read_bytes() == original_data

    def test_revert_without_backup_returns_false(self, fake_binary):
        patcher = BinaryPatcher(fake_binary)
        assert not patcher.revert()

    def test_revert_cleans_state(self, fake_binary, simple_spec):
        patcher = BinaryPatcher(fake_binary)

        with mock_patch.object(patcher, "resign", return_value=True):
            patcher.apply(simple_spec)

        assert patcher.get_state() is not None

        with mock_patch.object(patcher, "resign", return_value=True):
            patcher.revert()

        assert patcher.get_state() is None


# ============================================================
# BinaryPatcher: state tracking
# ============================================================


class TestStateTracking:
    def test_state_saved_on_apply(self, fake_binary, simple_spec):
        patcher = BinaryPatcher(fake_binary)

        with mock_patch.object(patcher, "resign", return_value=True):
            patcher.apply(simple_spec)

        state = patcher.get_state()
        assert state is not None
        assert state["spec_description"] == "Test patch"
        assert state["patches_applied"] == 1
        assert state["patch_ids"] == ["test_patch_1"]
        assert state["metadata"] == {"test": True}

    def test_no_state_before_apply(self, fake_binary):
        patcher = BinaryPatcher(fake_binary)
        assert patcher.get_state() is None


# ============================================================
# PatchSpec: serialization
# ============================================================


class TestPatchSpecSerialization:
    def test_roundtrip(self, simple_spec, tmp_path):
        path = tmp_path / "spec.json"
        BinaryPatcher.save_spec(simple_spec, path)
        loaded = BinaryPatcher.load_spec(path)

        assert loaded.spec_version == simple_spec.spec_version
        assert loaded.binary_sha256 == simple_spec.binary_sha256
        assert loaded.description == simple_spec.description
        assert len(loaded.patches) == len(simple_spec.patches)
        assert loaded.patches[0].id == simple_spec.patches[0].id
        assert loaded.patches[0].old_bytes == simple_spec.patches[0].old_bytes
        assert loaded.patches[0].new_bytes == simple_spec.patches[0].new_bytes
        assert loaded.metadata == simple_spec.metadata

    def test_patch_to_from_dict(self):
        p = Patch(
            id="test",
            description="desc",
            file_offset=0x100,
            old_bytes=b"\xAB\xCD",
            new_bytes=b"\xEF\x01",
        )
        d = p.to_dict()
        p2 = Patch.from_dict(d)
        assert p2.id == p.id
        assert p2.file_offset == p.file_offset
        assert p2.old_bytes == p.old_bytes
        assert p2.new_bytes == p.new_bytes


# ============================================================
# VA ↔ file offset conversion
# ============================================================


class TestVAConversion:
    @pytest.fixture
    def binary_info(self):
        return BinaryInfo(
            path=Path("/fake/FTL"),
            architecture="x86_64",
            pie=True,
            code_signed=False,
            hardened_runtime=False,
            signing_identity=None,
            segments=[
                SegmentInfo(
                    name="__TEXT",
                    virtual_address=0x100000000,
                    virtual_size=0x200000,
                    file_offset=0,
                    file_size=0x200000,
                    sections=["__text", "__cstring"],
                ),
                SegmentInfo(
                    name="__DATA",
                    virtual_address=0x100200000,
                    virtual_size=0x50000,
                    file_offset=0x200000,
                    file_size=0x50000,
                    sections=["__data"],
                ),
            ],
            augment_strings=[],
            code_caves=[],
            linked_libraries=[],
            file_size=0x250000,
        )

    def test_va_to_file_offset(self, binary_info):
        from ftl_gen.binary.recon import BinaryRecon

        # VA 0x100000100 → file offset 0x100 (in __TEXT segment)
        assert BinaryRecon.va_to_file_offset(binary_info, 0x100000100) == 0x100

    def test_va_to_file_offset_data_segment(self, binary_info):
        from ftl_gen.binary.recon import BinaryRecon

        # VA 0x100200010 → file offset 0x200010 (in __DATA segment)
        assert BinaryRecon.va_to_file_offset(binary_info, 0x100200010) == 0x200010

    def test_va_to_file_offset_invalid(self, binary_info):
        from ftl_gen.binary.recon import BinaryRecon

        with pytest.raises(ValueError, match="not in any segment"):
            BinaryRecon.va_to_file_offset(binary_info, 0xDEADBEEF)

    def test_file_offset_to_va(self, binary_info):
        from ftl_gen.binary.recon import BinaryRecon

        assert BinaryRecon.file_offset_to_va(binary_info, 0x100) == 0x100000100

    def test_roundtrip_conversion(self, binary_info):
        from ftl_gen.binary.recon import BinaryRecon

        va = 0x1000A2740
        offset = BinaryRecon.va_to_file_offset(binary_info, va)
        va2 = BinaryRecon.file_offset_to_va(binary_info, offset)
        assert va == va2


# ============================================================
# SSO string encoding
# ============================================================


class TestSSOEncoding:
    def test_sso_string_encoding_basic(self):
        from ftl_gen.binary.trampoline import encode_sso_string

        result = encode_sso_string("SCRAP_COLLECTOR")
        assert len(result) == 24
        # First byte: length << 1 (15 << 1 = 30)
        assert result[0] == 30
        # Data starts at byte 1
        assert result[1:16] == b"SCRAP_COLLECTOR"
        # Rest is NUL
        assert result[16:] == b"\x00" * 8

    def test_sso_string_encoding_short(self):
        from ftl_gen.binary.trampoline import encode_sso_string

        result = encode_sso_string("AB")
        assert len(result) == 24
        assert result[0] == 4  # 2 << 1
        assert result[1:3] == b"AB"
        assert result[3:] == b"\x00" * 21

    def test_sso_string_encoding_max_length(self):
        from ftl_gen.binary.trampoline import encode_sso_string

        s = "A" * 22
        result = encode_sso_string(s)
        assert len(result) == 24
        assert result[0] == 44  # 22 << 1
        assert result[1:23] == b"A" * 22

    def test_sso_string_too_long(self):
        from ftl_gen.binary.trampoline import encode_sso_string

        with pytest.raises(ValueError, match="too long for SSO"):
            encode_sso_string("A" * 23)

    def test_sso_string_empty(self):
        from ftl_gen.binary.trampoline import encode_sso_string

        result = encode_sso_string("")
        assert len(result) == 24
        assert result[0] == 0  # 0 << 1
        assert result[1:] == b"\x00" * 23


# ============================================================
# AugmentMapping validation
# ============================================================


class TestAugmentMapping:
    def test_valid_mapping(self):
        from ftl_gen.binary.trampoline import AugmentMapping

        m = AugmentMapping(custom_name="CUSTOM_SCRAP", vanilla_name="SCRAP_COLLECTOR")
        assert m.custom_name == "CUSTOM_SCRAP"
        assert m.vanilla_name == "SCRAP_COLLECTOR"

    def test_custom_name_too_long(self):
        from ftl_gen.binary.trampoline import AugmentMapping

        with pytest.raises(ValueError, match="too long"):
            AugmentMapping(custom_name="A" * 23, vanilla_name="SCRAP_COLLECTOR")

    def test_vanilla_name_too_long(self):
        from ftl_gen.binary.trampoline import AugmentMapping

        with pytest.raises(ValueError, match="too long"):
            AugmentMapping(custom_name="TEST", vanilla_name="A" * 23)


# ============================================================
# AugmentEffectMapper
# ============================================================


class TestAugmentEffectMapper:
    def test_suggest_scrap(self):
        from ftl_gen.binary.effects import AugmentEffectMapper

        mapper = AugmentEffectMapper()
        assert mapper.suggest_mapping("Bonus scrap from battles") == "SCRAP_COLLECTOR"

    def test_suggest_weapon_charge(self):
        from ftl_gen.binary.effects import AugmentEffectMapper

        mapper = AugmentEffectMapper()
        assert mapper.suggest_mapping("Faster weapon charge speed") == "AUTO_COOLDOWN"

    def test_suggest_missile(self):
        from ftl_gen.binary.effects import AugmentEffectMapper

        mapper = AugmentEffectMapper()
        assert mapper.suggest_mapping("Chance to not use a missile") == "EXPLOSIVE_REPLICATOR"

    def test_suggest_no_match(self):
        from ftl_gen.binary.effects import AugmentEffectMapper

        mapper = AugmentEffectMapper()
        assert mapper.suggest_mapping("Completely unique alien effect") is None

    def test_get_vanilla_effects(self):
        from ftl_gen.binary.effects import AugmentEffectMapper

        effects = AugmentEffectMapper.get_vanilla_effects()
        assert "SCRAP_COLLECTOR" in effects
        assert "WEAPON_PREIGNITE" in effects
        assert len(effects) >= 30

    def test_get_vanilla_effect_exists(self):
        from ftl_gen.binary.effects import AugmentEffectMapper

        desc = AugmentEffectMapper.get_vanilla_effect("SCRAP_COLLECTOR")
        assert desc is not None
        assert "scrap" in desc.lower()

    def test_get_vanilla_effect_missing(self):
        from ftl_gen.binary.effects import AugmentEffectMapper

        assert AugmentEffectMapper.get_vanilla_effect("NOT_A_REAL_AUGMENT") is None


# ============================================================
# TrampolineBuilder
# ============================================================


class TestTrampolineBuilder:
    """Tests for trampoline code generation.

    Uses a synthetic BinaryInfo to test code generation without
    needing the real FTL binary.
    """

    @pytest.fixture
    def binary_info(self):
        return BinaryInfo(
            path=Path("/fake/FTL"),
            architecture="x86_64",
            pie=True,
            code_signed=False,
            hardened_runtime=False,
            signing_identity=None,
            segments=[
                SegmentInfo(
                    name="__TEXT",
                    virtual_address=0x100000000,
                    virtual_size=0x200000,
                    file_offset=0,
                    file_size=0x200000,
                    sections=["__text"],
                ),
            ],
            augment_strings=[],
            code_caves=[
                CodeCave(file_offset=0x150000, size=4096, segment="__TEXT"),
            ],
            linked_libraries=[],
            file_size=0x200000,
        )

    @pytest.fixture
    def fake_binary_data(self):
        """Build fake binary data with known prologues at the expected offsets."""
        from ftl_gen.binary.trampoline import (
            HAS_AUG_DISPLACED_SIZE,
            HAS_AUGMENTATION_VA,
            GET_AUG_VAL_DISPLACED_SIZE,
            GET_AUGMENTATION_VALUE_VA,
        )

        data = bytearray(0x200000)

        # Write prologue at HasAugmentation file offset
        # VA 0x1000a2740, __TEXT starts at VA 0x100000000, file offset 0
        # So file offset = 0x0a2740
        has_offset = HAS_AUGMENTATION_VA - 0x100000000
        prologue = b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x54\x53\x48\x83\xec"
        data[has_offset:has_offset + len(prologue)] = prologue

        # Write prologue at GetAugmentationValue file offset
        get_offset = GET_AUGMENTATION_VALUE_VA - 0x100000000
        data[get_offset:get_offset + len(prologue)] = prologue

        return bytes(data)

    def test_trampoline_generates_code(self, binary_info, fake_binary_data):
        from ftl_gen.binary.trampoline import AugmentMapping, TrampolineBuilder

        builder = TrampolineBuilder(binary_info)
        mappings = [
            AugmentMapping(custom_name="CUSTOM_SCRAP", vanilla_name="SCRAP_COLLECTOR"),
        ]

        spec = builder.build(mappings, fake_binary_data)

        assert spec.description.startswith("Augment effect remapping")
        assert len(spec.patches) == 3  # hook1, hook2, cave code
        assert spec.metadata["augment_mappings"][0]["custom"] == "CUSTOM_SCRAP"

    def test_trampoline_hook_patches_are_correct_size(self, binary_info, fake_binary_data):
        from ftl_gen.binary.trampoline import (
            AugmentMapping,
            HAS_AUG_DISPLACED_SIZE,
            GET_AUG_VAL_DISPLACED_SIZE,
            TrampolineBuilder,
        )

        builder = TrampolineBuilder(binary_info)
        mappings = [
            AugmentMapping(custom_name="TEST_AUG", vanilla_name="AUTO_COOLDOWN"),
        ]

        spec = builder.build(mappings, fake_binary_data)

        # Hook patches should be same size as displaced prologues
        hook1 = spec.patches[0]
        assert len(hook1.new_bytes) == HAS_AUG_DISPLACED_SIZE
        assert hook1.new_bytes[0] == 0xE9  # JMP opcode

        hook2 = spec.patches[1]
        assert len(hook2.new_bytes) == GET_AUG_VAL_DISPLACED_SIZE
        assert hook2.new_bytes[0] == 0xE9

    def test_trampoline_multiple_mappings(self, binary_info, fake_binary_data):
        from ftl_gen.binary.trampoline import AugmentMapping, TrampolineBuilder

        builder = TrampolineBuilder(binary_info)
        mappings = [
            AugmentMapping(custom_name="CUSTOM_SCRAP", vanilla_name="SCRAP_COLLECTOR"),
            AugmentMapping(custom_name="CUSTOM_COOL", vanilla_name="AUTO_COOLDOWN"),
            AugmentMapping(custom_name="CUSTOM_SHIELD", vanilla_name="SHIELD_RECHARGE"),
        ]

        spec = builder.build(mappings, fake_binary_data)

        assert len(spec.metadata["augment_mappings"]) == 3
        assert spec.metadata["cave_size_used"] <= spec.metadata["cave_size_available"]

    @pytest.mark.skipif(
        not _can_import("capstone"),
        reason="capstone not installed",
    )
    def test_trampoline_disassembles_cleanly(self, binary_info, fake_binary_data):
        """Verify generated trampoline contains no invalid instructions."""
        from ftl_gen.binary.trampoline import (
            AugmentMapping,
            TrampolineBuilder,
            verify_trampoline,
        )

        builder = TrampolineBuilder(binary_info)
        mappings = [
            AugmentMapping(custom_name="CUSTOM_SCRAP", vanilla_name="SCRAP_COLLECTOR"),
        ]

        spec = builder.build(mappings, fake_binary_data)
        cave_patch = spec.patches[2]  # The code cave patch

        cave_va = spec.metadata["cave_va"]
        instructions = verify_trampoline(cave_patch.new_bytes, cave_va)

        # Should have a reasonable number of instructions
        assert len(instructions) > 10
        # Should contain push/pop for register saves
        mnemonics = [i["mnemonic"] for i in instructions]
        assert "push" in mnemonics
        assert "pop" in mnemonics
        # Should contain jmp for return
        assert "jmp" in mnemonics or "je" in mnemonics

    def test_trampoline_displaced_instructions_present(self, binary_info, fake_binary_data):
        """Verify displaced prologue bytes appear in the cave code."""
        from ftl_gen.binary.trampoline import (
            AugmentMapping,
            HAS_AUG_DISPLACED_SIZE,
            HAS_AUGMENTATION_VA,
            TrampolineBuilder,
        )

        builder = TrampolineBuilder(binary_info)
        mappings = [
            AugmentMapping(custom_name="TEST_AUG", vanilla_name="AUTO_COOLDOWN"),
        ]

        spec = builder.build(mappings, fake_binary_data)
        cave_code = spec.patches[2].new_bytes

        # The displaced prologue should appear somewhere in the cave code
        has_offset = HAS_AUGMENTATION_VA - 0x100000000
        displaced = fake_binary_data[has_offset:has_offset + HAS_AUG_DISPLACED_SIZE]

        assert displaced in cave_code

    def test_no_cave_raises(self, fake_binary_data):
        """Verify error when no code cave is large enough."""
        from ftl_gen.binary.trampoline import AugmentMapping, TrampolineBuilder

        no_cave_info = BinaryInfo(
            path=Path("/fake/FTL"),
            architecture="x86_64",
            pie=True,
            code_signed=False,
            hardened_runtime=False,
            signing_identity=None,
            segments=[
                SegmentInfo(
                    name="__TEXT",
                    virtual_address=0x100000000,
                    virtual_size=0x200000,
                    file_offset=0,
                    file_size=0x200000,
                    sections=[],
                ),
            ],
            augment_strings=[],
            code_caves=[],  # No caves!
            linked_libraries=[],
            file_size=0x200000,
        )

        builder = TrampolineBuilder(no_cave_info)
        with pytest.raises(ValueError, match="No code cave"):
            builder.build(
                [AugmentMapping(custom_name="TEST", vanilla_name="SCRAP_COLLECTOR")],
                fake_binary_data,
            )


# ============================================================
# Schema: effect_source field
# ============================================================


class TestAugmentBlueprintEffectSource:
    def test_effect_source_default_none(self):
        from ftl_gen.xml.schemas import AugmentBlueprint

        aug = AugmentBlueprint(
            name="TEST_AUG",
            title="Test Augment",
            desc="A test augment",
            cost=50,
        )
        assert aug.effect_source is None

    def test_effect_source_set(self):
        from ftl_gen.xml.schemas import AugmentBlueprint

        aug = AugmentBlueprint(
            name="CUSTOM_SCRAP",
            title="Scrap Bonus",
            desc="Gives bonus scrap",
            cost=60,
            effect_source="SCRAP_COLLECTOR",
        )
        assert aug.effect_source == "SCRAP_COLLECTOR"

    def test_effect_source_in_json(self):
        from ftl_gen.xml.schemas import AugmentBlueprint

        aug = AugmentBlueprint(
            name="TEST",
            title="Test",
            desc="Test",
            cost=50,
            effect_source="AUTO_COOLDOWN",
        )
        data = aug.model_dump()
        assert data["effect_source"] == "AUTO_COOLDOWN"


# ============================================================
# Integration test (requires real FTL binary)
# ============================================================


@pytest.mark.integration
class TestIntegration:
    """Integration tests that require the real FTL binary.

    Run with: pytest -m integration tests/test_binary_patcher.py
    """

    @pytest.fixture
    def ftl_binary(self):
        from ftl_gen.config import get_settings

        settings = get_settings()
        binary_path = settings.find_ftl_executable()
        if binary_path is None or not binary_path.exists():
            pytest.skip("FTL binary not found")
        return binary_path

    def test_full_roundtrip(self, ftl_binary, tmp_path):
        """Generate spec, apply, verify changes, revert, verify original."""
        from ftl_gen.binary.effects import AugmentEffectMapper
        from ftl_gen.binary.patcher import BinaryPatcher
        from ftl_gen.binary.recon import BinaryRecon
        from ftl_gen.binary.trampoline import AugmentMapping

        # Use a copy to avoid modifying the real binary
        test_binary = tmp_path / "FTL"
        test_binary.write_bytes(ftl_binary.read_bytes())

        recon = BinaryRecon(test_binary)
        info = recon.analyze()
        binary_data = test_binary.read_bytes()

        mappings = [
            AugmentMapping(custom_name="CUSTOM_SCRAP", vanilla_name="SCRAP_COLLECTOR"),
        ]

        mapper = AugmentEffectMapper()
        spec = mapper.build_patch_spec(mappings, info, binary_data)

        patcher = BinaryPatcher(test_binary)

        with mock_patch.object(patcher, "resign", return_value=True):
            result = patcher.apply(spec)

        assert result.success
        assert result.patches_applied == 3

        # Binary should be changed
        patched_data = test_binary.read_bytes()
        assert patched_data != binary_data

        # Revert
        with mock_patch.object(patcher, "resign", return_value=True):
            assert patcher.revert()

        # Binary should be restored
        assert test_binary.read_bytes() == binary_data


