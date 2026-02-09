"""x86_64 trampoline code generation for augment name interception.

Generates machine code that intercepts ShipObject::HasAugmentation and
ShipObject::GetAugmentationValue to remap custom augment names to vanilla
augment names. This allows custom-named augments to inherit the mechanical
effects of vanilla augments.

Architecture:
    1. Original function prologue replaced with JMP to code cave
    2. Code cave: compare augment name, swap RSI if match, execute
       displaced prologue, JMP back to original function+N

SSO string format (libc++ on macOS x86_64):
    Short (≤22 chars): byte 0 = (length << 1), bytes 1-22 = data, NUL-terminated
    Long (>22 chars): byte 0 = 1, bytes 8-15 = size, bytes 16-23 = heap pointer
    All vanilla augment names are ≤22 chars → SSO only.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from pathlib import Path

from ftl_gen.binary.patcher import Patch, PatchSpec
from ftl_gen.binary.recon import BinaryInfo, BinaryRecon, CodeCave

logger = logging.getLogger(__name__)

# Known function addresses from Ghidra analysis
HAS_AUGMENTATION_VA = 0x1000A2740  # ShipObject::HasAugmentation
GET_AUGMENTATION_VALUE_VA = 0x1000A2870  # ShipObject::GetAugmentationValue

# Number of prologue bytes to displace (must land on an instruction boundary!)
# These are verified against the actual binary before patching.
# ShipObject::HasAugmentation prologue (13 bytes):
#   push rbp; mov rbp,rsp; push r14; push rbx; sub rsp,0x20; xor eax,eax
# Next instruction at +13: cmp dword [rdi+8], 0 (4 bytes) — do NOT split it.
HAS_AUG_DISPLACED_SIZE = 13
# ShipObject::GetAugmentationValue prologue (13 bytes):
#   push rbp; mov rbp,rsp; push r14; push rbx; sub rsp,0x20; xor eax,eax
GET_AUG_VAL_DISPLACED_SIZE = 13

# Maximum custom augment name length (SSO limit)
MAX_AUG_NAME_LEN = 22

# Size of an SSO std::string struct (libc++ on 64-bit)
SSO_STRING_SIZE = 24


@dataclass
class AugmentMapping:
    """Maps a custom augment name to a vanilla augment name."""

    custom_name: str
    vanilla_name: str

    def __post_init__(self):
        if len(self.custom_name) > MAX_AUG_NAME_LEN:
            raise ValueError(
                f"Custom augment name too long ({len(self.custom_name)} > {MAX_AUG_NAME_LEN}): "
                f"{self.custom_name}"
            )
        if len(self.vanilla_name) > MAX_AUG_NAME_LEN:
            raise ValueError(
                f"Vanilla augment name too long ({len(self.vanilla_name)} > {MAX_AUG_NAME_LEN}): "
                f"{self.vanilla_name}"
            )


def encode_sso_string(s: str) -> bytes:
    """Encode a string as a libc++ SSO std::string (24 bytes).

    Short string layout (≤22 chars):
        byte 0: (length << 1) | 0   (even = short mode)
        bytes 1..len: character data
        remaining bytes: zero-padded
    Total: always 24 bytes.
    """
    if len(s) > MAX_AUG_NAME_LEN:
        raise ValueError(f"String too long for SSO ({len(s)} > {MAX_AUG_NAME_LEN}): {s}")

    buf = bytearray(SSO_STRING_SIZE)
    buf[0] = len(s) << 1  # length in short mode (bit 0 = 0 means short)
    for i, ch in enumerate(s.encode("ascii")):
        buf[1 + i] = ch
    return bytes(buf)


def _jmp_rel32(from_va: int, to_va: int) -> bytes:
    """Generate a 5-byte JMP rel32 instruction."""
    offset = to_va - (from_va + 5)  # rel32 is relative to NEXT instruction
    return b"\xe9" + struct.pack("<i", offset)


def _nop(n: int) -> bytes:
    """Generate N bytes of NOP padding."""
    return b"\x90" * n


class TrampolineBuilder:
    """Builds x86_64 trampoline code for augment name interception.

    The trampoline intercepts the std::string* argument (RSI) before
    HasAugmentation/GetAugmentationValue processes it. If the string
    matches a vanilla augment name, RSI is redirected to point to an
    SSO string containing the custom name (what's actually on the ship).

    This makes the function search for the custom name in the ship's
    augment list, so custom-named augments inherit vanilla effects.

    Layout of generated code in the cave:

        [trampoline for HasAugmentation]
            save registers
            extract C string pointer from RSI (SSO-aware)
            for each mapping:
                compare with vanilla name (what the game looks for)
                if match: lea rsi, [custom_sso_string] (what's on the ship)
            restore registers
            displaced prologue instructions
            jmp back to original+N

        [trampoline for GetAugmentationValue]
            (same structure)

        [data section]
            vanilla_name_1: db "WEAPON_PREIGNITE", 0  (C strings to match against)
            custom_sso_1: <24 bytes SSO string>        (replacement: custom name)
            ...
    """

    def __init__(self, binary_info: BinaryInfo):
        self.binary_info = binary_info

    def build(self, mappings: list[AugmentMapping], binary_data: bytes) -> PatchSpec:
        """Generate a complete PatchSpec for the given augment mappings.

        Args:
            mappings: List of custom→vanilla augment name mappings.
            binary_data: Raw binary bytes (for reading displaced prologues).

        Returns:
            PatchSpec ready to apply.
        """
        if not mappings:
            raise ValueError("No augment mappings provided")

        # Find a code cave large enough
        cave = self._find_suitable_cave(mappings)

        # Read the displaced prologues from the binary
        has_aug_offset = BinaryRecon.va_to_file_offset(
            self.binary_info, HAS_AUGMENTATION_VA
        )
        get_aug_val_offset = BinaryRecon.va_to_file_offset(
            self.binary_info, GET_AUGMENTATION_VALUE_VA
        )

        has_aug_prologue = binary_data[
            has_aug_offset : has_aug_offset + HAS_AUG_DISPLACED_SIZE
        ]
        get_aug_val_prologue = binary_data[
            get_aug_val_offset : get_aug_val_offset + GET_AUG_VAL_DISPLACED_SIZE
        ]

        # Verify prologues look right (should start with push rbp = 0x55)
        if has_aug_prologue[0] != 0x55:
            raise ValueError(
                f"HasAugmentation prologue doesn't start with 'push rbp' (0x55). "
                f"Got: 0x{has_aug_prologue[0]:02x}. Binary may have changed."
            )
        if get_aug_val_prologue[0] != 0x55:
            raise ValueError(
                f"GetAugmentationValue prologue doesn't start with 'push rbp' (0x55). "
                f"Got: 0x{get_aug_val_prologue[0]:02x}. Binary may have changed."
            )

        # Calculate cave VA from file offset
        cave_va = BinaryRecon.file_offset_to_va(
            self.binary_info, cave.file_offset
        )

        # Build the two trampolines + data section
        cave_code, has_tramp_offset, get_tramp_offset = self._generate_cave_code(
            mappings=mappings,
            cave_va=cave_va,
            has_aug_prologue=has_aug_prologue,
            get_aug_val_prologue=get_aug_val_prologue,
        )

        if len(cave_code) > cave.size:
            raise ValueError(
                f"Generated code ({len(cave_code)} bytes) exceeds cave size "
                f"({cave.size} bytes). Reduce number of mappings or find larger cave."
            )

        # Build patch list
        patches: list[Patch] = []

        # Patch 1: Overwrite HasAugmentation prologue with JMP to cave
        has_jmp = _jmp_rel32(HAS_AUGMENTATION_VA, cave_va + has_tramp_offset)
        has_jmp += _nop(HAS_AUG_DISPLACED_SIZE - 5)
        patches.append(Patch(
            id="has_augmentation_hook",
            description="Replace HasAugmentation prologue with JMP to trampoline",
            file_offset=has_aug_offset,
            old_bytes=has_aug_prologue,
            new_bytes=has_jmp,
        ))

        # Patch 2: Overwrite GetAugmentationValue prologue with JMP to cave
        get_jmp = _jmp_rel32(GET_AUGMENTATION_VALUE_VA, cave_va + get_tramp_offset)
        get_jmp += _nop(GET_AUG_VAL_DISPLACED_SIZE - 5)
        patches.append(Patch(
            id="get_augmentation_value_hook",
            description="Replace GetAugmentationValue prologue with JMP to trampoline",
            file_offset=get_aug_val_offset,
            old_bytes=get_aug_val_prologue,
            new_bytes=get_jmp,
        ))

        # Patch 3: Write trampoline code into the code cave
        cave_old_bytes = binary_data[
            cave.file_offset : cave.file_offset + len(cave_code)
        ]
        patches.append(Patch(
            id="trampoline_code",
            description="Trampoline + data in code cave",
            file_offset=cave.file_offset,
            old_bytes=cave_old_bytes,
            new_bytes=cave_code,
        ))

        # Compute SHA256 of the binary for the spec
        import hashlib
        binary_sha = hashlib.sha256(binary_data).hexdigest()

        return PatchSpec(
            spec_version="1.0",
            binary_sha256=binary_sha,
            description=f"Augment effect remapping ({len(mappings)} mappings)",
            patches=patches,
            metadata={
                "augment_mappings": [
                    {"custom": m.custom_name, "vanilla": m.vanilla_name}
                    for m in mappings
                ],
                "cave_offset": cave.file_offset,
                "cave_va": cave_va,
                "cave_size_used": len(cave_code),
                "cave_size_available": cave.size,
            },
        )

    def _find_suitable_cave(self, mappings: list[AugmentMapping]) -> CodeCave:
        """Find a code cave large enough for the trampolines + data."""
        # Estimate size needed:
        # Two trampolines (~200 bytes each) + data per mapping (~50 bytes each)
        estimated_size = 512 + len(mappings) * 80

        for cave in self.binary_info.code_caves:
            if cave.size >= estimated_size:
                return cave

        raise ValueError(
            f"No code cave large enough ({estimated_size} bytes needed). "
            f"Largest cave: {self.binary_info.code_caves[0].size if self.binary_info.code_caves else 0} bytes."
        )

    def _generate_cave_code(
        self,
        mappings: list[AugmentMapping],
        cave_va: int,
        has_aug_prologue: bytes,
        get_aug_val_prologue: bytes,
    ) -> tuple[bytes, int, int]:
        """Generate the complete cave contents: two trampolines + data.

        Returns (cave_bytes, has_trampoline_offset, get_trampoline_offset).
        Offsets are relative to start of cave.
        """
        # Phase 1: Build the data section
        # We need to know data offsets to generate RIP-relative LEA instructions.
        #
        # The game calls HasAugmentation("VANILLA_NAME") to check for effects.
        # The ship's augment list contains "CUSTOM_NAME" (our modded augment).
        # So the trampoline must:
        #   - MATCH the function argument against the VANILLA name
        #   - SUBSTITUTE RSI with the CUSTOM name (so the function finds it in the list)
        #
        # Data layout per mapping:
        #   - C string of vanilla name (NUL-terminated, for byte-by-byte compare)
        #   - SSO string of custom name (24 bytes, the replacement std::string*)
        data_entries: list[tuple[bytes, bytes]] = []
        for m in mappings:
            vanilla_cstr = m.vanilla_name.encode("ascii") + b"\x00"
            custom_sso = encode_sso_string(m.custom_name)
            data_entries.append((vanilla_cstr, custom_sso))

        # Estimate trampoline code size to place data after both trampolines
        # Each trampoline: ~60 bytes base + ~40 bytes per mapping + displaced prologue + jmp
        per_mapping_code = 50
        trampoline_base = 80
        one_tramp_size = trampoline_base + len(mappings) * per_mapping_code
        # Round up to 16-byte alignment
        one_tramp_size = (one_tramp_size + 15) & ~15

        has_tramp_offset = 0
        get_tramp_offset = one_tramp_size
        data_offset = one_tramp_size * 2

        # Build data section
        data_section = bytearray()
        # Track offsets of each vanilla C-string and custom SSO within the data section
        match_str_offsets: list[int] = []  # vanilla C-strings to match against
        subst_sso_offsets: list[int] = []  # custom SSO strings to substitute
        for vanilla_cstr, custom_sso in data_entries:
            match_str_offsets.append(data_offset + len(data_section))
            data_section.extend(vanilla_cstr)
            # Align SSO string to 8 bytes
            while len(data_section) % 8 != 0:
                data_section.append(0)
            subst_sso_offsets.append(data_offset + len(data_section))
            data_section.extend(custom_sso)

        # Now generate the two trampolines
        has_tramp = self._generate_trampoline(
            cave_va=cave_va,
            tramp_offset=has_tramp_offset,
            match_str_offsets=match_str_offsets,
            subst_sso_offsets=subst_sso_offsets,
            displaced_prologue=has_aug_prologue,
            return_va=HAS_AUGMENTATION_VA + HAS_AUG_DISPLACED_SIZE,
            target_size=one_tramp_size,
        )

        get_tramp = self._generate_trampoline(
            cave_va=cave_va,
            tramp_offset=get_tramp_offset,
            match_str_offsets=match_str_offsets,
            subst_sso_offsets=subst_sso_offsets,
            displaced_prologue=get_aug_val_prologue,
            return_va=GET_AUGMENTATION_VALUE_VA + GET_AUG_VAL_DISPLACED_SIZE,
            target_size=one_tramp_size,
        )

        # Assemble final cave
        cave = bytearray()
        cave.extend(has_tramp)
        cave.extend(get_tramp)
        cave.extend(data_section)

        return bytes(cave), has_tramp_offset, get_tramp_offset

    def _generate_trampoline(
        self,
        cave_va: int,
        tramp_offset: int,
        match_str_offsets: list[int],
        subst_sso_offsets: list[int],
        displaced_prologue: bytes,
        return_va: int,
        target_size: int,
    ) -> bytes:
        """Generate a single trampoline's machine code.

        The trampoline:
        1. Saves scratch registers
        2. Reads the C string from the std::string* in RSI (SSO-aware)
        3. For each mapping, compares argument against vanilla name;
           if match, redirects RSI to custom name SSO string
        4. Restores scratch registers
        5. Executes displaced prologue
        6. JMPs back to original function + N

        Register usage:
            RSI = std::string* argument (what we want to swap)
            RAX = scratch (C string pointer extraction)
            RCX = scratch (pointer to match C-string in cave)
            RDX = scratch (comparison pointer)
            R8  = preserved C string pointer across comparisons
        """
        code = bytearray()
        tramp_va = cave_va + tramp_offset

        def current_va() -> int:
            return tramp_va + len(code)

        def emit(data: bytes) -> None:
            code.extend(data)

        jmp_done_positions: list[int] = []

        # --- Save registers (including R8 as our scratch) ---
        emit(b"\x50")                         # push rax
        emit(b"\x51")                         # push rcx
        emit(b"\x52")                         # push rdx
        emit(b"\x41\x50")                     # push r8

        # --- Extract C string pointer from std::string* in RSI → R8 ---
        emit(b"\x48\x89\xf0")                 # mov rax, rsi
        emit(b"\xf6\x00\x01")                 # test byte [rax], 1
        jz_pos = len(code)
        emit(b"\x74\x00")                     # jz .inline
        # Long string
        emit(b"\x4c\x8b\x40\x10")             # mov r8, [rax + 16]
        jmp_pos = len(code)
        emit(b"\xeb\x00")                     # jmp .compare
        # .inline:
        inline_target = len(code)
        emit(b"\x49\x89\xc0")                 # mov r8, rax
        emit(b"\x49\x83\xc0\x01")             # add r8, 1
        # .compare:
        compare_target = len(code)
        code[jz_pos + 1] = inline_target - (jz_pos + 2)
        code[jmp_pos + 1] = compare_target - (jmp_pos + 2)

        # R8 = pointer to C string data (preserved across comparisons)

        for i, (match_off, subst_off) in enumerate(
            zip(match_str_offsets, subst_sso_offsets)
        ):
            # lea rcx, [rip + match_name] (vanilla name to compare against)
            lea_va = current_va()
            rel = (cave_va + match_off) - (lea_va + 7)
            emit(b"\x48\x8d\x0d")
            emit(struct.pack("<i", rel))

            # rdx = r8 (copy of C string pointer for this comparison)
            emit(b"\x4c\x89\xc2")             # mov rdx, r8

            # Inline strcmp: compare [rdx] vs [rcx] byte by byte
            loop_start = len(code)
            emit(b"\x0f\xb6\x02")             # movzx eax, byte [rdx]
            emit(b"\x3a\x01")                 # cmp al, [rcx]
            jne_pos = len(code)
            emit(b"\x75\x00")                 # jne .next
            emit(b"\x84\xc0")                 # test al, al
            je_pos = len(code)
            emit(b"\x74\x00")                 # je .match
            emit(b"\x48\xff\xc2")             # inc rdx
            emit(b"\x48\xff\xc1")             # inc rcx
            loop_back = loop_start - (len(code) + 2)
            emit(b"\xeb")
            emit(struct.pack("<b", loop_back))

            # .match: redirect RSI to custom SSO string (what's on the ship)
            match_target = len(code)
            code[je_pos + 1] = match_target - (je_pos + 2)

            lea2_va = current_va()
            rel2 = (cave_va + subst_off) - (lea2_va + 7)
            emit(b"\x48\x8d\x35")             # lea rsi, [rip + rel32]
            emit(struct.pack("<i", rel2))

            jmp_done_positions.append(len(code))
            emit(b"\xe9\x00\x00\x00\x00")     # jmp .done (placeholder)

            # .next:
            next_target = len(code)
            code[jne_pos + 1] = next_target - (jne_pos + 2)

        # .done: restore regs, displaced prologue, jmp back
        done_target = len(code)

        # Patch all jmp .done placeholders
        for pos in jmp_done_positions:
            rel32 = done_target - (pos + 5)
            struct.pack_into("<i", code, pos + 1, rel32)

        # Restore registers (reverse order)
        emit(b"\x41\x58")                     # pop r8
        emit(b"\x5a")                         # pop rdx
        emit(b"\x59")                         # pop rcx
        emit(b"\x58")                         # pop rax

        # Execute displaced prologue instructions
        emit(displaced_prologue)

        # JMP back to original function + N
        jmp_back_va = current_va()
        rel_back = return_va - (jmp_back_va + 5)
        emit(b"\xe9")                          # jmp rel32
        emit(struct.pack("<i", rel_back))

        # Pad to target_size with NOPs
        while len(code) < target_size:
            emit(b"\x90")

        if len(code) > target_size:
            raise ValueError(
                f"Trampoline code ({len(code)} bytes) exceeds target size ({target_size}). "
                f"Increase per-mapping estimate or reduce mappings."
            )

        return bytes(code)


def verify_trampoline(cave_code: bytes, cave_va: int) -> list[dict]:
    """Disassemble generated trampoline code and return instruction list.

    Useful for testing and debugging the generated code.
    Requires capstone.
    """
    try:
        import capstone
    except ImportError:
        raise ImportError("capstone required: pip install -e '.[binary]'")

    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail = True

    instructions = []
    for insn in cs.disasm(cave_code, cave_va):
        instructions.append({
            "address": f"0x{insn.address:x}",
            "bytes": insn.bytes.hex(),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "size": insn.size,
        })

    return instructions
