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

# Number of prologue bytes to displace (must cover complete instructions)
# These are verified against the actual binary before patching.
# ShipObject::HasAugmentation prologue (14 bytes):
#   push rbp; mov rbp, rsp; push r15; push r14; push rbx; sub rsp, 0x28
HAS_AUG_DISPLACED_SIZE = 14
# ShipObject::GetAugmentationValue prologue (14 bytes):
#   push rbp; mov rbp, rsp; push r15; push r14; push rbx; sub rsp, 0x28
GET_AUG_VAL_DISPLACED_SIZE = 14

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
    matches a custom augment name, RSI is redirected to point to an
    SSO string in the code cave containing the vanilla name.

    Layout of generated code in the cave:

        [trampoline for HasAugmentation]
            save registers
            extract C string pointer from RSI (SSO-aware)
            for each mapping:
                compare with custom name
                if match: lea rsi, [vanilla_sso_string]
            restore registers
            displaced prologue instructions
            jmp back to original+N

        [trampoline for GetAugmentationValue]
            (same structure)

        [data section]
            custom_name_1: db "CUSTOM_NAME", 0    (C strings for comparison)
            vanilla_sso_1: <24 bytes SSO string>   (replacement strings)
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
        # Phase 1: Build the data section (custom C-strings + vanilla SSO strings)
        # We need to know data offsets to generate RIP-relative LEA instructions.
        # Strategy: build code first with placeholder offsets, then fix up.
        # Simpler: pre-compute data layout, then generate code with known offsets.

        # Data layout: for each mapping, we store:
        #   - C string of custom name (NUL-terminated, for byte-by-byte compare)
        #   - SSO string of vanilla name (24 bytes, the replacement std::string)
        data_entries: list[tuple[bytes, bytes]] = []
        for m in mappings:
            custom_cstr = m.custom_name.encode("ascii") + b"\x00"
            vanilla_sso = encode_sso_string(m.vanilla_name)
            data_entries.append((custom_cstr, vanilla_sso))

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
        # Track offsets of each custom C-string and vanilla SSO within the data section
        custom_str_offsets: list[int] = []
        vanilla_sso_offsets: list[int] = []
        for custom_cstr, vanilla_sso in data_entries:
            custom_str_offsets.append(data_offset + len(data_section))
            data_section.extend(custom_cstr)
            # Align SSO string to 8 bytes
            while len(data_section) % 8 != 0:
                data_section.append(0)
            vanilla_sso_offsets.append(data_offset + len(data_section))
            data_section.extend(vanilla_sso)

        # Now generate the two trampolines
        has_tramp = self._generate_trampoline(
            cave_va=cave_va,
            tramp_offset=has_tramp_offset,
            custom_str_offsets=custom_str_offsets,
            vanilla_sso_offsets=vanilla_sso_offsets,
            displaced_prologue=has_aug_prologue,
            return_va=HAS_AUGMENTATION_VA + HAS_AUG_DISPLACED_SIZE,
            target_size=one_tramp_size,
        )

        get_tramp = self._generate_trampoline(
            cave_va=cave_va,
            tramp_offset=get_tramp_offset,
            custom_str_offsets=custom_str_offsets,
            vanilla_sso_offsets=vanilla_sso_offsets,
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
        custom_str_offsets: list[int],
        vanilla_sso_offsets: list[int],
        displaced_prologue: bytes,
        return_va: int,
        target_size: int,
    ) -> bytes:
        """Generate a single trampoline's machine code.

        The trampoline:
        1. Saves scratch registers
        2. Reads the C string from the std::string* in RSI (SSO-aware)
        3. For each mapping, compares and optionally redirects RSI
        4. Restores scratch registers
        5. Executes displaced prologue
        6. JMPs back to original function + N

        Register usage:
            RSI = std::string* argument (what we want to swap)
            RAX = scratch (C string pointer, then comparison result)
            RCX = scratch (pointer to custom name C-string in cave)
            RDX = saved across comparison
        """
        code = bytearray()
        tramp_va = cave_va + tramp_offset

        def current_va() -> int:
            return tramp_va + len(code)

        def emit(data: bytes) -> None:
            code.extend(data)

        # --- Save scratch registers ---
        emit(b"\x50")          # push rax
        emit(b"\x51")          # push rcx
        emit(b"\x52")          # push rdx

        # --- Extract C string pointer from std::string* in RSI ---
        # libc++ SSO: if (byte[0] & 1) == 0 → short string, data at RSI+1
        #             if (byte[0] & 1) == 1 → long string, pointer at RSI+16
        emit(b"\x48\x89\xf0")                 # mov rax, rsi
        emit(b"\xf6\x00\x01")                 # test byte [rax], 1
        # jz .inline (short string) — we'll patch the offset
        jz_pos = len(code)
        emit(b"\x74\x00")                     # jz .inline (placeholder)
        # Long string: load heap pointer
        emit(b"\x48\x8b\x40\x10")             # mov rax, [rax + 16]
        # jmp .compare
        jmp_pos = len(code)
        emit(b"\xeb\x00")                     # jmp .compare (placeholder)
        # .inline:
        inline_target = len(code)
        emit(b"\x48\x83\xc0\x01")             # add rax, 1  (inline data at offset 1)
        # .compare:
        compare_target = len(code)

        # Patch the jz and jmp offsets
        code[jz_pos + 1] = inline_target - (jz_pos + 2)
        code[jmp_pos + 1] = compare_target - (jmp_pos + 2)

        # RAX now points to the C string data.
        # --- For each mapping: compare and conditionally redirect ---
        for i, (custom_off, vanilla_off) in enumerate(
            zip(custom_str_offsets, vanilla_sso_offsets)
        ):
            # lea rcx, [rip + custom_name_cstr]
            # RIP-relative: target = cave_va + custom_off
            # RIP at this instruction = current_va() + 7 (lea is 7 bytes)
            lea_va = current_va()
            target_va = cave_va + custom_off
            rel = target_va - (lea_va + 7)
            emit(b"\x48\x8d\x0d")             # lea rcx, [rip + rel32]
            emit(struct.pack("<i", rel))

            # Inline byte-by-byte string compare (RAX vs RCX)
            # Save RAX (we need to preserve the original pointer)
            emit(b"\x52")                      # push rdx (save)
            emit(b"\x48\x89\xc2")             # mov rdx, rax  (copy to rdx for compare)

            # .loop_N:
            loop_start = len(code)
            emit(b"\x8a\x02")                 # mov al, [rdx]
            emit(b"\x3a\x01")                 # cmp al, [rcx]
            # jne .next_N
            jne_pos = len(code)
            emit(b"\x75\x00")                 # jne .next (placeholder)
            # test al, al (check for NUL terminator = match!)
            emit(b"\x84\xc0")                 # test al, al
            # je .match_N
            je_pos = len(code)
            emit(b"\x74\x00")                 # je .match (placeholder)
            # Advance pointers
            emit(b"\x48\xff\xc2")             # inc rdx
            emit(b"\x48\xff\xc1")             # inc rcx
            # jmp .loop_N
            loop_back = loop_start - (len(code) + 2)
            emit(b"\xeb")
            emit(struct.pack("<b", loop_back))

            # .match_N: redirect RSI to vanilla SSO string in cave
            match_target = len(code)
            code[je_pos + 1] = match_target - (je_pos + 2)

            emit(b"\x5a")                      # pop rdx (restore)
            # Restore RAX from what we pushed before
            # Actually we need to restore the original RAX. Let's use the stack.
            # lea rsi, [rip + vanilla_sso]
            lea2_va = current_va()
            vanilla_va = cave_va + vanilla_off
            rel2 = vanilla_va - (lea2_va + 7)
            emit(b"\x48\x8d\x35")             # lea rsi, [rip + rel32]
            emit(struct.pack("<i", rel2))
            # jmp .done (skip remaining comparisons)
            jmp_done_pos = len(code)
            emit(b"\xe9\x00\x00\x00\x00")     # jmp .done (placeholder, rel32)
            # We'll patch this after we know .done's position

            # .next_N: not a match, continue to next mapping
            next_target = len(code)
            code[jne_pos + 1] = next_target - (jne_pos + 2)
            emit(b"\x5a")                      # pop rdx (restore)

        # .done: restore registers, execute displaced prologue, jmp back
        done_target = len(code)

        # Patch all jmp .done instructions
        # Walk backwards looking for our jmp placeholders
        # Each mapping emits a jmp rel32 at jmp_done positions
        # We need to go back and fix them. Let's do it by re-scanning.
        # Actually, let's track them.
        # Re-scan: we stored jmp_done_pos for the last mapping.
        # We need to track all of them. Let me refactor.

        # We'll collect jmp_done positions and patch them after the loop.
        # Since we can't easily go back, let's use a different approach:
        # track positions as we go.

        # Hmm, we already emitted the code. Let me patch them now.
        # The pattern is: \xe9\x00\x00\x00\x00 (5 bytes) for jmp .done
        # We need to find all of them. But we only saved the last one.
        # Let me fix this by re-generating with proper tracking.
        pass

        # OK — I realize the approach above doesn't properly track the jmp .done
        # positions. Let me restart the per-mapping loop with proper tracking.
        # But we already emitted code... Let me use a cleaner approach.

        # Let's rebuild using a two-pass approach. First pass collects offsets,
        # second pass generates code. For now, with the code already emitted,
        # let me just re-implement cleanly.

        # Clear and restart from save registers
        code.clear()

        # This time, track jmp_done positions properly
        jmp_done_positions: list[int] = []

        # --- Save scratch registers ---
        emit(b"\x50")          # push rax
        emit(b"\x51")          # push rcx
        emit(b"\x52")          # push rdx

        # --- Extract C string pointer from std::string* in RSI ---
        emit(b"\x48\x89\xf0")                 # mov rax, rsi
        emit(b"\xf6\x00\x01")                 # test byte [rax], 1
        jz_pos = len(code)
        emit(b"\x74\x00")                     # jz .inline (placeholder)
        emit(b"\x48\x8b\x40\x10")             # mov rax, [rax + 16]
        jmp_pos = len(code)
        emit(b"\xeb\x00")                     # jmp .compare (placeholder)
        inline_target = len(code)
        emit(b"\x48\x83\xc0\x01")             # add rax, 1
        compare_target = len(code)
        code[jz_pos + 1] = inline_target - (jz_pos + 2)
        code[jmp_pos + 1] = compare_target - (jmp_pos + 2)

        # --- Per-mapping comparison ---
        for i, (custom_off, vanilla_off) in enumerate(
            zip(custom_str_offsets, vanilla_sso_offsets)
        ):
            # lea rcx, [rip + custom_name]
            lea_va = current_va()
            target_va = cave_va + custom_off
            rel = target_va - (lea_va + 7)
            emit(b"\x48\x8d\x0d")
            emit(struct.pack("<i", rel))

            # Save rax for use as compare pointer
            emit(b"\x48\x89\xc2")             # mov rdx, rax

            # Inline strcmp loop
            loop_start = len(code)
            emit(b"\x0f\xb6\x02")             # movzx eax, byte [rdx]  (zero-extend)
            emit(b"\x3a\x01")                 # cmp al, [rcx]
            jne_pos = len(code)
            emit(b"\x75\x00")                 # jne .next (placeholder)
            emit(b"\x84\xc0")                 # test al, al
            je_pos = len(code)
            emit(b"\x74\x00")                 # je .match (placeholder)
            emit(b"\x48\xff\xc2")             # inc rdx
            emit(b"\x48\xff\xc1")             # inc rcx
            loop_back = loop_start - (len(code) + 2)
            emit(b"\xeb")
            emit(struct.pack("<b", loop_back))

            # .match: redirect RSI
            match_target = len(code)
            code[je_pos + 1] = match_target - (je_pos + 2)

            lea2_va = current_va()
            vanilla_va = cave_va + vanilla_off
            rel2 = vanilla_va - (lea2_va + 7)
            emit(b"\x48\x8d\x35")             # lea rsi, [rip + rel32]
            emit(struct.pack("<i", rel2))

            jmp_done_positions.append(len(code))
            emit(b"\xe9\x00\x00\x00\x00")     # jmp .done (placeholder)

            # .next: not a match
            next_target = len(code)
            code[jne_pos + 1] = next_target - (jne_pos + 2)

            # Restore rax from rdx for next comparison (mov rax, rdx not needed
            # since we preserved original rax meaning via rdx copy — but we
            # clobbered eax with movzx. Reload from the SSO extraction.)
            # Actually, let me re-extract: the original C-string pointer was in RAX
            # before we did mov rdx, rax. We clobbered RAX in the loop. Let's
            # restore it from RDX which still holds the original start.
            # Wait — RDX was advanced by inc. We need a different approach.

            # Fix: save original RAX on stack before each comparison
            # This means we need to push/pop around each mapping check.
            # Let me restructure to save/restore rax properly.

        # Hmm, there's a register allocation issue. RAX gets clobbered in the
        # compare loop (movzx eax) and RDX gets incremented. For the next mapping
        # we need the original C-string pointer again.
        #
        # Solution: Use R8 to hold the original C-string pointer (callee must save
        # it, but we save/restore all our scratch regs anyway).
        # Let me redo this cleanly one more time.

        code.clear()
        jmp_done_positions.clear()

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

        for i, (custom_off, vanilla_off) in enumerate(
            zip(custom_str_offsets, vanilla_sso_offsets)
        ):
            # lea rcx, [rip + custom_name]
            lea_va = current_va()
            rel = (cave_va + custom_off) - (lea_va + 7)
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

            # .match: redirect RSI to vanilla SSO string
            match_target = len(code)
            code[je_pos + 1] = match_target - (je_pos + 2)

            lea2_va = current_va()
            rel2 = (cave_va + vanilla_off) - (lea2_va + 7)
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
