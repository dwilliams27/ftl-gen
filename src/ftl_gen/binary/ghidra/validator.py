"""Deterministic validation of Ghidra analysis findings.

Uses capstone disassembly and raw byte checks to independently verify
claims made by the LLM analyzer. No LLM involved — pure deterministic code.

Validation types:
- byte_match: Verify string exists at claimed file offset
- disasm_verify: Verify function prologue at claimed address
- xref_verify: Verify call target exists in disassembly
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of validating a single finding."""

    finding: str
    check_type: str  # "byte_match", "disasm_verify", "xref_verify"
    passed: bool
    evidence: str
    confidence: float  # 0.0-1.0


class FindingValidator:
    """Validates analysis findings using raw binary inspection and capstone.

    This is the "ground truth" checker — it reads actual bytes from the binary
    and uses a real disassembler, independent of the LLM's analysis.
    """

    def __init__(self, binary_path: Path):
        try:
            import capstone
        except ImportError:
            raise ImportError(
                "capstone is required for binary validation. "
                "Install with: pip install -e '.[binary]'"
            )

        self.binary_path = binary_path
        self.binary_data = binary_path.read_bytes()
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.cs.detail = True

    def validate_string_at(
        self,
        file_offset: int,
        expected: str,
    ) -> ValidationResult:
        """Verify a NUL-terminated string exists at the given file offset."""
        expected_bytes = expected.encode("ascii") + b"\x00"
        actual = self.binary_data[file_offset:file_offset + len(expected_bytes)]

        passed = actual == expected_bytes
        return ValidationResult(
            finding=f"String '{expected}' at file offset 0x{file_offset:x}",
            check_type="byte_match",
            passed=passed,
            evidence=f"Actual bytes: {actual!r}" if not passed else f"Matched: {expected!r}",
            confidence=1.0 if passed else 0.0,
        )

    def validate_function_prologue(
        self,
        file_offset: int,
        virtual_address: int | None = None,
    ) -> ValidationResult:
        """Verify that bytes at the given offset look like a function prologue.

        Common x86_64 prologues:
        - push rbp; mov rbp, rsp (standard frame setup)
        - push rbx; sub rsp, N (leaf-like with callee-saved reg)
        - endbr64; push rbp; ... (CET-enabled)
        - sub rsp, N (frameless)
        """
        raw = self.binary_data[file_offset:file_offset + 32]
        va = virtual_address or file_offset
        instructions = list(self.cs.disasm(raw, va))

        if len(instructions) < 2:
            return ValidationResult(
                finding=f"Function prologue at file offset 0x{file_offset:x}",
                check_type="disasm_verify",
                passed=False,
                evidence="Could not disassemble enough instructions",
                confidence=0.0,
            )

        # Check for common prologue patterns
        first = instructions[0]
        is_prologue = False
        prologue_type = ""

        if first.mnemonic == "push" and "rbp" in first.op_str:
            # push rbp — classic frame setup
            if len(instructions) > 1 and instructions[1].mnemonic == "mov":
                is_prologue = True
                prologue_type = "push rbp; mov rbp, rsp"
            else:
                is_prologue = True
                prologue_type = "push rbp; ..."

        elif first.mnemonic == "push":
            # push <reg> — callee-saved register
            is_prologue = True
            prologue_type = f"push {first.op_str}; ..."

        elif first.mnemonic == "sub" and "rsp" in first.op_str:
            # sub rsp, N — frameless function
            is_prologue = True
            prologue_type = f"sub rsp, ..."

        elif first.mnemonic == "endbr64":
            # CET-enabled, check second instruction
            if len(instructions) > 1 and instructions[1].mnemonic == "push":
                is_prologue = True
                prologue_type = "endbr64; push ..."

        disasm_text = "; ".join(
            f"{i.mnemonic} {i.op_str}" for i in instructions[:6]
        )

        return ValidationResult(
            finding=f"Function prologue at file offset 0x{file_offset:x}",
            check_type="disasm_verify",
            passed=is_prologue,
            evidence=f"[{prologue_type}] {disasm_text}" if is_prologue else f"Not a prologue: {disasm_text}",
            confidence=0.9 if is_prologue else 0.1,
        )

    def validate_xref(
        self,
        caller_file_offset: int,
        target_virtual_address: int,
        caller_virtual_address: int | None = None,
        max_scan_bytes: int = 4096,
    ) -> ValidationResult:
        """Verify that a function at caller_offset contains a CALL/JMP to target_addr.

        Disassembles from the caller offset looking for a call/jmp instruction
        whose resolved target matches target_virtual_address.
        """
        raw = self.binary_data[caller_file_offset:caller_file_offset + max_scan_bytes]
        va = caller_virtual_address or caller_file_offset
        instructions = list(self.cs.disasm(raw, va))

        found_call = False
        call_instruction = ""

        for insn in instructions:
            if insn.mnemonic in ("call", "jmp"):
                # Resolve relative target for direct calls
                if insn.op_str.startswith("0x"):
                    try:
                        call_target = int(insn.op_str, 16)
                        if call_target == target_virtual_address:
                            found_call = True
                            call_instruction = f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}"
                            break
                    except ValueError:
                        pass

            # Stop at ret (end of function)
            if insn.mnemonic == "ret":
                break

        return ValidationResult(
            finding=f"0x{va:x} calls 0x{target_virtual_address:x}",
            check_type="xref_verify",
            passed=found_call,
            evidence=call_instruction if found_call else "CALL/JMP to target not found in disassembly",
            confidence=1.0 if found_call else 0.0,
        )

    def validate_bytes_at(
        self,
        file_offset: int,
        expected_hex: str,
    ) -> ValidationResult:
        """Verify exact bytes at a file offset match expected hex string."""
        expected = bytes.fromhex(expected_hex)
        actual = self.binary_data[file_offset:file_offset + len(expected)]

        passed = actual == expected
        actual_hex = actual.hex()

        return ValidationResult(
            finding=f"Bytes at 0x{file_offset:x} == {expected_hex}",
            check_type="byte_match",
            passed=passed,
            evidence=f"Actual: {actual_hex}" if not passed else f"Matched: {expected_hex}",
            confidence=1.0 if passed else 0.0,
        )

    def get_disassembly(
        self,
        file_offset: int,
        virtual_address: int | None = None,
        num_instructions: int = 20,
    ) -> list[dict]:
        """Disassemble N instructions at a file offset. Utility for inspection."""
        raw = self.binary_data[file_offset:file_offset + num_instructions * 15]
        va = virtual_address or file_offset
        instructions = list(self.cs.disasm(raw, va))

        result = []
        for insn in instructions[:num_instructions]:
            result.append({
                "address": f"0x{insn.address:x}",
                "bytes": insn.bytes.hex(),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
            })
        return result
