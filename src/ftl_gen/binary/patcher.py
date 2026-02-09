"""Safe binary patching infrastructure for FTL.

Applies patch specs (collections of byte-level edits) to the FTL binary
with backup, verification, atomic writes, and code signature repair.

Design principles:
- All-or-nothing: verify ALL patches before writing ANY
- Single write: read binary → apply in memory → write once
- Always backup before first patch
- State tracking via .patch_state.json
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class Patch:
    """A single byte-level edit to the binary."""

    id: str
    description: str
    file_offset: int
    old_bytes: bytes
    new_bytes: bytes

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "description": self.description,
            "file_offset": self.file_offset,
            "old_bytes": self.old_bytes.hex(),
            "new_bytes": self.new_bytes.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> Patch:
        return cls(
            id=d["id"],
            description=d["description"],
            file_offset=d["file_offset"],
            old_bytes=bytes.fromhex(d["old_bytes"]),
            new_bytes=bytes.fromhex(d["new_bytes"]),
        )


@dataclass
class PatchSpec:
    """A complete set of patches to apply atomically."""

    spec_version: str
    binary_sha256: str
    description: str
    patches: list[Patch]
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "spec_version": self.spec_version,
            "binary_sha256": self.binary_sha256,
            "description": self.description,
            "patches": [p.to_dict() for p in self.patches],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict) -> PatchSpec:
        return cls(
            spec_version=d["spec_version"],
            binary_sha256=d["binary_sha256"],
            description=d["description"],
            patches=[Patch.from_dict(p) for p in d["patches"]],
            metadata=d.get("metadata", {}),
        )


@dataclass
class PatchResult:
    """Result of applying a patch spec."""

    success: bool
    patches_applied: int
    backup_path: Path | None
    errors: list[str]


class BinaryPatcher:
    """Applies and reverts binary patches with safety guarantees.

    Usage:
        patcher = BinaryPatcher(Path("/path/to/FTL"))
        spec = PatchSpec.from_dict(json.load(open("patch.json")))
        result = patcher.apply(spec)
        # Later:
        patcher.revert()
    """

    BACKUP_SUFFIX = ".ftlgen.bak"
    STATE_FILE = ".patch_state.json"

    def __init__(self, binary_path: Path):
        self.binary_path = binary_path.resolve()
        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {self.binary_path}")

    @property
    def backup_path(self) -> Path:
        return self.binary_path.with_suffix(
            self.binary_path.suffix + self.BACKUP_SUFFIX
        )

    @property
    def state_path(self) -> Path:
        return self.binary_path.parent / self.STATE_FILE

    def sha256(self) -> str:
        """Compute SHA256 of the current binary."""
        h = hashlib.sha256()
        with open(self.binary_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def backup(self) -> Path:
        """Create a backup of the binary.

        Only creates a new backup if one doesn't already exist,
        to avoid overwriting the true original with a patched version.
        """
        if self.backup_path.exists():
            logger.info("Backup already exists: %s", self.backup_path)
            return self.backup_path

        shutil.copy2(self.binary_path, self.backup_path)
        logger.info("Backup created: %s", self.backup_path)
        return self.backup_path

    def verify_spec(self, spec: PatchSpec) -> list[str]:
        """Verify a patch spec against the current binary.

        Returns a list of error strings. Empty list = all good.
        Checks:
        1. Binary SHA256 matches spec (warning only — Steam may update)
        2. Each patch's old_bytes match at file_offset
        """
        errors: list[str] = []
        current_sha = self.sha256()

        if current_sha != spec.binary_sha256:
            # Check if we have a backup and it matches — binary may already be patched
            if self.backup_path.exists():
                backup_sha = hashlib.sha256(
                    self.backup_path.read_bytes()
                ).hexdigest()
                if backup_sha == spec.binary_sha256:
                    errors.append(
                        f"Binary appears already patched (backup matches spec SHA256). "
                        f"Revert first with 'binary-patch revert'."
                    )
                    return errors
            errors.append(
                f"SHA256 mismatch — binary may have been updated by Steam. "
                f"Expected: {spec.binary_sha256[:16]}..., "
                f"Got: {current_sha[:16]}..."
            )

        binary_data = self.binary_path.read_bytes()
        binary_size = len(binary_data)

        for patch in spec.patches:
            end = patch.file_offset + len(patch.old_bytes)
            if end > binary_size:
                errors.append(
                    f"Patch '{patch.id}': offset 0x{patch.file_offset:x} + "
                    f"{len(patch.old_bytes)} bytes exceeds binary size ({binary_size})"
                )
                continue

            actual = binary_data[patch.file_offset : end]
            if actual != patch.old_bytes:
                errors.append(
                    f"Patch '{patch.id}': bytes at 0x{patch.file_offset:x} don't match. "
                    f"Expected: {patch.old_bytes.hex()[:32]}..., "
                    f"Got: {actual.hex()[:32]}..."
                )

        return errors

    def apply(self, spec: PatchSpec) -> PatchResult:
        """Apply a patch spec to the binary.

        1. Creates backup if none exists
        2. Verifies all patches (aborts if ANY fail)
        3. Applies all patches in memory, writes once
        4. Saves state to .patch_state.json
        5. Re-signs the binary (ad-hoc)
        """
        errors: list[str] = []

        # Backup
        backup = self.backup()

        # Verify
        verify_errors = self.verify_spec(spec)
        if verify_errors:
            return PatchResult(
                success=False,
                patches_applied=0,
                backup_path=backup,
                errors=verify_errors,
            )

        # Apply all patches in memory
        binary_data = bytearray(self.binary_path.read_bytes())
        for patch in spec.patches:
            end = patch.file_offset + len(patch.old_bytes)
            binary_data[patch.file_offset : end] = patch.new_bytes
            logger.info(
                "Applied patch '%s' at 0x%x (%d bytes)",
                patch.id,
                patch.file_offset,
                len(patch.new_bytes),
            )

        # Write atomically (write to temp, rename)
        tmp_path = self.binary_path.with_suffix(".ftlgen.tmp")
        try:
            tmp_path.write_bytes(bytes(binary_data))
            # Preserve permissions
            tmp_path.chmod(self.binary_path.stat().st_mode)
            tmp_path.replace(self.binary_path)
        except Exception as e:
            tmp_path.unlink(missing_ok=True)
            errors.append(f"Write failed: {e}")
            return PatchResult(
                success=False,
                patches_applied=0,
                backup_path=backup,
                errors=errors,
            )

        # Save state
        self._save_state(spec)

        # Re-sign
        resign_ok = self.resign()
        if not resign_ok:
            errors.append(
                "Code re-signing failed. Binary may not run on macOS. "
                "Try: codesign --remove-signature <binary> && codesign -s - <binary>"
            )

        return PatchResult(
            success=True,
            patches_applied=len(spec.patches),
            backup_path=backup,
            errors=errors,
        )

    def revert(self) -> bool:
        """Restore the original binary from backup."""
        if not self.backup_path.exists():
            logger.warning("No backup found at %s", self.backup_path)
            return False

        shutil.copy2(self.backup_path, self.binary_path)
        logger.info("Reverted binary from %s", self.backup_path)

        # Clean up state
        self.state_path.unlink(missing_ok=True)

        # Re-sign the restored binary
        self.resign()

        return True

    def resign(self) -> bool:
        """Strip existing signature and ad-hoc re-sign.

        macOS requires valid code signatures. After patching, the original
        signature is invalid, so we strip it and apply an ad-hoc signature.
        """
        try:
            # Strip existing signature
            result = subprocess.run(
                ["codesign", "--remove-signature", str(self.binary_path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.warning("Failed to remove signature: %s", result.stderr)

            # Ad-hoc re-sign
            result = subprocess.run(
                ["codesign", "-s", "-", str(self.binary_path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.warning("Failed to ad-hoc sign: %s", result.stderr)
                return False

            logger.info("Binary re-signed (ad-hoc)")
            return True

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning("codesign not available: %s", e)
            return False

    def get_state(self) -> dict | None:
        """Read the current patch state, or None if no patches applied."""
        if not self.state_path.exists():
            return None
        try:
            return json.loads(self.state_path.read_text())
        except (json.JSONDecodeError, OSError):
            return None

    def _save_state(self, spec: PatchSpec) -> None:
        """Save patch state to .patch_state.json."""
        state = {
            "applied_at": datetime.now(timezone.utc).isoformat(),
            "spec_description": spec.description,
            "spec_version": spec.spec_version,
            "binary_sha256_original": spec.binary_sha256,
            "binary_sha256_patched": self.sha256(),
            "patches_applied": len(spec.patches),
            "patch_ids": [p.id for p in spec.patches],
            "metadata": spec.metadata,
        }
        self.state_path.write_text(json.dumps(state, indent=2) + "\n")

    @staticmethod
    def load_spec(path: Path) -> PatchSpec:
        """Load a PatchSpec from a JSON file."""
        data = json.loads(path.read_text())
        return PatchSpec.from_dict(data)

    @staticmethod
    def save_spec(spec: PatchSpec, path: Path) -> None:
        """Save a PatchSpec to a JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(spec.to_dict(), indent=2) + "\n")
