"""Validation and patching endpoints."""

from pathlib import Path

from fastapi import APIRouter, HTTPException

from ftl_gen.api.deps import get_mods_dir, get_slipstream
from ftl_gen.api.models import PatchResult, ValidationResult
from ftl_gen.api.services import ModReader
from ftl_gen.core.mod_builder import ModBuilder
from ftl_gen.llm.parsers import build_mod_content

router = APIRouter()


def _resolve_mod_path(name: str) -> Path:
    """Resolve a mod name to its .ftl file path."""
    mods_dir = get_mods_dir()
    ftl_path = mods_dir / f"{name}.ftl"
    if not ftl_path.exists():
        raise HTTPException(status_code=404, detail=f"No .ftl file for mod: {name}")
    return ftl_path


def _rebuild_with_test_loadout(name: str) -> Path:
    """Rebuild a mod with the Kestrel test loadout enabled."""
    mods_dir = get_mods_dir()
    reader = ModReader(mods_dir)
    mod = reader.get_mod(name)
    if not mod:
        raise HTTPException(status_code=404, detail=f"Mod not found: {name}")

    # Collect sprite files from the existing mod
    sprite_files = {}
    for sprite_path in mod.sprite_files:
        data = reader.get_sprite_data(name, sprite_path)
        if data:
            sprite_files[sprite_path] = data

    content = build_mod_content(
        mod_name=name,
        description=mod.description,
        weapons=mod.weapons,
        drones=mod.drones,
        augments=mod.augments,
        crew=mod.crew,
        events=mod.events,
    )

    builder = ModBuilder(mods_dir)
    return builder.build(content, sprite_files or None, test_loadout=True)


@router.post("/validate", response_model=ValidationResult)
def validate_mod(name: str):
    """Validate a mod using Slipstream."""
    slipstream = get_slipstream()
    if not slipstream.is_available():
        raise HTTPException(status_code=503, detail="Slipstream not available")

    ftl_path = _resolve_mod_path(name)
    result = slipstream.validate(ftl_path)

    return ValidationResult(
        ok=result.ok,
        warnings=result.warnings,
        errors=result.errors,
    )


@router.post("/patch", response_model=PatchResult)
def patch_mod(name: str, test_loadout: bool = False):
    """Patch a mod into the game."""
    slipstream = get_slipstream()
    if not slipstream.is_available():
        raise HTTPException(status_code=503, detail="Slipstream not available")

    if test_loadout:
        ftl_path = _rebuild_with_test_loadout(name)
    else:
        ftl_path = _resolve_mod_path(name)

    result = slipstream.patch([ftl_path])
    return PatchResult(success=result.success, message=result.message)


@router.post("/patch-and-run", response_model=PatchResult)
def patch_and_run(name: str, test_loadout: bool = False):
    """Patch a mod and launch FTL."""
    slipstream = get_slipstream()
    if not slipstream.is_available():
        raise HTTPException(status_code=503, detail="Slipstream not available")

    if test_loadout:
        ftl_path = _rebuild_with_test_loadout(name)
    else:
        ftl_path = _resolve_mod_path(name)

    result = slipstream.patch_and_run([ftl_path])
    return PatchResult(success=result.success, message=result.message)
