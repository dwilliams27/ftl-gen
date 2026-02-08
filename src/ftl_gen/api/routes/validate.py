"""Validation and patching endpoints."""

from pathlib import Path

from fastapi import APIRouter, HTTPException

from ftl_gen.api.deps import get_mods_dir, get_slipstream
from ftl_gen.api.models import (
    CrashReportResponse,
    FtlLogResponse,
    PatchResult,
    ValidationResult,
)
from ftl_gen.api.services import ModReader
from ftl_gen.core.mod_builder import ModBuilder
from ftl_gen.llm.parsers import build_mod_content
from ftl_gen.xml.validators import (
    check_dangling_references,
    detect_event_loops,
)

router = APIRouter()


def _resolve_mod_path(name: str) -> Path:
    """Resolve a mod name to its .ftl file path."""
    mods_dir = get_mods_dir()
    ftl_path = mods_dir / f"{name}.ftl"
    if not ftl_path.exists():
        raise HTTPException(status_code=404, detail=f"No .ftl file for mod: {name}")
    return ftl_path


def _get_mod_xml(name: str) -> tuple[str | None, str | None]:
    """Read blueprints and events XML from a mod directory."""
    mods_dir = get_mods_dir()
    mod_dir = mods_dir / name / "data"
    blueprints_xml = None
    events_xml = None
    if mod_dir.exists():
        bp_file = mod_dir / "blueprints.xml.append"
        ev_file = mod_dir / "events.xml.append"
        if bp_file.exists():
            blueprints_xml = bp_file.read_text()
        if ev_file.exists():
            events_xml = ev_file.read_text()
    return blueprints_xml, events_xml


def _rebuild_mod(
    name: str,
    test_weapon: bool = False,
    test_drone: bool = False,
    test_augment: bool = False,
) -> Path:
    """Rebuild a mod's .ftl from its directory sources.

    Always rebuilds so the .ftl reflects the current build pipeline.
    """
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
    return builder.build(
        content, sprite_files or None,
        test_weapon=test_weapon, test_drone=test_drone, test_augment=test_augment,
    )


@router.get("/crash-report", response_model=CrashReportResponse)
def get_crash_report():
    """Get crash report from the last monitored FTL launch."""
    slipstream = get_slipstream()
    report = slipstream.get_crash_report()
    if report is None:
        raise HTTPException(
            status_code=404,
            detail="No monitored launch has been initiated",
        )

    return CrashReportResponse(
        process_alive=report.process_alive,
        exit_code=report.exit_code,
        log_lines=report.log_lines,
        errors=report.errors,
        mod_name=report.mod_name,
    )


@router.get("/ftl-log", response_model=FtlLogResponse)
def get_ftl_log():
    """Get current FTL log state. Poll this after patch-and-run."""
    slipstream = get_slipstream()
    report = slipstream.get_crash_report()
    if report is not None:
        return FtlLogResponse(
            running=report.process_alive,
            mod_name=report.mod_name,
            log_lines=report.log_lines,
            exit_code=report.exit_code,
        )

    # No monitored launch — fall back to reading FTL.log directly
    from ftl_gen.config import get_settings
    settings = get_settings()
    log_path = settings.ftl_log_path
    log_lines: list[str] = []
    if log_path.exists():
        log_lines = log_path.read_text(errors="replace").splitlines()

    return FtlLogResponse(
        running=False,
        mod_name=None,
        log_lines=log_lines,
    )


@router.post("/validate", response_model=ValidationResult)
def validate_mod(name: str):
    """Validate a mod using Slipstream + event loop detection."""
    slipstream = get_slipstream()
    if not slipstream.is_available():
        raise HTTPException(status_code=503, detail="Slipstream not available")

    ftl_path = _resolve_mod_path(name)
    result = slipstream.validate(ftl_path)

    # Also run event loop detection
    _, events_xml = _get_mod_xml(name)
    extra_warnings = []
    extra_errors = []
    if events_xml:
        cycles = detect_event_loops(events_xml)
        if cycles:
            for cycle in cycles:
                extra_errors.append(f"Event loop: {' -> '.join(cycle)}")
        dangling = check_dangling_references(events_xml)
        for ref in dangling:
            extra_warnings.append(f"Dangling ref: {ref}")

    return ValidationResult(
        ok=result.ok and not extra_errors,
        warnings=result.warnings + extra_warnings,
        errors=result.errors + extra_errors,
    )


@router.post("/patch", response_model=PatchResult)
def patch_mod(
    name: str,
    test_weapon: bool = False,
    test_drone: bool = False,
    test_augment: bool = False,
):
    """Patch a mod into the game."""
    slipstream = get_slipstream()
    if not slipstream.is_available():
        raise HTTPException(status_code=503, detail="Slipstream not available")

    ftl_path = _rebuild_mod(name, test_weapon=test_weapon, test_drone=test_drone, test_augment=test_augment)
    result = slipstream.patch([ftl_path])
    return PatchResult(success=result.success, message=result.message)


@router.post("/patch-and-run", response_model=PatchResult)
def patch_and_run(
    name: str,
    test_weapon: bool = False,
    test_drone: bool = False,
    test_augment: bool = False,
):
    """Patch a mod and launch FTL with log monitoring (non-blocking)."""
    slipstream = get_slipstream()
    if not slipstream.is_available():
        raise HTTPException(status_code=503, detail="Slipstream not available")

    ftl_path = _rebuild_mod(name, test_weapon=test_weapon, test_drone=test_drone, test_augment=test_augment)

    # Patch
    patch_result = slipstream.patch([ftl_path])
    if not patch_result.success:
        return PatchResult(success=False, message=patch_result.message)

    # Stop any previous launcher before starting a new one
    if slipstream._launcher is not None:
        slipstream._launcher.stop()

    # Launch with monitoring (non-blocking — just starts the process and log tailer)
    from ftl_gen.core.launcher import FTLLauncher
    launcher = FTLLauncher(slipstream.settings, mod_name=name)
    result = launcher.start()
    if not result.success:
        return PatchResult(success=False, message=result.message)

    # Store launcher for log polling via GET /ftl-log
    slipstream._launcher = launcher
    return PatchResult(success=True, message=f"FTL launched with {name}")
