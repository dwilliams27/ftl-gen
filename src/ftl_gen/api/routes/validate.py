"""Validation, diagnostics, and patching endpoints."""

from pathlib import Path

from fastapi import APIRouter, HTTPException

from ftl_gen.api.deps import get_mods_dir, get_slipstream
from ftl_gen.api.models import (
    CrashReportResponse,
    DiagnosticCheckModel,
    DiagnosticReport,
    PatchResult,
    ValidationResult,
)
from ftl_gen.api.services import ModReader
from ftl_gen.core.mod_builder import ModBuilder
from ftl_gen.llm.parsers import build_mod_content
from ftl_gen.xml.validators import (
    XMLValidator,
    check_common_crash_patterns,
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


def _run_diagnostics(name: str) -> DiagnosticReport:
    """Run all diagnostic checks on a mod."""
    mods_dir = get_mods_dir()
    checks: list[DiagnosticCheckModel] = []
    event_cycles: list[list[str]] = []
    dangling_refs: list[str] = []

    # 1. XML syntax check
    mod_dir = mods_dir / name
    validator = XMLValidator()
    if mod_dir.exists():
        result = validator.validate_mod_directory(mod_dir)
        if result.ok:
            checks.append(DiagnosticCheckModel(name="XML Syntax", status="pass"))
        else:
            checks.append(DiagnosticCheckModel(
                name="XML Syntax", status="fail",
                message="; ".join(result.errors),
            ))
    else:
        checks.append(DiagnosticCheckModel(
            name="XML Syntax", status="warn",
            message="No mod directory found (only .ftl archive)",
        ))

    blueprints_xml, events_xml = _get_mod_xml(name)

    # 2. Required fields check (weapon blueprints)
    if blueprints_xml:
        from lxml import etree
        try:
            root = etree.fromstring(blueprints_xml.encode())
            field_errors = []
            for weapon in root.findall(".//weaponBlueprint"):
                r = validator.validate_weapon_blueprint(weapon)
                field_errors.extend(r.errors)
            if field_errors:
                checks.append(DiagnosticCheckModel(
                    name="Required Fields", status="fail",
                    message="; ".join(field_errors),
                ))
            else:
                checks.append(DiagnosticCheckModel(name="Required Fields", status="pass"))
        except etree.XMLSyntaxError:
            checks.append(DiagnosticCheckModel(
                name="Required Fields", status="fail",
                message="Cannot parse blueprints XML",
            ))
    else:
        checks.append(DiagnosticCheckModel(name="Required Fields", status="pass"))

    # 3. Event loops
    if events_xml:
        event_cycles = detect_event_loops(events_xml)
        if event_cycles:
            cycle_strs = [" -> ".join(c) for c in event_cycles]
            checks.append(DiagnosticCheckModel(
                name="Event Loops", status="fail",
                message=f"Circular references: {'; '.join(cycle_strs)}",
            ))
        else:
            checks.append(DiagnosticCheckModel(name="Event Loops", status="pass"))
    else:
        checks.append(DiagnosticCheckModel(name="Event Loops", status="pass"))

    # 4. Dangling references
    if events_xml:
        dangling_refs = check_dangling_references(events_xml)
        if dangling_refs:
            checks.append(DiagnosticCheckModel(
                name="Dangling Refs", status="warn",
                message="; ".join(dangling_refs),
            ))
        else:
            checks.append(DiagnosticCheckModel(name="Dangling Refs", status="pass"))
    else:
        checks.append(DiagnosticCheckModel(name="Dangling Refs", status="pass"))

    # 5. Crash patterns
    crash_issues = check_common_crash_patterns(blueprints_xml, events_xml)
    if crash_issues:
        checks.append(DiagnosticCheckModel(
            name="Crash Patterns", status="fail",
            message="; ".join(crash_issues),
        ))
    else:
        checks.append(DiagnosticCheckModel(name="Crash Patterns", status="pass"))

    ok = all(c.status != "fail" for c in checks)
    return DiagnosticReport(
        ok=ok,
        checks=checks,
        event_cycles=event_cycles,
        dangling_refs=dangling_refs,
    )


@router.post("/diagnose", response_model=DiagnosticReport)
def diagnose_mod(name: str):
    """Run all diagnostic checks on a mod."""
    # Verify mod exists
    mods_dir = get_mods_dir()
    mod_dir = mods_dir / name
    ftl_path = mods_dir / f"{name}.ftl"
    if not mod_dir.exists() and not ftl_path.exists():
        raise HTTPException(status_code=404, detail=f"Mod not found: {name}")

    return _run_diagnostics(name)


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
