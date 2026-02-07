"""Mod listing and detail endpoints."""

import shutil

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from ftl_gen.api.deps import get_mods_dir
from ftl_gen.api.models import ModDetail, ModSummary
from ftl_gen.api.services import ModReader

router = APIRouter()


def _get_reader() -> ModReader:
    return ModReader(get_mods_dir())


@router.get("/mods", response_model=list[ModSummary])
def list_mods():
    """List all generated mods."""
    return _get_reader().list_mods()


@router.get("/mods/{name}", response_model=ModDetail)
def get_mod(name: str):
    """Get full details for a mod."""
    mod = _get_reader().get_mod(name)
    if not mod:
        raise HTTPException(status_code=404, detail=f"Mod not found: {name}")
    return mod


@router.delete("/mods/{name}", status_code=204)
def delete_mod(name: str):
    """Delete a mod (both directory and .ftl file)."""
    mods_dir = get_mods_dir()
    mod_dir = mods_dir / name
    ftl_path = mods_dir / f"{name}.ftl"

    deleted = False
    if mod_dir.is_dir():
        shutil.rmtree(mod_dir)
        deleted = True
    if ftl_path.exists():
        ftl_path.unlink()
        deleted = True

    if not deleted:
        raise HTTPException(status_code=404, detail=f"Mod not found: {name}")


@router.get("/mods/{name}/download")
def download_mod(name: str):
    """Download a mod as a .ftl file."""
    mods_dir = get_mods_dir()
    ftl_path = mods_dir / f"{name}.ftl"

    if not ftl_path.exists():
        raise HTTPException(status_code=404, detail=f"No .ftl file for mod: {name}")

    return FileResponse(
        ftl_path,
        media_type="application/zip",
        filename=f"{name}.ftl",
    )
