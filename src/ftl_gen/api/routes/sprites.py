"""Sprite serving endpoints."""

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from ftl_gen.api.deps import get_mods_dir
from ftl_gen.api.services import ModReader

router = APIRouter()


@router.get("/mods/{name}/sprites/{path:path}")
def get_sprite(name: str, path: str):
    """Serve a sprite PNG from a mod."""
    reader = ModReader(get_mods_dir())
    data = reader.get_sprite_data(name, path)

    if data is None:
        raise HTTPException(status_code=404, detail=f"Sprite not found: {path}")

    return Response(content=data, media_type="image/png")
