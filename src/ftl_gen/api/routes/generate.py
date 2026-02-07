"""Mod generation endpoints with SSE streaming."""

import asyncio
import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter
from sse_starlette.sse import EventSourceResponse

from ftl_gen.api.models import GenerateRequest, GenerateSingleRequest
from ftl_gen.chaos import ChaosConfig
from ftl_gen.config import get_settings
from ftl_gen.core.generator import ModGenerator
from ftl_gen.xml.schemas import (
    AugmentBlueprint,
    CrewBlueprint,
    DroneBlueprint,
    EventBlueprint,
    WeaponBlueprint,
)

router = APIRouter()
_executor = ThreadPoolExecutor(max_workers=2)


def _make_progress_callback(queue: asyncio.Queue, loop: asyncio.AbstractEventLoop) -> Callable:
    """Create a progress callback that pushes to an asyncio queue from a worker thread."""

    def callback(step: str, status: str, **kwargs):
        data = {"step": step, "status": status, **kwargs}
        loop.call_soon_threadsafe(queue.put_nowait, data)

    return callback


@router.post("/generate")
async def generate_mod(request: GenerateRequest):
    """Generate a complete mod with SSE progress streaming."""
    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_running_loop()

    async def _run():
        def _generate():
            settings = get_settings()
            generator = ModGenerator(settings)

            chaos_config = None
            if request.chaos_level is not None:
                chaos_config = ChaosConfig(
                    level=request.chaos_level,
                    seed=request.seed,
                    unsafe=request.unsafe,
                )

            callback = _make_progress_callback(queue, loop)
            ftl_path = generator.generate_mod(
                theme=request.theme,
                mod_name=request.name,
                num_weapons=request.weapons,
                num_events=request.events,
                num_drones=request.drones,
                num_augments=request.augments,
                num_crew=request.crew,
                generate_sprites=request.sprites,
                use_cached_images=request.cache_images,
                chaos_config=chaos_config,
                test_loadout=request.test_loadout,
                progress_callback=callback,
            )
            return str(ftl_path)

        try:
            ftl_path = await loop.run_in_executor(_executor, _generate)
            await queue.put({"step": "complete", "status": "completed", "path": ftl_path})
        except Exception as e:
            await queue.put({"step": "error", "status": "error", "detail": str(e)})

    asyncio.ensure_future(_run())

    async def event_generator():
        while True:
            try:
                data = await asyncio.wait_for(queue.get(), timeout=120)
                yield {"event": "progress", "data": json.dumps(data)}
                if data.get("step") in ("complete", "error"):
                    break
            except asyncio.TimeoutError:
                yield {"event": "ping", "data": "{}"}

    return EventSourceResponse(event_generator())


@router.post("/generate/weapon", response_model=WeaponBlueprint)
async def generate_weapon(request: GenerateSingleRequest):
    """Generate a single weapon."""
    loop = asyncio.get_running_loop()

    def _gen():
        settings = get_settings()
        generator = ModGenerator(settings)
        return generator.generate_single_weapon(request.description)

    return await loop.run_in_executor(_executor, _gen)


@router.post("/generate/drone", response_model=DroneBlueprint)
async def generate_drone(request: GenerateSingleRequest):
    """Generate a single drone."""
    loop = asyncio.get_running_loop()

    def _gen():
        settings = get_settings()
        generator = ModGenerator(settings)
        return generator.generate_single_drone(request.description)

    return await loop.run_in_executor(_executor, _gen)


@router.post("/generate/event", response_model=EventBlueprint)
async def generate_event(request: GenerateSingleRequest):
    """Generate a single event."""
    loop = asyncio.get_running_loop()

    def _gen():
        settings = get_settings()
        generator = ModGenerator(settings)
        return generator.generate_single_event(request.description)

    return await loop.run_in_executor(_executor, _gen)


@router.post("/generate/augment", response_model=AugmentBlueprint)
async def generate_augment(request: GenerateSingleRequest):
    """Generate a single augment."""
    loop = asyncio.get_running_loop()

    def _gen():
        settings = get_settings()
        generator = ModGenerator(settings)
        return generator.generate_single_augment(request.description)

    return await loop.run_in_executor(_executor, _gen)


@router.post("/generate/crew", response_model=CrewBlueprint)
async def generate_crew(request: GenerateSingleRequest):
    """Generate a single crew race."""
    loop = asyncio.get_running_loop()

    def _gen():
        settings = get_settings()
        generator = ModGenerator(settings)
        return generator.generate_single_crew(request.description)

    return await loop.run_in_executor(_executor, _gen)
