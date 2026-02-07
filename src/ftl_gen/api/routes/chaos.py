"""Chaos mode endpoints."""

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter
from sse_starlette.sse import EventSourceResponse

from ftl_gen.api.models import ChaosPreviewItem, ChaosPreviewResponse, ChaosRequest
from ftl_gen.chaos import ChaosConfig, randomize_all
from ftl_gen.config import get_settings
from ftl_gen.core.mod_builder import ModBuilder
from ftl_gen.data.loader import load_vanilla_reference
from ftl_gen.llm.parsers import build_mod_content

router = APIRouter()
_executor = ThreadPoolExecutor(max_workers=2)


@router.post("/chaos")
async def generate_chaos(request: ChaosRequest):
    """Generate a chaos-only mod with SSE progress streaming."""
    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_running_loop()

    async def _run():
        def _generate():
            settings = get_settings()
            chaos_config = ChaosConfig(
                level=request.level, seed=request.seed, unsafe=request.unsafe
            )

            def put(data):
                loop.call_soon_threadsafe(queue.put_nowait, data)

            put({"step": "chaos", "status": "started"})
            chaos_result = randomize_all(chaos_config)
            put({
                "step": "chaos", "status": "completed",
                "detail": f"Randomized {len(chaos_result.weapons)} weapons, "
                          f"{len(chaos_result.drones)} drones, "
                          f"{len(chaos_result.augments)} augments, "
                          f"{len(chaos_result.crew)} crew",
            })

            put({"step": "building", "status": "started"})
            mod_name = request.name or f"ChaosMode_{int(request.level * 100)}"
            content = build_mod_content(
                mod_name=mod_name,
                description=f"Chaos mode: {int(request.level * 100)}% (seed: {chaos_result.seed_used})",
                weapons=chaos_result.weapons,
                drones=chaos_result.drones,
                augments=chaos_result.augments,
                crew=chaos_result.crew,
                events=[],
            )
            mod_builder = ModBuilder(settings.output_dir)
            ftl_path = mod_builder.build(content, test_loadout=request.test_loadout)
            put({"step": "building", "status": "completed"})
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


@router.post("/chaos/preview", response_model=ChaosPreviewResponse)
async def preview_chaos(request: ChaosRequest):
    """Preview chaos stat changes without creating a mod."""
    loop = asyncio.get_running_loop()

    def _preview():
        chaos_config = ChaosConfig(
            level=request.level, seed=request.seed, unsafe=request.unsafe
        )
        vanilla = load_vanilla_reference()
        chaos_result = randomize_all(chaos_config)

        items = []

        # Build lookup of original weapons
        orig_weapons = {w["name"]: w for w in vanilla.get("weapons", [])}
        for w in chaos_result.weapons:
            orig = orig_weapons.get(w.name, {})
            items.append(ChaosPreviewItem(
                name=w.name,
                item_type="weapon",
                original_stats={"damage": orig.get("damage", 0), "cooldown": orig.get("cooldown", 0),
                                "power": orig.get("power", 0), "cost": orig.get("cost", 0)},
                chaos_stats={"damage": w.damage, "cooldown": w.cooldown,
                             "power": w.power, "cost": w.cost},
            ))

        return ChaosPreviewResponse(
            level=request.level,
            seed=chaos_result.seed_used,
            items=items,
        )

    return await loop.run_in_executor(_executor, _preview)
