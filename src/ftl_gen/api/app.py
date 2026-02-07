"""FastAPI application for FTL-Gen web UI."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from ftl_gen import __version__
from ftl_gen.api.routes import chaos, config, generate, mods, sprites, validate

# Path to the built React SPA
UI_DIST = Path(__file__).resolve().parent.parent.parent.parent / "ui" / "dist"


def create_app(dev: bool = False) -> FastAPI:
    """Create the FastAPI application."""
    app = FastAPI(
        title="FTL-Gen",
        version=__version__,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )

    # CORS for development (Vite dev server on :5173)
    if dev:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["http://localhost:5173"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # API routes
    prefix = "/api/v1"
    app.include_router(config.router, prefix=prefix, tags=["config"])
    app.include_router(mods.router, prefix=prefix, tags=["mods"])
    app.include_router(sprites.router, prefix=prefix, tags=["sprites"])
    app.include_router(generate.router, prefix=prefix, tags=["generate"])
    app.include_router(chaos.router, prefix=prefix, tags=["chaos"])
    app.include_router(validate.router, prefix=prefix, tags=["validate"])

    # Serve built React SPA in production
    if not dev and UI_DIST.exists():
        # Serve static assets
        app.mount("/assets", StaticFiles(directory=UI_DIST / "assets"), name="assets")

        # Catch-all for SPA routing - serve index.html for any non-API route
        from fastapi.responses import FileResponse

        @app.get("/{path:path}")
        async def serve_spa(path: str):
            # Don't serve SPA for API routes
            if path.startswith("api/"):
                return
            # Serve static files if they exist
            file_path = UI_DIST / path
            if file_path.is_file():
                return FileResponse(file_path)
            # Fall back to index.html for SPA routing
            return FileResponse(UI_DIST / "index.html")

    return app
