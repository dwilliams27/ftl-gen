"""API request/response models."""

from datetime import datetime

from pydantic import BaseModel, Field

from ftl_gen.xml.schemas import (
    AugmentBlueprint,
    CrewBlueprint,
    DroneBlueprint,
    EventBlueprint,
    WeaponBlueprint,
)


class ConfigStatus(BaseModel):
    """Current configuration status."""

    llm_provider: str
    llm_model: str
    llm_key_configured: bool
    image_model: str
    image_key_configured: bool
    slipstream_available: bool
    slipstream_path: str | None
    output_dir: str


class ModSummary(BaseModel):
    """Summary of a mod for list views."""

    name: str
    path: str
    size_bytes: int
    created_at: datetime
    has_ftl: bool
    weapon_count: int = 0
    drone_count: int = 0
    augment_count: int = 0
    crew_count: int = 0
    event_count: int = 0
    sprite_count: int = 0


class ModDetail(BaseModel):
    """Full mod details for detail view."""

    name: str
    path: str
    description: str = ""
    created_at: datetime
    has_ftl: bool
    weapons: list[WeaponBlueprint] = Field(default_factory=list)
    drones: list[DroneBlueprint] = Field(default_factory=list)
    augments: list[AugmentBlueprint] = Field(default_factory=list)
    crew: list[CrewBlueprint] = Field(default_factory=list)
    events: list[EventBlueprint] = Field(default_factory=list)
    sprite_files: list[str] = Field(default_factory=list)
    blueprints_xml: str = ""
    events_xml: str = ""
    animations_xml: str = ""
    metadata_xml: str = ""


class GenerateRequest(BaseModel):
    """Request to generate a mod."""

    theme: str
    name: str | None = None
    weapons: int = 3
    events: int = 3
    drones: int = 0
    augments: int = 0
    crew: int = 0
    sprites: bool = True
    cache_images: bool = False
    chaos_level: float | None = None
    seed: int | None = None
    unsafe: bool = False
    test_weapon: bool = False
    test_drone: bool = False
    test_augment: bool = False


class GenerateSingleRequest(BaseModel):
    """Request to generate a single item."""

    description: str


class ChaosRequest(BaseModel):
    """Request to generate a chaos mod."""

    level: float = 0.5
    seed: int | None = None
    unsafe: bool = False
    name: str | None = None
    test_weapon: bool = False
    test_drone: bool = False
    test_augment: bool = False


class ChaosPreviewItem(BaseModel):
    """A single item in the chaos preview."""

    name: str
    item_type: str
    original_stats: dict
    chaos_stats: dict


class ChaosPreviewResponse(BaseModel):
    """Preview of chaos changes without creating a mod."""

    level: float
    seed: int
    items: list[ChaosPreviewItem]


class ValidationResult(BaseModel):
    """Result of mod validation."""

    ok: bool
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class PatchResult(BaseModel):
    """Result of mod patching."""

    success: bool
    message: str = ""


class CrashReportResponse(BaseModel):
    """Crash report snapshot from a monitored FTL launch."""

    process_alive: bool
    exit_code: int | None = None
    log_lines: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    mod_name: str | None = None


class FtlLogResponse(BaseModel):
    """Live FTL log state for the launch monitor."""

    running: bool
    mod_name: str | None = None
    log_lines: list[str] = Field(default_factory=list)
    exit_code: int | None = None


class GenerationProgress(BaseModel):
    """A progress event during generation."""

    step: str
    status: str  # "started" | "completed" | "error"
    detail: str = ""
    items_so_far: int = 0
    cost_so_far: float = 0.0
