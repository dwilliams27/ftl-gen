"""Single cached loader for vanilla reference data."""

import json
from pathlib import Path
from typing import Any

_VANILLA_DATA: dict[str, Any] | None = None
_DATA_PATH = Path(__file__).parent / "vanilla_reference.json"


def load_vanilla_reference() -> dict[str, Any]:
    """Load vanilla reference data from JSON file (cached after first call)."""
    global _VANILLA_DATA
    if _VANILLA_DATA is None:
        if _DATA_PATH.exists():
            with open(_DATA_PATH) as f:
                _VANILLA_DATA = json.load(f)
        else:
            _VANILLA_DATA = {}
    return _VANILLA_DATA
