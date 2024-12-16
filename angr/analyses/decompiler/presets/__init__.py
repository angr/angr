from __future__ import annotations

from .preset import DecompilationPreset
from .fast import preset_fast
from .full import preset_full
from .basic import preset_basic


DECOMPILATION_PRESETS = {
    "fast": preset_fast,
    "full": preset_full,
    "basic": preset_basic,
    "default": preset_fast,
}


__all__ = (
    "DECOMPILATION_PRESETS",
    "DecompilationPreset",
)
