from __future__ import annotations

import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class PlatformCapabilities:
    """Host facilities that can vary between angr platforms."""

    emscripten: bool
    icicle: bool
    lmdb: bool
    multiprocessing: bool
    psutil: bool
    subprocess: bool
    unicorn: bool


_IS_EMSCRIPTEN = sys.platform == "emscripten"

capabilities = PlatformCapabilities(
    emscripten=_IS_EMSCRIPTEN,
    icicle=not _IS_EMSCRIPTEN,
    lmdb=not _IS_EMSCRIPTEN,
    multiprocessing=not _IS_EMSCRIPTEN,
    psutil=not _IS_EMSCRIPTEN,
    subprocess=not _IS_EMSCRIPTEN,
    unicorn=not _IS_EMSCRIPTEN,
)

__all__ = ("PlatformCapabilities", "capabilities")
