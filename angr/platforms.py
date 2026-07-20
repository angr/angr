from __future__ import annotations

import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class PlatformCapabilities:
    """Host facilities that can vary between angr platforms."""

    ailment: bool
    capstone: bool
    emscripten: bool
    filesystem: bool
    icicle: bool
    lmdb: bool
    multiprocessing: bool
    pcode: bool
    psutil: bool
    subprocess: bool
    unicorn: bool
    vex: bool
    z3: bool


_IS_EMSCRIPTEN = sys.platform == "emscripten"

capabilities = PlatformCapabilities(
    ailment=True,
    capstone=True,
    emscripten=_IS_EMSCRIPTEN,
    filesystem=True,
    icicle=not _IS_EMSCRIPTEN,
    lmdb=not _IS_EMSCRIPTEN,
    multiprocessing=not _IS_EMSCRIPTEN,
    pcode=not _IS_EMSCRIPTEN,
    psutil=not _IS_EMSCRIPTEN,
    subprocess=not _IS_EMSCRIPTEN,
    unicorn=not _IS_EMSCRIPTEN,
    vex=True,
    z3=True,
)

__all__ = ("PlatformCapabilities", "capabilities")
