"""
Stable name resolution for decompiler optimization passes and peephole optimizations.
"""

from __future__ import annotations


def _known_passes() -> dict[str, type]:
    # Recomputed on each call to pick up classes added via ``register_optimization_pass`` after this module is imported.

    # pylint:disable=import-outside-toplevel
    from angr.go.optimization_passes import get_go_optimization_passes
    from angr.rust.optimization_passes import get_rust_optimization_passes

    from .optimization_passes import ALL_OPTIMIZATION_PASSES
    from .peephole_optimizations import ALL_PEEPHOLE_OPTS

    # the flavor-specific passes are not in ALL_OPTIMIZATION_PASSES: the decompiler appends them by binary language
    return {
        cls.__qualname__: cls
        for cls in (
            *ALL_OPTIMIZATION_PASSES,
            *ALL_PEEPHOLE_OPTS,
            *get_go_optimization_passes(),
            *get_rust_optimization_passes(),
        )
    }


def pass_to_name(cls: type) -> str:
    """Return a stable string identifier (the class name) for an optimization pass or peephole class."""
    return cls.__qualname__


def name_to_pass(name: str) -> type | None:
    """
    Resolve a class name back to its registered pass class. Returns None for names that are not registered at the time
    this method is called. Peephole passes might be defined by analyses or plugins that have not yet been imported.
    """
    return _known_passes().get(name)


__all__ = ("name_to_pass", "pass_to_name")
