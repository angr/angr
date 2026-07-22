"""
Stable name resolution for decompiler optimization passes and peephole optimizations.
"""

from __future__ import annotations


def _known_passes() -> dict[str, type]:
    # Recomputed on each call to pick up classes added via ``register_optimization_pass`` after this module is imported.

    from .optimization_passes import ALL_OPTIMIZATION_PASSES  # pylint:disable=import-outside-toplevel
    from .peephole_optimizations import ALL_PEEPHOLE_OPTS  # pylint:disable=import-outside-toplevel

    return {cls.__qualname__: cls for cls in (*ALL_OPTIMIZATION_PASSES, *ALL_PEEPHOLE_OPTS)}


def pass_to_name(cls: type) -> str:
    """Return a stable string identifier (the class name) for an optimization pass or peephole class."""
    return cls.__qualname__


def name_to_pass(name: str) -> type:
    """Resolve a class name back to its registered pass class.

    :raises KeyError: if ``name`` does not refer to a class in
        ``ALL_OPTIMIZATION_PASSES`` or ``ALL_PEEPHOLE_OPTS``.
    """
    return _known_passes()[name]


__all__ = ("name_to_pass", "pass_to_name")
