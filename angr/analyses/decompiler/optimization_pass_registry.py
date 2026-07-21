"""
Stable name resolution for decompiler optimization passes and peephole optimizations.

Used by DecompilationCache serialization to round-trip pass-class references as strings
rather than embedding live class objects. Names are bare ``__qualname__`` strings (the
class names); only classes registered in ``ALL_OPTIMIZATION_PASSES`` or ``ALL_PEEPHOLE_OPTS``
(including user-registered ones added via ``register_optimization_pass``) are resolvable,
so loading is a whitelisted lookup rather than an arbitrary ``importlib`` call. The class
names are unique across the registry, so the module prefix is not needed.
"""

from __future__ import annotations


def _known_passes() -> dict[str, type]:
    # Recomputed on each call to pick up classes added via ``register_optimization_pass`` after this module is imported.
    from .optimization_passes import ALL_OPTIMIZATION_PASSES
    from .peephole_optimizations import ALL_PEEPHOLE_OPTS

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
