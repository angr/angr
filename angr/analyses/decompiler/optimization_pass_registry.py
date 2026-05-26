"""
Stable name resolution for decompiler optimization passes and peephole optimizations.

Used by DecompilationCache serialization to round-trip pass-class references as strings
rather than embedding live class objects. Names are fully-qualified ``module.qualname``
strings; only classes registered in ``ALL_OPTIMIZATION_PASSES`` or ``ALL_PEEPHOLE_OPTS``
(including user-registered ones added via ``register_optimization_pass``) are resolvable,
so loading is a whitelisted lookup rather than an arbitrary ``importlib`` call.
"""

from __future__ import annotations


def _fqn(cls: type) -> str:
    return f"{cls.__module__}.{cls.__qualname__}"


def _known_passes() -> dict[str, type]:
    # Recomputed on each call to pick up classes added via ``register_optimization_pass`` after this module is imported.
    from .optimization_passes import ALL_OPTIMIZATION_PASSES
    from .peephole_optimizations import ALL_PEEPHOLE_OPTS

    return {_fqn(cls): cls for cls in (*ALL_OPTIMIZATION_PASSES, *ALL_PEEPHOLE_OPTS)}


def pass_to_name(cls: type) -> str:
    """Return a stable string identifier for an optimization pass or peephole class."""
    return _fqn(cls)


def name_to_pass(name: str) -> type:
    """Resolve a stable string identifier back to its registered pass class.

    :raises KeyError: if ``name`` does not refer to a class in
        ``ALL_OPTIMIZATION_PASSES`` or ``ALL_PEEPHOLE_OPTS``.
    """
    return _known_passes()[name]


__all__ = ("name_to_pass", "pass_to_name")
