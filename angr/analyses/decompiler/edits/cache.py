"""
Decompilation-cache access for the edit layer.

Both ``kb.decompilations`` and ``kb.dec_variables`` spill to LMDB under memory pressure and hand
back a freshly deserialized -- that is, *different* -- Python object on reload. Never hold a
``DecompilationCache`` or a ``VariableManagerInternal`` across anything that can decompile; always
re-fetch by key at the point of mutation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .errors import NotDecompiledError

if TYPE_CHECKING:
    from collections.abc import Iterable

    from angr.analyses.decompiler.decompilation_cache import DecompilationCache
    from angr.knowledge_base import KnowledgeBase
    from angr.sim_type import SimType

DEFAULT_FLAVOR = "pseudocode"


def get_cache(kb: KnowledgeBase, func_addr: int, flavor: str = DEFAULT_FLAVOR) -> DecompilationCache | None:
    """Return the cached decompilation for a function, or None if there is none."""
    return kb.decompilations.get((func_addr, flavor), None)


def require_cache(kb: KnowledgeBase, func_addr: int, flavor: str = DEFAULT_FLAVOR) -> DecompilationCache:
    """Return the cached decompilation, raising NotDecompiledError if it is missing or empty."""
    cache = get_cache(kb, func_addr, flavor)
    if cache is None or cache.codegen is None:
        raise NotDecompiledError(
            f"Function {func_addr:#x} has not been decompiled yet (flavor {flavor!r}). Decompile it first."
        )
    return cache


def invalidate(
    kb: KnowledgeBase,
    func_addr: int,
    *,
    flavors: Iterable[str] | None = None,
    drop_variables: bool = False,
) -> None:
    """
    Drop cached decompilations for a function.

    :param flavors:         Flavors to drop; None drops every flavor currently cached. A prototype
                            change must drop all of them, or a non-pseudocode flavor silently
                            retains the old signature.
    :param drop_variables:  Also drop ``kb.dec_variables[func_addr]``. Required for new argument
                            names to take effect, but it discards every rename and manual type for
                            the function -- see :func:`snapshot_user_edits`.
    """
    if flavors is None:
        flavors = list(kb.decompilations.available_flavors(func_addr))
    for flavor in flavors:
        kb.decompilations.discard((func_addr, flavor))

    if drop_variables and kb.dec_variables.has_function_manager(func_addr):
        del kb.dec_variables[func_addr]


def snapshot_user_edits(kb: KnowledgeBase, func_addr: int) -> dict[str, tuple[str | None, SimType | None]]:
    """
    Capture user renames and manual types for a function, keyed by ``SimVariable.ident``.

    Used to survive the ``dec_variables`` drop that a prototype change requires.
    """
    if not kb.dec_variables.has_function_manager(func_addr):
        return {}

    varman = kb.dec_variables[func_addr]
    snapshot: dict[str, tuple[str | None, SimType | None]] = {}
    for var in varman.get_unified_variables(sort=None):
        if not var.ident:
            continue
        name = var.name if var.renamed else None
        ty = varman.get_variable_type(var) if var in varman.variables_with_manual_types else None
        if name is not None or ty is not None:
            snapshot[var.ident] = (name, ty)
    return snapshot


def restore_user_edits(
    kb: KnowledgeBase, func_addr: int, snapshot: dict[str, tuple[str | None, SimType | None]]
) -> tuple[int, list[str]]:
    """
    Re-apply a :func:`snapshot_user_edits` result after re-decompilation.

    Best-effort: idents can change across a re-decompile, so the unmatched ones are returned rather
    than silently dropped.
    """
    if not snapshot or not kb.dec_variables.has_function_manager(func_addr):
        return 0, sorted(snapshot)

    varman = kb.dec_variables[func_addr]
    by_ident = {var.ident: var for var in varman.get_unified_variables(sort=None) if var.ident}

    restored = 0
    missing: list[str] = []
    for ident, (name, ty) in snapshot.items():
        var = by_ident.get(ident)
        if var is None:
            missing.append(ident)
            continue
        if name is not None:
            var.name = name
            var.renamed = True
            var.clear_hash()
        if ty is not None:
            varman.set_variable_type(var, ty, all_unified=True, mark_manual=True)
        restored += 1

    return restored, sorted(missing)


def function_summary(kb: KnowledgeBase, func_addr: int) -> dict[str, Any]:
    """Small helper for edit results: what is currently cached for a function."""
    return {
        "flavors": sorted(kb.decompilations.available_flavors(func_addr)),
        "has_variables": kb.dec_variables.has_function_manager(func_addr),
    }
