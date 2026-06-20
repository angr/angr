from __future__ import annotations

from typing import TYPE_CHECKING

from angr.utils.ssa import get_vvar_deflocs, get_vvar_uselocs

if TYPE_CHECKING:
    from angr.ailment.block import Block
    from angr.ailment.expression import VirtualVariable
    from angr.code_location import AILCodeLocation


class BlockDefUses:
    """
    Cached per-block virtual-variable definition/use information for SReachingDefinitions (SRDA).

    An instance holds the vvar definitions, phi sources, and explicit vvar uses found by scanning a single AIL block's
    statements (exactly the per-block portion of :meth:`SReachingDefinitionsAnalysis._analyze`). The cross-block parts
    of SRDA (function-argument externs, call-site implicit uses, callee-saved restoration) are *not* stored here; they
    are cheap and recomputed on every run.

    Validity: every block mutation in the decompiler replaces ``block.statements`` with a freshly allocated list
    (``Block.copy`` slices the list; dead-assignment removal builds a new list of statements; peephole optimizations
    operate on copies). A cached instance therefore remains valid for a block exactly as long as ``block.statements``
    is the same list object it was computed from *and* it has not been explicitly marked dirty.
    """

    __slots__ = ("addr", "dirty", "idx", "phi_vvars", "statements_ref", "vvar_deflocs", "vvar_uselocs")

    def __init__(self, addr: int, idx: int | None):
        self.addr = addr
        self.idx = idx
        # The exact ``block.statements`` list object this entry was computed from. Held as a real reference (not an
        # ``id()``) so the object cannot be garbage-collected and have its id reused while the entry is cached, which
        # would make the ``is`` identity check below unsound.
        self.statements_ref: list | None = None
        self.dirty: bool = True
        self.vvar_deflocs: dict[int, tuple[VirtualVariable, AILCodeLocation]] = {}
        self.phi_vvars: dict[int, set[int | None]] = {}
        self.vvar_uselocs: dict[int, list[tuple[VirtualVariable, AILCodeLocation]]] = {}

    def is_valid_for(self, block: Block) -> bool:
        return not self.dirty and self.statements_ref is block.statements

    def compute(self, block: Block) -> None:
        phi: dict[int, set[int | None]] = {}
        # check_extra_defs is disabled because we scan a single block in isolation: an extra-def varid may be defined in
        # another block, so the subset-consistency assertion in get_vvar_deflocs would spuriously fail here.
        self.vvar_deflocs = get_vvar_deflocs([block], phi_vvars=phi, check_extra_defs=False)
        self.phi_vvars = phi
        self.vvar_uselocs = get_vvar_uselocs([block])
        self.statements_ref = block.statements
        self.dirty = False


class BlockDefUsesCache:
    """
    A decompilation-scoped cache mapping an AIL block key ``(addr, idx)`` to its :class:`BlockDefUses`.

    Created once per decompilation (by Clinic) and threaded through every function-mode SRDA invocation so that blocks
    that have not changed since the previous run are not re-scanned. Entries are validated by statement-list identity
    (see :meth:`BlockDefUses.is_valid_for`): a stale entry for a rebuilt block is recomputed automatically, and
    :meth:`mark_dirty` additionally invalidates an entry after an in-place edit.

    The cached information is independent of SRDA's cross-block parameters (``func_args``,
    ``use_callee_saved_regs_at_return``, ``variable_map``), so a single cache instance is valid across all the
    function-mode call sites that share it. Temporaries (``track_tmps``) are intentionally not cached; callers that
    need tmp tracking (e.g. block-mode BlockSimplifier) do not use this cache.
    """

    __slots__ = ("_entries", "hits", "misses")

    def __init__(self):
        self._entries: dict[tuple[int, int | None], BlockDefUses] = {}
        self.hits = 0
        self.misses = 0

    def get(self, block: Block) -> BlockDefUses:
        key = (block.addr, block.idx)
        entry = self._entries.get(key)
        if entry is not None and entry.is_valid_for(block):
            self.hits += 1
            return entry
        self.misses += 1
        entry = BlockDefUses(block.addr, block.idx)
        entry.compute(block)
        self._entries[key] = entry
        return entry

    def mark_dirty(self, addr: int, idx: int | None) -> None:
        entry = self._entries.get((addr, idx))
        if entry is not None:
            entry.dirty = True

    def refresh(self, block: Block) -> BlockDefUses:
        """Force a recompute for ``block`` and store it, keeping the cache warm after an in-place edit."""
        entry = BlockDefUses(block.addr, block.idx)
        entry.compute(block)
        self._entries[(block.addr, block.idx)] = entry
        return entry
