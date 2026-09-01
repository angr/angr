from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from angr.ailment import AILBlockRewriter
from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import Const, Load, VirtualVariable
from angr.ailment.statement import Assignment, Statement, Store

if TYPE_CHECKING:
    import networkx

l = logging.getLogger(name=__name__)


class StackCopyCoalescer:
    """
    Collapse chains of stack-slot copies left behind by devirtualization.

    A VM moves one value through a run of frame slots, which reaches the decompiler as
    ``v2 = v1; v5 = v2; v7 = v5;`` -- a fresh local per hop. In SSA each of those virtual variables
    has exactly one definition, so rewriting a use of the destination into a use of the source is
    always value-preserving, however the slots are laid out. That part is unconditional.

    Deleting the copy afterwards is not. A stack virtual variable is also a *location*, and a load
    the analysis cannot pin down may read it. Two things therefore keep a copy alive:

    * its address is taken -- the slot appears under a ``Reference`` -- so a pointer to it exists;
    * some load or store addresses the frame through an expression this pass cannot resolve to one
      slot, which could name any of them.

    The second is deliberately coarse: one unresolvable frame access disables deletion everywhere
    rather than only near the slots it might touch. Propagation still happens, so the chain reads
    from its true source either way; only the now-redundant assignment survives.
    """

    def __init__(self, ail_graph: networkx.DiGraph):
        self._graph = ail_graph
        self.propagated = 0
        self.removed = 0
        self.pinned_by_reference = 0
        self.opaque_frame_access = False

    #
    # analysis
    #

    @staticmethod
    def _is_stack_vvar(expr) -> bool:
        return isinstance(expr, VirtualVariable) and getattr(expr, "was_stack", False)

    def _copies(self) -> dict[int, VirtualVariable]:
        """``{destination varid: source}`` for every assignment that is a bare stack-slot copy."""
        out: dict[int, VirtualVariable] = {}
        for block in self._graph:
            for stmt in block.statements or []:
                if (
                    isinstance(stmt, Assignment)
                    and self._is_stack_vvar(stmt.dst)
                    and isinstance(stmt.src, VirtualVariable)
                    and stmt.dst.varid != stmt.src.varid
                    and stmt.dst.bits == stmt.src.bits
                ):
                    out[stmt.dst.varid] = stmt.src
        return out

    def _referenced_varids(self) -> set[int]:
        """Variables whose address is taken, and so may be read through a pointer."""
        found: set[int] = set()
        coalescer = self

        class _Scan(AILBlockViewer):
            def _handle_UnaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
                if expr.op == "Reference" and isinstance(expr.operand, VirtualVariable):
                    found.add(expr.operand.varid)
                return super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)

            def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
                coalescer._note_frame_address(expr.addr)
                return super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

            def _handle_Store(self, stmt_idx, stmt, block):
                coalescer._note_frame_address(stmt.addr)
                return super()._handle_Store(stmt_idx, stmt, block)

        scanner = _Scan()
        for block in self._graph:
            scanner.walk(block)
        return found

    def _note_frame_address(self, addr) -> None:
        """Record an access that could name any slot rather than one in particular."""
        if not self._names_one_slot(addr) and self._mentions_reference(addr):
            self.opaque_frame_access = True

    @classmethod
    def _names_one_slot(cls, expr, depth: int = 0) -> bool:
        """Whether an address expression denotes a single, fixed location."""
        if depth > 16:
            return False
        if isinstance(expr, (Const, VirtualVariable)):
            return True
        op = getattr(expr, "op", None)
        if op == "Reference":
            return True
        if op in ("Add", "Sub"):
            # a constant displacement keeps it fixed; two unknown terms do not
            non_const = [o for o in expr.operands if not isinstance(o, Const)]
            if len(non_const) <= 1:
                return all(cls._names_one_slot(o, depth + 1) for o in non_const)
        return False

    @classmethod
    def _mentions_reference(cls, expr, depth: int = 0) -> bool:
        if depth > 16 or expr is None:
            return False
        if getattr(expr, "op", None) == "Reference":
            return True
        operands = getattr(expr, "operands", None)
        if operands is None:
            operand = getattr(expr, "operand", None)
            return cls._mentions_reference(operand, depth + 1) if operand is not None else False
        return any(cls._mentions_reference(o, depth + 1) for o in operands)

    def _use_counts(self) -> dict[int, int]:
        """How many times each variable is *read* (definitions do not count)."""
        counts: dict[int, int] = {}

        class _Count(AILBlockViewer):
            def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
                counts[expr.varid] = counts.get(expr.varid, 0) + 1
                return None

            def _handle_Assignment(self, stmt_idx, stmt, block):
                # walk the source only; the destination is a definition, not a use
                self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
                return None

        counter = _Count()
        for block in self._graph:
            counter.walk(block)
        return counts

    #
    # rewriting
    #

    def _resolve(self, copies: dict[int, VirtualVariable]) -> dict[int, VirtualVariable]:
        """Follow each copy to the end of its chain, so one pass collapses the whole run."""
        resolved: dict[int, VirtualVariable] = {}
        for varid in copies:
            seen = {varid}
            source = copies[varid]
            while source.varid in copies and source.varid not in seen:
                seen.add(source.varid)
                source = copies[source.varid]
            resolved[varid] = source
        return resolved

    def _substitute(self, resolved: dict[int, VirtualVariable]) -> int:
        count = 0
        coalescer = self

        class _Rewrite(AILBlockRewriter):
            def _handle_UnaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
                # Reference(v) is the address *of that slot*. Substituting the value's source
                # inside it would silently change which slot is addressed.
                if expr.op == "Reference":
                    return expr
                return super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)

            def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
                # AILBlockRewriter feeds the result back in, so "unchanged" is the expression
                # itself -- returning None would be read as the next expression to rewrite.
                replacement = resolved.get(expr.varid)
                if replacement is None or replacement.varid == expr.varid:
                    return expr
                nonlocal count
                count += 1
                return replacement

            def _handle_Assignment(self, stmt_idx, stmt, block):
                # the destination is a definition; only the source is a use
                src = self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
                if src is stmt.src:
                    return None
                return Assignment(stmt.idx, stmt.dst, src, **stmt.tags)

        rewriter = _Rewrite(update_block=False)
        for block in list(self._graph):
            new_block = rewriter.walk(block)
            if new_block is not None and new_block is not block:
                block.statements = list(new_block.statements)
        _ = coalescer
        return count

    def run(self) -> networkx.DiGraph:
        copies = self._copies()
        if not copies:
            return self._graph

        referenced = self._referenced_varids()
        resolved = self._resolve(copies)
        self.propagated = self._substitute(resolved)

        # Only now are the remaining uses known.
        counts = self._use_counts()
        removable = {
            varid
            for varid in copies
            if counts.get(varid, 0) == 0 and varid not in referenced and not self.opaque_frame_access
        }
        self.pinned_by_reference = sum(1 for varid in copies if varid in referenced)

        if removable:
            for block in self._graph:
                kept = [
                    stmt
                    for stmt in block.statements or []
                    if not (
                        isinstance(stmt, Assignment)
                        and isinstance(stmt.dst, VirtualVariable)
                        and stmt.dst.varid in removable
                    )
                ]
                if len(kept) != len(block.statements or []):
                    self.removed += len(block.statements) - len(kept)
                    block.statements = kept

        l.debug(
            "stack copy coalescing: %d copies, %d uses rewritten, %d removed (%d pinned by reference, "
            "opaque frame access: %s)",
            len(copies),
            self.propagated,
            self.removed,
            self.pinned_by_reference,
            self.opaque_frame_access,
        )
        return self._graph


def coalesce_stack_copies(ail_graph: networkx.DiGraph) -> networkx.DiGraph:
    return StackCopyCoalescer(ail_graph).run()
