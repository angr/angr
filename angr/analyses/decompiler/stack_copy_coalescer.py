from __future__ import annotations

import logging

import networkx

from angr.ailment import AILBlockRewriter
from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import Const, Phi, VirtualVariable
from angr.ailment.statement import Assignment, SideEffectStatement

l = logging.getLogger(name=__name__)


class StackCopyCoalescer:
    """
    Collapse chains of stack-slot copies left behind by devirtualization.

    A VM moves one value through a run of frame slots, which reaches the decompiler as
    ``v2 = v1; v5 = v2; v7 = v5;`` -- a fresh local per hop. In SSA each of those virtual variables
    has exactly one definition, so rewriting a use of the destination into a use of the source is
    value-preserving, however the slots are laid out -- unless either slot's address is taken: a
    write through that address changes the slot without a new definition.

    Deleting the copy afterwards is not. A stack virtual variable is also a *location*, and a load
    the analysis cannot pin down may read it. Two things therefore keep a copy alive:

    * its address is taken -- the slot appears under a ``Reference`` -- so a pointer to it exists;
    * some load or store addresses the frame through an expression this pass cannot resolve to one
      slot, which could name any of them.

    The second is deliberately coarse: one unresolvable frame access disables deletion everywhere
    rather than only near the slots it might touch. Propagation still happens, so the chain reads
    from its true source either way; only the now-redundant assignment survives.

    A copy is also forwarded into the phi statements that read its destination: the phi entry for predecessor ``P``
    reads the copy's source instead. This is copy propagation on SSA values and needs no interference check here;
    the phi may now merge values of other stack slots, and dephication keeps the copies such a phi really needs
    (swaps, values that stay live). It requires that both definitions reach the end of ``P`` on every path, i.e.
    source dominates destination dominates ``P``, and that neither stack slot is address-taken in any version.
    """

    def __init__(self, ail_graph: networkx.DiGraph, entry=None, forward_into_phis: bool = True):
        self._graph = ail_graph
        self._entry = entry
        self._forward_into_phis = forward_into_phis
        self.propagated = 0
        self.phi_propagated = 0
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
    # phi forwarding
    #

    @staticmethod
    def _slot_range(vvar: VirtualVariable) -> tuple[int, int] | None:
        if not getattr(vvar, "was_stack", False):
            return None
        return vvar.stack_offset, vvar.stack_offset + max(vvar.size, 1)

    def _referenced_slot_ranges(self, referenced: set[int]) -> list[tuple[int, int]]:
        """Byte ranges of the stack slots with an address-taken version."""
        if not referenced:
            return []
        ranges = set()

        class _Scan(AILBlockViewer):
            def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
                if expr.varid in referenced:
                    r = StackCopyCoalescer._slot_range(expr)
                    if r is not None:
                        ranges.add(r)

        scanner = _Scan()
        for block in self._graph:
            scanner.walk(block)
        return sorted(ranges)

    def _definitions(self) -> dict[int, tuple[object, int]]:
        defs: dict[int, tuple[object, int]] = {}
        for block in self._graph:
            for idx, stmt in enumerate(block.statements or []):
                dst = None
                if isinstance(stmt, Assignment):
                    dst = stmt.dst
                elif isinstance(stmt, SideEffectStatement):
                    dst = stmt.ret_expr
                if isinstance(dst, VirtualVariable):
                    defs[dst.varid] = block, idx
        return defs

    def _dominance(self):
        """``dominates(a, b)`` over blocks, or None when the graph has no identifiable entry."""
        entry = self._entry
        if entry is None:
            roots = [n for n in self._graph if self._graph.in_degree(n) == 0]
            if len(roots) != 1:
                return None
            entry = roots[0]
        if entry not in self._graph:
            return None
        idoms = networkx.immediate_dominators(self._graph, entry)
        children: dict[object, list] = {}
        for node, idom in idoms.items():
            if node is not idom:
                children.setdefault(idom, []).append(node)
        # pre/post numbering of the dominator tree
        span: dict[object, tuple[int, int]] = {}
        clock = 0
        stack = [(entry, iter(children.get(entry, ())))]
        enter = {entry: 0}
        while stack:
            node, it = stack[-1]
            child = next(it, None)
            if child is None:
                stack.pop()
                clock += 1
                span[node] = enter[node], clock
            else:
                clock += 1
                enter[child] = clock
                stack.append((child, iter(children.get(child, ()))))

        def dominates(a, b) -> bool:
            sa, sb = span.get(a), span.get(b)
            return sa is not None and sb is not None and sa[0] <= sb[0] and sb[1] <= sa[1]

        return dominates

    def _phi_forwardable(
        self, substitutable: dict[int, VirtualVariable], referenced: set[int], defs, dominates
    ) -> dict[int, VirtualVariable]:
        """The copies whose source may stand in for the destination in a phi."""
        pinned = self._referenced_slot_ranges(referenced)

        def slot_pinned(vvar: VirtualVariable) -> bool:
            r = self._slot_range(vvar)
            return r is not None and any(lo < r[1] and r[0] < hi for lo, hi in pinned)

        out = {}
        for varid, src in substitutable.items():
            dst_block, dst_idx = defs[varid]
            if slot_pinned(dst_block.statements[dst_idx].dst) or slot_pinned(src):
                continue
            src_def = defs.get(src.varid)
            if src_def is not None:
                # the source is defined before the copy on every path to it
                if src_def[0] is dst_block:
                    if src_def[1] >= dst_idx:
                        continue
                elif not dominates(src_def[0], dst_block):
                    continue
            out[varid] = src
        return out

    def _substitute_phis(self, forwardable: dict[int, VirtualVariable], defs, dominates) -> int:
        resolved = self._resolve(forwardable)
        blocks = {(block.addr, block.idx): block for block in self._graph}
        count = 0
        for block in self._graph:
            statements = list(block.statements or [])
            block_changed = False
            for idx, stmt in enumerate(statements):
                if not (isinstance(stmt, Assignment) and isinstance(stmt.src, Phi)):
                    continue
                new_entries = []
                changed = False
                for pred_key, vvar in stmt.src.src_and_vvars:
                    replacement = resolved.get(vvar.varid) if vvar is not None else None
                    pred = blocks.get((pred_key[0], pred_key[1])) if pred_key is not None else None
                    if (
                        replacement is not None
                        and pred is not None
                        and vvar.bits == replacement.bits
                        and dominates(defs[vvar.varid][0], pred)
                    ):
                        new_entries.append((pred_key, replacement))
                        changed = True
                        count += 1
                    else:
                        new_entries.append((pred_key, vvar))
                if changed:
                    new_phi = Phi(stmt.src.idx, stmt.src.bits, new_entries, **stmt.src.tags)
                    statements[idx] = Assignment(stmt.idx, stmt.dst, new_phi, **stmt.tags)
                    block_changed = True
            if block_changed:
                block.statements = statements
        return count

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
        # a slot whose address is taken may be written through it: its value at a use is neither the copied value
        # (destination) nor the value it held at the copy (source)
        substitutable = {
            varid: src for varid, src in copies.items() if varid not in referenced and src.varid not in referenced
        }
        resolved = self._resolve(substitutable)
        self.propagated = self._substitute(resolved)

        if self._forward_into_phis and (dominates := self._dominance()) is not None:
            defs = self._definitions()
            forwardable = self._phi_forwardable(substitutable, referenced, defs, dominates)
            self.phi_propagated = self._substitute_phis(forwardable, defs, dominates)

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
            "stack copy coalescing: %d copies, %d uses and %d phi sources rewritten, %d removed (%d pinned by "
            "reference, opaque frame access: %s)",
            len(copies),
            self.propagated,
            self.phi_propagated,
            self.removed,
            self.pinned_by_reference,
            self.opaque_frame_access,
        )
        return self._graph


def coalesce_stack_copies(ail_graph: networkx.DiGraph) -> networkx.DiGraph:
    return StackCopyCoalescer(ail_graph).run()
