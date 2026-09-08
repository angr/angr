"""Function-level optimization pass that collapses Insert/Extract round-trips.

On i386 cdecl at O0, double parameters are decomposed into 4-byte halves and
reassembled via Insert/Extract chains that may span multiple blocks::

    Block A:
        vvar_56 = Extract(a1, 32bits@0)
        vvar_57 = Extract(a1, 32bits@4)

    Block B:
        vvar_61 = Insert(base, 0x4, vvar_57)
        vvar_62 = Insert(vvar_61, 0x0, vvar_56)
        call(vvar_62)

This pass resolves VVar references to their definitions across blocks and
replaces the Insert chain with a direct reference to the source variable::

    Block B:
        call(a1)
"""

from __future__ import annotations

import networkx

from angr.ailment.block import Block
from angr.ailment.expression import Const, Extract, Insert, VirtualVariable
from angr.ailment.statement import Assignment

from .optimization_pass import OptimizationPass, OptimizationPassStage


class InsertExtractReverter(OptimizationPass):
    """Collapse cross-block Insert(Extract()) round-trips into direct variable references."""

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_MAKING_CALLSITES
    NAME = "Collapse Insert/Extract round-trips"
    DESCRIPTION = __doc__

    def __init__(self, func, manager=None, **kwargs):
        super().__init__(func, manager, **kwargs)
        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        graph: networkx.DiGraph = self._graph
        if graph is None:
            return

        # Build a global VVar -> definition map
        vvar_defs: dict[int, object] = {}
        for node in graph.nodes():
            if not isinstance(node, Block):
                continue
            for s in node.statements:
                if isinstance(s, Assignment) and isinstance(s.dst, VirtualVariable):
                    vvar_defs[s.dst.varid] = s.src

        changed = False
        for node in graph.nodes():
            if not isinstance(node, Block):
                continue
            new_stmts = list(node.statements)
            i = 0
            while i < len(new_stmts) - 1:
                s0, s1 = new_stmts[i], new_stmts[i + 1]
                result = self._try_collapse(s0, s1, vvar_defs)
                if result is not None:
                    new_stmts[i : i + 2] = result
                    changed = True
                    # Don't advance -- re-check at same position
                else:
                    i += 1
            if changed:
                node.statements = new_stmts

        if changed:
            self.out_graph = graph

    @staticmethod
    def _try_collapse(stmt0: object, stmt1: object, vvar_defs: dict[int, object]) -> list | None:
        """Try to collapse a pair of Insert assignments into a single assignment.

        Returns a replacement statement list or None if not matched.
        """
        if not (
            isinstance(stmt0, Assignment)
            and isinstance(stmt1, Assignment)
            and isinstance(stmt0.dst, VirtualVariable)
            and isinstance(stmt1.dst, VirtualVariable)
        ):
            return None

        inner_insert = stmt0.src
        outer_insert = stmt1.src
        if not (isinstance(inner_insert, Insert) and isinstance(outer_insert, Insert)):
            return None
        if not (
            isinstance(inner_insert.offset, Const)
            and isinstance(outer_insert.offset, Const)
            and isinstance(inner_insert.offset.value, int)
            and isinstance(outer_insert.offset.value, int)
        ):
            return None

        # Outer Insert's base must reference the inner Insert's destination
        if not (isinstance(outer_insert.base, VirtualVariable) and outer_insert.base.varid == stmt0.dst.varid):
            return None

        # Resolve values through VVar definitions (follow chains to a fixed point)
        inner_val = inner_insert.value
        seen: set[int] = set()
        while isinstance(inner_val, VirtualVariable) and inner_val.varid in vvar_defs and inner_val.varid not in seen:
            seen.add(inner_val.varid)
            inner_val = vvar_defs[inner_val.varid]
        outer_val = outer_insert.value
        seen.clear()
        while isinstance(outer_val, VirtualVariable) and outer_val.varid in vvar_defs and outer_val.varid not in seen:
            seen.add(outer_val.varid)
            outer_val = vvar_defs[outer_val.varid]

        if not (isinstance(inner_val, Extract) and isinstance(outer_val, Extract)):
            return None
        if not (isinstance(inner_val.offset, Const) and isinstance(outer_val.offset, Const)):
            return None

        # Both Extracts must reference the same source
        if not inner_val.base.likes(outer_val.base):
            return None

        inner_off = inner_insert.offset.value
        outer_off = outer_insert.offset.value

        # Extract offsets must match their Insert offsets
        if inner_val.offset.value != inner_off or outer_val.offset.value != outer_off:
            return None

        # The two inserts must cover the full width
        lo_off = min(outer_off, inner_off)
        hi_off = max(outer_off, inner_off)
        lo_size = (outer_val.bits if outer_off <= inner_off else inner_val.bits) // 8
        hi_size = (inner_val.bits if outer_off <= inner_off else outer_val.bits) // 8

        if lo_off != 0 or lo_off + lo_size != hi_off or hi_off + hi_size != outer_insert.bits // 8:
            return None

        source = inner_val.base
        if source.bits != outer_insert.bits:
            return None

        # Replace both with: vvar_B = source
        return [Assignment(stmt1.idx, stmt1.dst, source, **stmt1.tags)]
