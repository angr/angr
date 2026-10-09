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

When the two Inserts overwrite the whole base but their values are not halves of one source (MSVC spilling two
dword arguments into a qword slot for ``fild qword``), the pair becomes ``hi Concat lo`` (except in Go binaries).

The Extract definitions (and any copies between them and the Inserts, or the overwritten base) are dropped once the
collapse leaves them without uses. They are O0 spills of the parameter halves into stack locals; the generic dead-assignment removal keeps
unused stack variables, so they would otherwise survive as ``v0 = *((unsigned int *)&a0)``.
"""

from __future__ import annotations

import archinfo
import networkx

from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, Expression, Extract, Insert, VirtualVariable
from angr.ailment.statement import Assignment, Statement
from angr.utils.ssa import get_vvar_uselocs

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

        blocks = [node for node in graph.nodes() if isinstance(node, Block)]
        # Go's passes read the words of a multi-word value (string, slice, interface) built in a stack slot from its
        # Insert chain; a Concat would hide them
        concat_whole = not self.project.is_go_binary
        vvar_defs = self._collect_vvar_defs(blocks)
        use_counts = {varid: len(uses) for varid, uses in get_vvar_uselocs(blocks).items()}

        changed = False
        # vvars whose uses a collapse removed; their definitions are dropped below if nothing else uses them
        orphan_candidates: set[int] = set()
        for node in blocks:
            new_stmts = list(node.statements)
            i = 0
            while i < len(new_stmts) - 1:
                s0, s1 = new_stmts[i], new_stmts[i + 1]
                result = self._try_collapse(s0, s1, vvar_defs, use_counts, orphan_candidates, concat_whole)
                if result is not None:
                    new_stmts[i : i + 2] = result
                    changed = True
                    # Don't advance -- re-check at same position
                else:
                    i += 1
            if changed:
                node.statements = new_stmts

        if changed:
            self._remove_orphaned_defs(blocks, orphan_candidates)
            self.out_graph = graph

    @staticmethod
    def _collect_vvar_defs(blocks: list[Block]) -> dict[int, tuple[Block, int, Assignment]]:
        vvar_defs: dict[int, tuple[Block, int, Assignment]] = {}
        for node in blocks:
            for stmt_idx, s in enumerate(node.statements):
                if isinstance(s, Assignment) and isinstance(s.dst, VirtualVariable):
                    vvar_defs[s.dst.varid] = (node, stmt_idx, s)
        return vvar_defs

    @staticmethod
    def _pure_copy_sources(expr) -> list[VirtualVariable] | None:
        """Return the vvars an effect-free copy expression (vvar, Const, Extract of such) reads, or None."""
        if isinstance(expr, VirtualVariable):
            return [expr]
        if isinstance(expr, Const):
            return []
        if isinstance(expr, Extract) and isinstance(expr.offset, Const):
            return InsertExtractReverter._pure_copy_sources(expr.base)
        return None

    def _remove_orphaned_defs(self, blocks: list[Block], candidates: set[int]) -> None:
        """Drop pure-copy definitions of ``candidates`` that no longer have any use, transitively."""
        while candidates:
            vvar_defs = self._collect_vvar_defs(blocks)
            use_counts = {varid: len(uses) for varid, uses in get_vvar_uselocs(blocks).items()}
            removed: dict[Block, set[int]] = {}
            next_candidates: set[int] = set()
            for varid in candidates:
                if varid not in vvar_defs or use_counts.get(varid, 0) > 0:
                    continue
                block, stmt_idx, stmt = vvar_defs[varid]
                srcs = self._pure_copy_sources(stmt.src)
                if srcs is None:
                    continue
                removed.setdefault(block, set()).add(stmt_idx)
                next_candidates.update(src.varid for src in srcs)
            if not removed:
                break
            for block, stmt_idxs in removed.items():
                block.statements = [s for idx, s in enumerate(block.statements) if idx not in stmt_idxs]
            candidates = next_candidates

    @staticmethod
    def _try_collapse(
        stmt0: Statement,
        stmt1: Statement,
        vvar_defs: dict[int, tuple[Block, int, Assignment]],
        use_counts: dict[int, int],
        orphan_candidates: set[int],
        concat_whole: bool = True,
    ) -> list[Statement] | None:
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

        # Outer Insert's base must reference the inner Insert's destination, and be its only use
        if not (isinstance(outer_insert.base, VirtualVariable) and outer_insert.base.varid == stmt0.dst.varid):
            return None
        if use_counts.get(stmt0.dst.varid, 0) != 1:
            return None

        inner_off = inner_insert.offset.value
        outer_off = outer_insert.offset.value
        if inner_insert.endness != outer_insert.endness:
            return None

        # The two inserts must cover the full width
        (lo_off, lo_ins), (hi_off, hi_ins) = sorted(
            [(inner_off, inner_insert), (outer_off, outer_insert)], key=lambda item: item[0]
        )
        lo_bits = lo_ins.value.bits
        hi_bits = hi_ins.value.bits
        if lo_bits % 8 or hi_bits % 8:
            return None
        if lo_off != 0 or lo_bits // 8 != hi_off or lo_bits + hi_bits != outer_insert.bits:
            return None

        # Resolve values through VVar definitions (follow chains to a fixed point)
        inner_val = InsertExtractReverter._resolve(inner_insert.value, vvar_defs)
        outer_val = InsertExtractReverter._resolve(outer_insert.value, vvar_defs)

        if (
            isinstance(inner_val, Extract)
            and isinstance(outer_val, Extract)
            and isinstance(inner_val.offset, Const)
            and isinstance(outer_val.offset, Const)
            and inner_val.base.likes(outer_val.base)
            and inner_val.offset.value == inner_off
            and outer_val.offset.value == outer_off
            and inner_val.base.bits == outer_insert.bits
        ):
            for val in (inner_insert.value, outer_insert.value):
                if isinstance(val, VirtualVariable):
                    orphan_candidates.add(val.varid)
            # Replace both with: vvar_B = source
            return [Assignment(stmt1.idx, stmt1.dst, inner_val.base, **stmt1.tags)]

        if not concat_whole:
            return None

        # Otherwise the two pieces still overwrite the whole base: vvar_B = hi Concat lo
        orphan_candidates.update(vvar.varid for vvar in InsertExtractReverter._vvars_in(inner_insert.base))
        # (offset 0 is the least significant piece on little-endian)
        if outer_insert.endness == archinfo.Endness.LE:
            high, low = hi_ins.value, lo_ins.value
        else:
            high, low = lo_ins.value, hi_ins.value
        concat = BinaryOp(outer_insert.idx, "Concat", [high, low], False, bits=outer_insert.bits, **outer_insert.tags)
        return [Assignment(stmt1.idx, stmt1.dst, concat, **stmt1.tags)]

    @staticmethod
    def _vvars_in(expr: Expression) -> list[VirtualVariable]:
        """The vvars of an Insert base built by ssailification (a vvar, possibly widened with a Concat)."""
        if isinstance(expr, VirtualVariable):
            return [expr]
        if isinstance(expr, BinaryOp) and expr.op == "Concat":
            return [vvar for op in expr.operands for vvar in InsertExtractReverter._vvars_in(op)]
        return []

    @staticmethod
    def _resolve(expr: Expression, vvar_defs: dict[int, tuple[Block, int, Assignment]]) -> Expression:
        seen: set[int] = set()
        while isinstance(expr, VirtualVariable) and expr.varid in vvar_defs and expr.varid not in seen:
            seen.add(expr.varid)
            expr = vvar_defs[expr.varid][2].src
        return expr
