"""Combined walker that collects VVar uses + Tmp uses in a single pass.

SPropagator's ``_analyze`` historically called four separate helpers
(``get_vvar_deflocs``, ``get_vvar_uselocs``, ``get_tmp_deflocs``,
``get_tmp_uselocs``) against the same set of blocks. Each of the two
``_uselocs`` helpers spun up its own ``AILBlockViewer`` and walked
every block independently.

Folding both use-collectors into a single walker halves the
walk-the-block cost (one ``_handle_expr`` dispatch chain per visited
node, not two) and is a drop-in replacement: the per-block tmp use
extraction matches ``TmpUsesCollector``'s shape and the cross-block
vvar use accumulator matches ``VVarUsesCollector``'s.
"""

from __future__ import annotations

from collections import defaultdict

from angr.ailment import AILBlockViewer
from angr.ailment.block import Block
from angr.ailment.expression import Phi, Tmp, VirtualVariable
from angr.ailment.statement import Statement
from angr.code_location import AILCodeLocation


class VVarAndTmpUsesCollector(AILBlockViewer):
    """Collect VVar uses + Tmp uses in a single pass.

    See ``VVarUsesCollector`` / ``TmpUsesCollector`` for the per-side
    semantics. This combined version inherits both:

    - ``vvar_and_uselocs`` accumulates across all blocks walked
      (consumer extracts when done).
    - ``tmp_and_uselocs`` is intended to be extracted per-block;
      ``reset_tmp_uses_only()`` clears just the tmp side without
      losing the cross-block vvar accumulator.
    """

    def __init__(self) -> None:
        super().__init__()
        self.vvar_and_uselocs: dict[int, list[tuple[VirtualVariable, AILCodeLocation]]] = defaultdict(list)
        self.tmp_and_uselocs: dict[tuple[int, int], set[tuple[Tmp, int]]] = defaultdict(set)
        # See ``VVarUsesCollector._dst_varid_for_current_stmt``.
        self._dst_varid_for_current_stmt: int | None = None

    def reset(self) -> None:
        self.vvar_and_uselocs = defaultdict(list)
        self.tmp_and_uselocs = defaultdict(set)
        self._dst_varid_for_current_stmt = None

    def reset_tmp_uses_only(self) -> None:
        self.tmp_and_uselocs = defaultdict(set)

    def _handle_expr(self, expr_idx: int, expr, stmt_idx: int, stmt, block: Block | None):
        if expr.tags.get("extra_def", False):
            return None
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Assignment(self, stmt_idx: int, stmt, block: Block | None):
        # Skip the dst subtree (def, not a use). See ``VVarUsesCollector``
        # / ``TmpUsesCollector`` overrides for the rationale.
        if isinstance(stmt.dst, VirtualVariable) and isinstance(stmt.src, Phi):
            self._dst_varid_for_current_stmt = stmt.dst.varid
        else:
            self._dst_varid_for_current_stmt = None
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
        self._dst_varid_for_current_stmt = None

    def _handle_VirtualVariable(
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        if expr.varid == self._dst_varid_for_current_stmt:
            return
        if block is not None and stmt is not None:
            self.vvar_and_uselocs[expr.varid].append(
                (expr, AILCodeLocation(block.addr, block.idx, stmt_idx, stmt.tags.get("ins_addr")))
            )

    def _handle_Tmp(self, expr_idx: int, expr: Tmp, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self.tmp_and_uselocs[(expr.tmp_idx, expr.bits)].add((expr, stmt_idx))
