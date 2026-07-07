from __future__ import annotations

from collections import defaultdict

from angr.ailment import AILBlockViewer
from angr.ailment.block import Block
from angr.ailment.expression import Phi, VirtualVariable
from angr.ailment.statement import Assignment, Statement
from angr.code_location import AILCodeLocation


class VVarUsesCollector(AILBlockViewer):
    """
    Collect all uses of virtual variables and their use locations in an AIL block. Skip collecting use locations if
    block is not specified.
    """

    def __init__(self):
        super().__init__()

        self.vvar_and_uselocs: dict[int, list[tuple[VirtualVariable, AILCodeLocation]]] = defaultdict(list)
        self.vvars: set[int] = set()
        self._walking_assignment_dst: bool = False
        self._assignment_dst_varid: int | None = None
        self._assignment_src_is_phi: bool = False

    def reset(self) -> None:
        self.vvar_and_uselocs = defaultdict(list)
        self.vvars = set()
        self._walking_assignment_dst = False
        self._assignment_dst_varid = None
        self._assignment_src_is_phi = False

    def _handle_expr(self, expr_idx: int, expr, stmt_idx: int, stmt, block: Block | None):
        if expr.tags.get("extra_def", False):
            return None
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Block | None):
        # Read ``stmt.dst`` / ``stmt.src`` exactly once per statement: each
        # access materializes a fresh wrapper around a clone of the whole
        # subtree (O(subtree size)), so reading them per visited vvar --
        # as a def-vs-use check inside ``_handle_VirtualVariable`` would --
        # makes walking a statement quadratic in its size. Discriminating
        # the def site positionally (are we inside the dst subtree?) is
        # also the only sound option: ``idx`` is not unique (``idx=None``
        # normalizes to 0), and ``is`` identity never survives the
        # wrapper boundary.
        dst = stmt.dst
        src = stmt.src
        # MultiStatementExpression can nest assignments inside ``src``;
        # save and restore the outer statement's context.
        prev = (self._walking_assignment_dst, self._assignment_dst_varid, self._assignment_src_is_phi)
        self._assignment_dst_varid = dst.varid if isinstance(dst, VirtualVariable) else None
        self._assignment_src_is_phi = isinstance(src, Phi)
        self._walking_assignment_dst = True
        try:
            self._handle_expr(0, dst, stmt_idx, stmt, block)
            self._walking_assignment_dst = False
            self._handle_expr(1, src, stmt_idx, stmt, block)
        finally:
            self._walking_assignment_dst, self._assignment_dst_varid, self._assignment_src_is_phi = prev

    def _handle_VirtualVariable(
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        if self._walking_assignment_dst:
            # the def site itself, not a use
            return
        if (
            self._assignment_src_is_phi
            and self._assignment_dst_varid is not None
            and expr.varid == self._assignment_dst_varid
        ):
            # avoid phi loops
            return
        if block is not None and stmt is not None:
            self.vvar_and_uselocs[expr.varid].append(
                (expr, AILCodeLocation(block.addr, block.idx, stmt_idx, stmt.tags.get("ins_addr")))
            )
        self.vvars.add(expr.varid)
