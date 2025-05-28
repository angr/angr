from __future__ import annotations
from typing import Any, TYPE_CHECKING
from collections import defaultdict
import logging

from angr.ailment import AILBlockWalkerBase, AILBlockWalker
from angr.ailment.statement import Assignment, Call
from angr.ailment.expression import VirtualVariable, Convert, BinaryOp, Phi

from angr.knowledge_plugins.key_definitions import atoms
from angr.code_location import CodeLocation

if TYPE_CHECKING:
    from angr.ailment.expression import (
        Expression,
        Load,
        UnaryOp,
        ITE,
        DirtyExpression,
        VEXCCallExpression,
    )
    from angr.ailment.statement import Statement
    from angr.ailment.block import Block


_l = logging.getLogger(__name__)


class ExprNarrowingInfo:
    """
    Stores the analysis result of _narrowing_needed().
    """

    __slots__ = ("narrowable", "phi_vars", "to_size", "use_exprs")

    def __init__(
        self,
        narrowable: bool,
        to_size: int | None = None,
        use_exprs: list[tuple[atoms.VirtualVariable, CodeLocation, tuple[str, tuple[Expression, ...]]]] | None = None,
        phi_vars: set[VirtualVariable] | None = None,
    ):
        self.narrowable = narrowable
        self.to_size = to_size
        self.use_exprs = use_exprs
        self.phi_vars = phi_vars


class NarrowingInfoExtractor(AILBlockWalkerBase):
    """
    Walks a statement or an expression and extracts the operations that are applied on the given expression.

    For example, for target expression rax, `(rax & 0xff) + 0x1` means the following operations are applied on `rax`:
    rax & 0xff
    (rax & 0xff) + 0x1

    The previous expression is always used in the succeeding expression.
    """

    def __init__(self, target_expr: Expression):
        super().__init__()
        self._target_expr = target_expr
        self.operations = []

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Any:
        if expr == self._target_expr:
            # we are done!
            return True
        has_target_expr = super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)
        if has_target_expr:
            # record the current operation
            self.operations.append(expr)
            return True
        return False

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement, block: Block | None):
        return self._handle_expr(0, expr.addr, stmt_idx, stmt, block)

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        r = False
        if expr.args:
            for i, arg in enumerate(expr.args):
                r |= self._handle_expr(i, arg, stmt_idx, stmt, block)
        return r

    def _handle_BinaryOp(self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement, block: Block | None):
        r = self._handle_expr(0, expr.operands[0], stmt_idx, stmt, block)
        r |= self._handle_expr(1, expr.operands[1], stmt_idx, stmt, block)
        return r

    def _handle_UnaryOp(self, expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt: Statement, block: Block | None):
        return self._handle_expr(0, expr.operand, stmt_idx, stmt, block)

    def _handle_Convert(self, expr_idx: int, expr: Convert, stmt_idx: int, stmt: Statement, block: Block | None):
        return self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block)

    def _handle_ITE(self, expr_idx: int, expr: ITE, stmt_idx: int, stmt: Statement, block: Block | None):
        r = self._handle_expr(0, expr.cond, stmt_idx, stmt, block)
        r |= self._handle_expr(1, expr.iftrue, stmt_idx, stmt, block)
        r |= self._handle_expr(2, expr.iffalse, stmt_idx, stmt, block)
        return r

    def _handle_DirtyExpression(
        self, expr_idx: int, expr: DirtyExpression, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        r = False
        if expr.operands:
            for i, op in enumerate(expr.operands):
                r |= self._handle_expr(i, op, stmt_idx, stmt, block)
        return r

    def _handle_VEXCCallExpression(
        self, expr_idx: int, expr: VEXCCallExpression, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        r = False
        for idx, operand in enumerate(expr.operands):
            r |= self._handle_expr(idx, operand, stmt_idx, stmt, block)
        return r


class ExpressionNarrower(AILBlockWalker):
    """
    Narrows an expression regardless of whether the expression is a definition or a use.
    """

    def __init__(
        self, project, rd, narrowables, addr2blocks: dict[tuple[int, int | None], Block], new_blocks: dict[Block, Block]
    ):
        super().__init__(update_block=False)

        self.project = project
        self._rd = rd
        self._addr2blocks = addr2blocks
        self._new_blocks = new_blocks

        self.new_vvar_sizes: dict[int, int] = {}
        self.replacement_core_vvars: dict[int, list[VirtualVariable]] = defaultdict(list)
        self.narrowed_any = False

        for def_, narrow_info in narrowables:
            self.new_vvar_sizes[def_.atom.varid] = narrow_info.to_size

    def walk(self, block: Block):
        self.narrowed_any = False
        return super().walk(block)

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Block | None) -> Assignment | None:

        if isinstance(stmt.src, Phi):
            changed = False

            src_and_vvars = []
            for src, vvar in stmt.src.src_and_vvars:
                if vvar is None:
                    src_and_vvars.append((src, None))
                    continue
                if vvar.varid in self.new_vvar_sizes and self.new_vvar_sizes[vvar.varid] != vvar.size:
                    self.narrowed_any = True
                    changed = True
                    new_var = VirtualVariable(
                        vvar.idx,
                        vvar.varid,
                        self.new_vvar_sizes[vvar.varid] * self.project.arch.byte_width,
                        category=vvar.category,
                        oident=vvar.oident,
                        **vvar.tags,
                    )

                    self.replacement_core_vvars[new_var.varid].append(new_var)
                else:
                    new_var = None

                src_and_vvars.append((src, new_var))

            new_src = Phi(stmt.src.idx, stmt.src.bits, src_and_vvars, **stmt.src.tags)

        else:
            new_src = self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
            if new_src is None:
                changed = False
                new_src = stmt.src
            else:
                changed = True

        if isinstance(stmt.dst, VirtualVariable) and stmt.dst.varid in self.new_vvar_sizes:
            changed = True
            new_dst = VirtualVariable(
                stmt.dst.idx,
                stmt.dst.varid,
                self.new_vvar_sizes[stmt.dst.varid] * self.project.arch.byte_width,
                category=stmt.dst.category,
                oident=stmt.dst.oident,
                **stmt.dst.tags,
            )

            self.replacement_core_vvars[new_dst.varid].append(new_dst)

            if isinstance(new_src, Phi):
                new_src.bits = self.new_vvar_sizes[stmt.dst.varid] * self.project.arch.byte_width
            else:
                new_src = Convert(
                    None,
                    stmt.src.bits,
                    self.new_vvar_sizes[stmt.dst.varid] * self.project.arch.byte_width,
                    False,
                    new_src,
                    **new_src.tags,
                )
        else:
            new_dst = self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
            if new_dst is not None:
                changed = True
            else:
                new_dst = stmt.dst

        if changed:
            self.narrowed_any = True
            return Assignment(stmt.idx, new_dst, new_src, **stmt.tags)

        return None

    def _handle_VirtualVariable(
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement, block: Block | None
    ) -> Convert | None:
        if expr.varid in self.new_vvar_sizes and self.new_vvar_sizes[expr.varid] != expr.size:
            self.narrowed_any = True
            new_expr = VirtualVariable(
                expr.idx,
                expr.varid,
                self.new_vvar_sizes[expr.varid] * self.project.arch.byte_width,
                category=expr.category,
                oident=expr.oident,
                **expr.tags,
            )

            self.replacement_core_vvars[expr.varid].append(new_expr)

            return Convert(
                None,
                new_expr.bits,
                expr.bits,
                False,
                new_expr,
                **new_expr.tags,
            )
        return None

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None) -> Call | None:
        new_stmt = super()._handle_Call(stmt_idx, stmt, block)
        if new_stmt is None:
            changed = False
            new_stmt = stmt
        else:
            changed = True

        if (
            stmt.ret_expr is not None
            and isinstance(stmt.ret_expr, VirtualVariable)
            and stmt.ret_expr.was_reg
            and stmt.ret_expr.varid in self.new_vvar_sizes
            and stmt.ret_expr.size != self.new_vvar_sizes[stmt.ret_expr.varid]
        ):
            changed = True

            # update reg name
            tags = dict(stmt.ret_expr.tags)
            tags["reg_name"] = self.project.arch.translate_register_name(
                stmt.ret_expr.reg_offset, size=self.new_vvar_sizes[stmt.ret_expr.varid]
            )
            new_ret_expr = VirtualVariable(
                stmt.ret_expr.idx,
                stmt.ret_expr.varid,
                self.new_vvar_sizes[stmt.ret_expr.varid] * self.project.arch.byte_width,
                category=stmt.ret_expr.category,
                oident=stmt.ret_expr.oident,
                **tags,
            )
            self.replacement_core_vvars[new_ret_expr.varid].append(new_ret_expr)
            new_stmt.ret_expr = new_ret_expr

        if changed:
            self.narrowed_any = True
            return new_stmt

        return None
