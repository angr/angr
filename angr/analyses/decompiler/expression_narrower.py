from __future__ import annotations
from typing import Any, TYPE_CHECKING
from collections import defaultdict
import logging

from angr.ailment import AILBlockRewriter, AILBlockWalker, Const
from angr.ailment.statement import Assignment, Call
from angr.ailment.expression import Atom, VirtualVariable, Convert, BinaryOp, Phi
from angr.ailment.utils import is_none_or_likeable

from angr.knowledge_plugins.key_definitions import atoms
from angr.code_location import AILCodeLocation

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
        use_exprs: list[tuple[atoms.VirtualVariable, AILCodeLocation]] | None = None,
        phi_vars: set[VirtualVariable] | None = None,
    ):
        self.narrowable = narrowable
        self.to_size = to_size
        self.use_exprs = use_exprs
        self.phi_vars = phi_vars

    def __repr__(self):
        if self.narrowable:
            return f"<{self.use_exprs} -> {self.to_size} bytes, phi_vars={self.phi_vars}>"
        return "<not narrowable>"


class EffectiveSizeExtractor(AILBlockWalker[None, None, None]):
    """
    Walks a statement or an expression and extracts the effective size (in bits).

    For example, for target expression rax, `(rax & 0xff) + 0x1` means the effective size of rax is 8 bits, from bit
    0 to bit 7. We record this information in expr_to_effective_bits as {rax: (0, 8)}.

    We pay special consideration to expressions that are used as Call arguments, as they may have been converted to a
    smaller size because the Call argument needs that size, but the Call prototype may have been incorrectly inferred.
    """

    def __init__(self, target_expr: Expression, ignore_call_args: bool = True):
        super().__init__()
        self._target_expr = target_expr
        self._ignore_call_args = ignore_call_args
        self.expr_to_effective_bits: dict[Expression, tuple[int, int]] = {}
        self.expr_used_as_call_arg_effective_bits: tuple[int, int] | None = None

    def _update_effective_bits(self, expr, lo_bits: int, hi_bits: int):
        existing = self.expr_to_effective_bits.get(expr)
        if existing is None:
            self.expr_to_effective_bits[expr] = lo_bits, hi_bits
        else:
            self.expr_to_effective_bits[expr] = max(existing[0], lo_bits), min(existing[1], hi_bits)

    def _top(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None):
        pass

    def _stmt_top(self, stmt_idx: int, stmt: Statement, block: Block | None):
        pass

    def _handle_block_end(self, stmt_results, block: Block):
        pass

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Any:
        if is_none_or_likeable(expr, self._target_expr):
            # we are done!
            if expr not in self.expr_to_effective_bits:
                self._update_effective_bits(expr, 0, expr.bits)
            return
        super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Insert(self, expr_idx: int, expr, stmt_idx: int, stmt: Statement | None, block: Block | None):
        # self._handle_expr(0, expr.base, stmt_idx, stmt, block)
        self._handle_expr(1, expr.offset, stmt_idx, stmt, block)
        self._handle_expr(2, expr.value, stmt_idx, stmt, block)

    def _handle_Extract(self, expr_idx: int, expr, stmt_idx: int, stmt: Statement | None, block: Block | None):
        if isinstance(expr.offset, Const):
            self._update_effective_bits(expr.base, expr.offset.value, expr.offset.value + expr.bits)
        self._handle_expr(0, expr.base, stmt_idx, stmt, block)
        self._handle_expr(1, expr.offset, stmt_idx, stmt, block)

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self._handle_expr(0, expr.addr, stmt_idx, stmt, block)

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement | None, block: Block | None):
        if expr.args is not None:
            for i, arg in enumerate(expr.args):
                if (
                    self._ignore_call_args
                    and isinstance(arg, Convert)
                    and arg.to_bits < arg.from_bits
                    and is_none_or_likeable(arg.operand, self._target_expr)
                ):
                    self.expr_used_as_call_arg_effective_bits = 0, arg.to_bits
                else:
                    self._handle_expr(i, arg, stmt_idx, stmt, block)

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
        if stmt.args is not None:
            for i, arg in enumerate(stmt.args):
                if (
                    self._ignore_call_args
                    and isinstance(arg, Convert)
                    and arg.to_bits < arg.from_bits
                    and is_none_or_likeable(arg.operand, self._target_expr)
                ):
                    self.expr_used_as_call_arg_effective_bits = 0, arg.to_bits
                else:
                    self._handle_expr(i, arg, stmt_idx, stmt, block)

        if stmt.ret_expr is not None:
            self._handle_expr(0, stmt.ret_expr, stmt_idx, stmt, block)

    def _handle_BinaryOp(
        self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        effective_bits = self.expr_to_effective_bits.get(expr)
        if effective_bits is None:
            effective_bits = 0, expr.bits
        if expr.op == "And" and isinstance(expr.operands[1], Const):
            match expr.operands[1].value:
                case 0xFF:
                    lo_bits, hi_bits = 0, 8
                case 0xFFFF:
                    lo_bits, hi_bits = 0, 16
                case 0xFFFF_FFFF:
                    lo_bits, hi_bits = 0, 32
                case 0xFFFF_FFFF_FFFF_FFFF:
                    lo_bits, hi_bits = 0, 64
                case _:
                    lo_bits, hi_bits = effective_bits

            self._update_effective_bits(expr.operands[0], lo_bits, hi_bits)

        elif expr.op in {"Add", "Sub", "Mul", "Mod", "Xor", "Or", "And"}:
            self._update_effective_bits(expr.operands[0], effective_bits[0], effective_bits[1])
            self._update_effective_bits(expr.operands[1], effective_bits[0], effective_bits[1])
        elif expr.op == "Shl":
            self._update_effective_bits(expr.operands[0], effective_bits[0], effective_bits[1])

        self._handle_expr(0, expr.operands[0], stmt_idx, stmt, block)
        self._handle_expr(1, expr.operands[1], stmt_idx, stmt, block)

    def _handle_UnaryOp(self, expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt: Statement | None, block: Block | None):
        if expr.op == "Reference":
            # we really only need 1 byte of the target variable :)
            pass
        else:
            self._update_effective_bits(expr, 0, expr.bits)
        self._handle_expr(0, expr.operand, stmt_idx, stmt, block)

    def _handle_Convert(self, expr_idx: int, expr: Convert, stmt_idx: int, stmt: Statement | None, block: Block | None):
        effective_bits = self.expr_to_effective_bits.get(expr)
        if effective_bits is None or effective_bits[1] > expr.to_bits:
            effective_bits = 0, expr.to_bits
        self._update_effective_bits(expr.operand, effective_bits[0], effective_bits[1])
        self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block)

    def _handle_ITE(self, expr_idx: int, expr: ITE, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self._handle_expr(0, expr.cond, stmt_idx, stmt, block)
        self._handle_expr(1, expr.iftrue, stmt_idx, stmt, block)
        self._handle_expr(2, expr.iffalse, stmt_idx, stmt, block)

    def _handle_DirtyExpression(
        self, expr_idx: int, expr: DirtyExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        if expr.operands:
            for i, op in enumerate(expr.operands):
                self._handle_expr(i, op, stmt_idx, stmt, block)

    def _handle_VEXCCallExpression(
        self, expr_idx: int, expr: VEXCCallExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        for idx, operand in enumerate(expr.operands):
            self._handle_expr(idx, operand, stmt_idx, stmt, block)


class ExpressionNarrower(AILBlockRewriter):
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

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Block | None) -> Assignment:
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
                    new_var = vvar

                src_and_vvars.append((src, new_var))

            new_src = Phi(stmt.src.idx, stmt.src.bits, src_and_vvars, **stmt.src.tags)

        else:
            new_src = self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
            changed = new_src is not stmt.src

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
            changed |= new_dst is not stmt.dst

        if changed:
            self.narrowed_any = True
            assert isinstance(new_dst, Atom)
            return Assignment(stmt.idx, new_dst, new_src, **stmt.tags)

        return stmt

    def _handle_VirtualVariable(
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
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
        return expr

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None) -> Call:
        new_stmt = super()._handle_Call(stmt_idx, stmt, block)
        assert isinstance(new_stmt, Call)
        changed = new_stmt is not stmt

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

        return stmt
