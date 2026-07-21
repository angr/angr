from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING, Any

from angr.ailment import AILBlockRewriter, AILBlockWalker, Const
from angr.ailment.expression import Atom, BinaryOp, Call, Convert, Extract, Phi, VirtualVariable
from angr.ailment.statement import Assignment, SideEffectStatement
from angr.code_location import AILCodeLocation
from angr.knowledge_plugins.key_definitions import atoms

if TYPE_CHECKING:
    from angr.ailment.block import Block
    from angr.ailment.expression import (
        ITE,
        DirtyExpression,
        Expression,
        Load,
        UnaryOp,
        VEXCCallExpression,
    )
    from angr.ailment.manager import Manager
    from angr.ailment.statement import Statement


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
    Walks a statement once and extracts the effective size (in bits) of every virtual variable that appears in it.

    For example, for virtual variable rax, `(rax & 0xff) + 0x1` means the effective size of rax is 8 bits, from bit
    0 to bit 7. We record this information in vvar_effective_bits as {rax.varid: {rax.idx: (0, 8)}}.

    We pay special consideration to expressions that are used as Call arguments, as they may have been converted to a
    smaller size because the Call argument needs that size, but the Call prototype may have been incorrectly inferred.

    A single walk records information for all virtual variables in the statement, so one walker instance can be
    queried for many different variables without re-walking the statement. Constraints that parent expressions impose
    on their children are tracked per expression node (keyed by the node's ``idx``) during the walk; results are
    aggregated per (varid, expression idx) so that repeated occurrences of the same variable are kept separate.
    """

    def __init__(self, ignore_call_args: bool = True):
        super().__init__()
        self._ignore_call_args = ignore_call_args
        # transient per-node constraints established during the walk, keyed by the expression node's ``idx``.
        self._node_effective_bits: dict[int, tuple[int, int]] = {}
        # varid -> {occurrence idx -> (lo_bits, hi_bits)}
        self.vvar_effective_bits: dict[int, dict[int, tuple[int, int]]] = {}
        # varid -> (lo_bits, hi_bits) for vvars that are (possibly narrowed) call arguments
        self.vvar_call_arg_effective_bits: dict[int, tuple[int, int]] = {}
        # varids of vvars that are used as the base expression of an Insert
        self.vvars_used_as_insert_base: set[int] = set()

    def _update_effective_bits(self, expr, lo_bits: int, hi_bits: int):
        key = expr.idx
        existing = self._node_effective_bits.get(key)
        if existing is None:
            self._node_effective_bits[key] = lo_bits, hi_bits
        else:
            self._node_effective_bits[key] = max(existing[0], lo_bits), min(existing[1], hi_bits)

    def _record_vvar_occurrence(self, expr: VirtualVariable) -> None:
        constraint = self._node_effective_bits.get(expr.idx)
        per_idx = self.vvar_effective_bits.get(expr.varid)
        if per_idx is None:
            per_idx = {}
            self.vvar_effective_bits[expr.varid] = per_idx
        existing = per_idx.get(expr.idx)
        if constraint is None:
            if existing is None:
                per_idx[expr.idx] = 0, expr.bits
        elif existing is None:
            per_idx[expr.idx] = constraint
        else:
            per_idx[expr.idx] = max(existing[0], constraint[0]), min(existing[1], constraint[1])

    def _top(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None):
        pass

    def _stmt_top(self, stmt_idx: int, stmt: Statement, block: Block | None):
        pass

    def _handle_block_end(self, stmt_results, block: Block):
        pass

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Any:
        if isinstance(expr, VirtualVariable):
            # we are done!
            self._record_vvar_occurrence(expr)
            return
        super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Insert(self, expr_idx: int, expr, stmt_idx: int, stmt: Statement | None, block: Block | None):
        # the base of an Insert is consumed at full width: every byte outside the inserted range is preserved
        # into the result, so narrowing the base (and zero-extending it back) would destroy those bytes
        self._handle_expr(0, expr.base, stmt_idx, stmt, block)
        if isinstance(expr.base, VirtualVariable):
            self.vvars_used_as_insert_base.add(expr.base.varid)
        self._handle_expr(1, expr.offset, stmt_idx, stmt, block)
        self._handle_expr(2, expr.value, stmt_idx, stmt, block)

    def _handle_Extract(self, expr_idx: int, expr, stmt_idx: int, stmt: Statement | None, block: Block | None):
        if isinstance(expr.offset, Const) and isinstance(expr.offset.value, int):
            # Extract offsets are in bytes
            offset_bits = expr.offset.value * 8
            self._update_effective_bits(expr.base, offset_bits, offset_bits + expr.bits)
        self._handle_expr(0, expr.base, stmt_idx, stmt, block)
        self._handle_expr(1, expr.offset, stmt_idx, stmt, block)

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self._handle_expr(0, expr.addr, stmt_idx, stmt, block)

    def _handle_call_args(self, args, stmt_idx: int, stmt: Statement | None, block: Block | None) -> None:
        for i, arg in enumerate(args):
            handled = False
            if self._ignore_call_args:
                if (
                    isinstance(arg, Convert)
                    and arg.to_bits < arg.from_bits
                    and isinstance(arg.operand, VirtualVariable)
                ):
                    handled = True
                    self.vvar_call_arg_effective_bits[arg.operand.varid] = 0, arg.to_bits
                if isinstance(arg, Extract) and isinstance(arg.offset, Const) and isinstance(arg.base, VirtualVariable):
                    handled = True
                    # Extract offsets are in bytes
                    self.vvar_call_arg_effective_bits[arg.base.varid] = (
                        arg.offset.value * 8,
                        arg.offset.value * 8 + arg.bits,
                    )

            if not handled:
                self._handle_expr(i, arg, stmt_idx, stmt, block)

    def _handle_Call(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement | None, block: Block | None):
        if expr.args is not None:
            self._handle_call_args(expr.args, stmt_idx, stmt, block)

    def _handle_SideEffectStatement(self, stmt_idx: int, stmt: SideEffectStatement, block: Block | None):
        if stmt.expr.args is not None:
            self._handle_call_args(stmt.expr.args, stmt_idx, stmt, block)

        if stmt.ret_expr is not None:
            self._handle_expr(0, stmt.ret_expr, stmt_idx, stmt, block)

    def _handle_BinaryOp(
        self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        effective_bits = self._node_effective_bits.get(expr.idx)
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
        effective_bits = self._node_effective_bits.get(expr.idx)
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
        self,
        project,
        rd,
        manager: Manager,
        narrowables,
        addr2blocks: dict[tuple[int, int | None], Block],
        new_blocks: dict[Block, Block],
    ):
        super().__init__(update_block=False)

        self.project = project
        self._rd = rd
        self.manager = manager
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
                    self.manager.next_atom(),
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
                self.manager.next_atom(),
                new_expr.bits,
                expr.bits,
                False,
                new_expr,
                **new_expr.tags,
            )
        return expr

    def _handle_SideEffectStatement(
        self, stmt_idx: int, stmt: SideEffectStatement, block: Block | None
    ) -> SideEffectStatement:
        new_stmt = super()._handle_SideEffectStatement(stmt_idx, stmt, block)
        assert isinstance(new_stmt, SideEffectStatement)
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
