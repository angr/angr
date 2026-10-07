# pylint:disable=no-self-use,abstract-method
from __future__ import annotations

import struct
from collections import defaultdict

from angr.ailment import AILBlockViewer
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    DirtyExpression,
    Expression,
    Insert,
    Load,
    MultiStatementExpression,
    Register,
    StackBaseOffset,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.statement import Assignment, Statement, Store
from angr.ailment.tagged_object import TagDict
from angr.utils.ssa import phi_assignment_get_src

from .optimization_pass import OptimizationPass


class MemoryAccessFinder(AILBlockViewer):
    """
    Determines if a statement may read memory, reference the stack, or have side effects.
    """

    def __init__(self):
        super().__init__()
        self.found = False

    def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):
        if self.found:
            return None
        if isinstance(expr, (Load, Call, DirtyExpression, MultiStatementExpression, StackBaseOffset)) or (
            isinstance(expr, VirtualVariable) and expr.was_stack
        ):
            self.found = True
            return None
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


class VVarValueUseCounter(AILBlockViewer):
    """
    Counts value uses of virtual variables. Taking the address of a virtual variable is not a value use.
    """

    def __init__(self):
        super().__init__()
        self.counts: defaultdict[int, int] = defaultdict(int)

    def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.tags.get("extra_def", False):
            return None
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Assignment(self, stmt_idx, stmt, block):
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)

    def _handle_UnaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.op == "Reference" and isinstance(expr.operand, VirtualVariable):
            return None
        return super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        self.counts[expr.varid] += 1


class InlinedStringCopySimplifierBase(OptimizationPass):
    """
    Helpers shared by the passes that fold constant writes into inlined string copy calls.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._vvar_value_uses: dict[int, int] | None = None

    @staticmethod
    def _int_const_views(statements) -> tuple[list, dict[int, tuple[Statement, Statement]]]:
        """
        Replace float-valued constant writes with writes of their bit patterns (an 8-byte movsd copies string bytes as
        well). Returns the new statements and id(view) -> (view, original) for restoring untouched writes.
        """
        views = []
        originals: dict[int, tuple[Statement, Statement]] = {}
        for stmt in statements:
            view = stmt
            if isinstance(stmt, Store) and isinstance(stmt.data, Const) and stmt.data.bits in {32, 64}:
                bits = InlinedStringCopySimplifierBase._float_const_bits(stmt.data)
                if bits is not None:
                    view = Store(stmt.idx, stmt.addr, bits, stmt.size, stmt.endness, guard=stmt.guard, **stmt.tags)
            elif isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and isinstance(stmt.src, Const):
                bits = InlinedStringCopySimplifierBase._float_const_bits(stmt.src)
                if bits is not None:
                    view = Assignment(stmt.idx, stmt.dst, bits, **stmt.tags)
            if view is not stmt:
                originals[id(view)] = view, stmt
            views.append(view)
        return views, originals

    @staticmethod
    def _restore_float_consts(statements, originals: dict[int, tuple[Statement, Statement]]) -> list:
        restored = []
        for stmt in statements:
            entry = originals.get(id(stmt))
            restored.append(entry[1] if entry is not None and entry[0] is stmt else stmt)
        return restored

    @staticmethod
    def _float_const_bits(c: Const) -> Const | None:
        if not isinstance(c.value, float) or c.bits not in {32, 64}:
            return None
        int_fmt, float_fmt = ("<I", "<f") if c.bits == 32 else ("<Q", "<d")
        (value,) = struct.unpack(int_fmt, struct.pack(float_fmt, c.value))
        return Const(c.idx, value, c.bits, **c.tags)

    def _stmts_removable(self, statements, stmt_indices) -> bool:
        """
        Statements are removable if the vvars they define are not used anywhere else.
        """
        defined = [
            statements[i].dst.varid
            for i in stmt_indices
            if isinstance(statements[i], Assignment) and isinstance(statements[i].dst, VirtualVariable)
        ]
        if not defined:
            return True
        local_counter = VVarValueUseCounter()
        for i in stmt_indices:
            local_counter.walk_statement(statements[i])
        all_uses = self._value_use_counts()
        return all(all_uses.get(varid, 0) == local_counter.counts.get(varid, 0) for varid in defined)

    def _value_use_counts(self) -> dict[int, int]:
        if self._vvar_value_uses is None:
            counter = VVarValueUseCounter()
            phi_srcs: dict[int, list[int]] = {}
            for block in self._graph:
                for stmt in block.statements:
                    phi = phi_assignment_get_src(stmt)
                    if phi is not None:
                        assert isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable)
                        phi_srcs[stmt.dst.varid] = [vvar.varid for _, vvar in phi.src_and_vvars if vvar is not None]
                    else:
                        counter.walk_statement(stmt, block=block)
            counts = counter.counts
            worklist = [varid for varid in phi_srcs if counts[varid] > 0]
            live = set(worklist)
            while worklist:
                for src_varid in phi_srcs.get(worklist.pop(), []):
                    counts[src_varid] += 1
                    if src_varid in phi_srcs and src_varid not in live:
                        live.add(src_varid)
                        worklist.append(src_varid)
            self._vvar_value_uses = dict(counts)
        return self._vvar_value_uses

    def _is_partial_stack_update(self, stmt: Assignment) -> bool:
        """
        Checks if the statement only writes a constant into part of a stack variable and does not touch
        the other bytes of the stack variable.
        """
        src = stmt.src
        dst = stmt.dst
        return (
            isinstance(src, Insert)
            and isinstance(dst, VirtualVariable)
            and dst.was_stack
            and src.endness == self.project.arch.memory_endness
            and isinstance(src.offset, Const)
            and src.offset.is_int
            and isinstance(src.value, Const)
            and src.value.is_int
            and src.offset.value_int >= 0
            and src.offset.value_int + src.value.size <= dst.size
            and (
                (
                    isinstance(src.base, VirtualVariable)
                    and src.base.was_stack
                    and src.base.stack_offset == dst.stack_offset
                    and src.base.size == dst.size
                )
                or (isinstance(src.base, Const) and src.base.tags.get("uninitialized", False))
            )
        )

    @staticmethod
    def _is_unrelated_stmt(stmt) -> bool:
        """
        Returns True if a statement does not read or write memory.
        """
        if not (isinstance(stmt, Assignment) and isinstance(stmt.dst, (VirtualVariable, Register))):
            return False
        if isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_stack:
            return False
        finder = MemoryAccessFinder()
        finder.walk_expression(stmt.src)
        return not finder.found

    def _stack_vvar_ref(self, vvar: VirtualVariable, offset: int) -> Expression:
        bits = self.project.arch.bits
        ref = UnaryOp(self.manager.next_atom(), "Reference", vvar, bits=bits, extra_def=True)
        if offset == vvar.stack_offset:
            return ref
        delta = Const(self.manager.next_atom(), offset - vvar.stack_offset, bits)
        return BinaryOp(self.manager.next_atom(), "Add", [ref, delta], bits=bits)

    @staticmethod
    def _extra_def_vvar(dst: Expression) -> VirtualVariable | None:
        """
        The stack variable that a string copy to `dst` defines, if any.
        """
        if isinstance(dst, BinaryOp) and dst.op == "Add" and isinstance(dst.operands[1], Const):
            dst = dst.operands[0]
        if dst.tags.get("extra_def", False):
            assert isinstance(dst, UnaryOp) and dst.op == "Reference"
            assert isinstance(dst.operand, VirtualVariable)
            return dst.operand
        return None

    def _tags_with_extra_defs(self, tags, dst: Expression) -> TagDict:
        tags = TagDict(tags)
        vvar = self._extra_def_vvar(dst)
        if vvar is not None:
            tags["extra_defs"] = [vvar.varid]
        else:
            tags.pop("extra_defs", None)
        return tags
