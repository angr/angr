# pylint:disable=arguments-differ
from __future__ import annotations

from angr.ailment.expression import Expression, BinaryOp, Const, Register, StackBaseOffset, UnaryOp, VirtualVariable
from angr.ailment.statement import Call, Store

from angr.sim_type import SimTypePointer, SimTypeWideChar
from .base import PeepholeOptimizationMultiStmtBase
from .inlined_wstrcpy import InlinedWstrcpy


class InlinedWstrcpyConsolidation(PeepholeOptimizationMultiStmtBase):
    """
    Consolidate multiple inlined wstrcpy/wstrncpy calls.
    """

    __slots__ = ()

    NAME = "Consolidate multiple inlined wstrncpy calls"
    stmt_classes = ((Call, Call), (Call, Store))

    def optimize(  # type:ignore
        self, stmts: list[Call], stmt_idx: int | None = None, block=None, **kwargs
    ):  # pylint:disable=unused-argument
        last_stmt, stmt = stmts
        if InlinedWstrcpy.is_inlined_wstrncpy(last_stmt):
            assert last_stmt.args is not None
            assert self.kb is not None
            s_last: bytes = self.kb.custom_strings[last_stmt.args[1].value]
            addr_last = last_stmt.args[0]
            new_str = None  # will be set if consolidation should happen

            if isinstance(stmt, Call) and InlinedWstrcpy.is_inlined_wstrncpy(stmt):
                assert stmt.args is not None
                # consolidating two calls
                s_curr: bytes = self.kb.custom_strings[stmt.args[1].value]
                addr_curr = stmt.args[0]
                # determine if the two addresses are consecutive
                delta = self._get_delta(addr_last, addr_curr)
                if delta is not None and delta == len(s_last):
                    # consolidate both calls!
                    new_str = s_last + s_curr
            elif isinstance(stmt, Store) and isinstance(stmt.data, Const) and isinstance(stmt.data.value, int):
                # consolidating a call and a store, in case the store statement is storing the suffix of a string (but
                # the suffix is too short to qualify an inlined strcpy optimization)
                addr_curr = stmt.addr
                delta = self._get_delta(addr_last, addr_curr)
                if delta is not None and delta == len(s_last):
                    if stmt.size == 2 and stmt.data.value == 0:
                        # it's probably the terminating null byte
                        r, s = True, b"\x00\x00"
                    else:
                        r, s = InlinedWstrcpy.is_integer_likely_a_wide_string(
                            stmt.data.value, stmt.size, stmt.endness, min_length=1  # type:ignore
                        )
                    if r and s is not None:
                        new_str = s_last + s

            if new_str is not None:
                assert self.project is not None
                wstr_type = SimTypePointer(SimTypeWideChar()).with_arch(self.project.arch)
                if new_str.endswith(b"\x00\x00"):
                    call_name = "wstrcpy"
                    new_str_idx = self.kb.custom_strings.allocate(new_str[:-2])
                    args = [
                        last_stmt.args[0],
                        Const(None, None, new_str_idx, last_stmt.args[0].bits, custom_string=True, type=wstr_type),
                    ]
                    prototype = None
                else:
                    call_name = "wstrncpy"
                    new_str_idx = self.kb.custom_strings.allocate(new_str)
                    args = [
                        last_stmt.args[0],
                        Const(None, None, new_str_idx, last_stmt.args[0].bits, custom_string=True, type=wstr_type),
                        Const(None, None, len(new_str) // 2, self.project.arch.bits),
                    ]
                    prototype = None

                return [Call(stmt.idx, call_name, args=args, prototype=prototype, **stmt.tags)]

        return None

    @staticmethod
    def _parse_addr(addr: Expression) -> tuple[Expression, int]:
        if isinstance(addr, Register):
            return addr, 0
        if isinstance(addr, StackBaseOffset):
            return StackBaseOffset(None, addr.bits, 0), addr.offset
        if (
            isinstance(addr, UnaryOp)
            and addr.op == "Reference"
            and isinstance(addr.operand, VirtualVariable)
            and addr.operand.was_stack
        ):
            return StackBaseOffset(None, addr.bits, 0), addr.operand.stack_offset
        if isinstance(addr, BinaryOp):
            if addr.op == "Add" and isinstance(addr.operands[1], Const) and isinstance(addr.operands[1].value, int):
                base_0, offset_0 = InlinedWstrcpyConsolidation._parse_addr(addr.operands[0])
                return base_0, offset_0 + addr.operands[1].value
            if addr.op == "Sub" and isinstance(addr.operands[1], Const) and isinstance(addr.operands[1].value, int):
                base_0, offset_0 = InlinedWstrcpyConsolidation._parse_addr(addr.operands[0])
                return base_0, offset_0 - addr.operands[1].value

        return addr, 0

    @staticmethod
    def _get_delta(addr_0: Expression, addr_1: Expression) -> int | None:
        base_0, offset_0 = InlinedWstrcpyConsolidation._parse_addr(addr_0)
        base_1, offset_1 = InlinedWstrcpyConsolidation._parse_addr(addr_1)
        if base_0.likes(base_1):
            return offset_1 - offset_0
        return None
