# pylint:disable=arguments-differ
from __future__ import annotations

from ailment.expression import Expression, BinaryOp, Const, Register, StackBaseOffset
from ailment.statement import Call, Store

from .base import PeepholeOptimizationMultiStmtBase
from .inlined_strcpy import InlinedStrcpy


class InlinedStrcpyConsolidation(PeepholeOptimizationMultiStmtBase):
    """
    Consolidate multiple inlined strcpy calls.
    """

    __slots__ = ()

    NAME = "Consolidate multiple inlined strcpy calls"
    stmt_classes = ((Call, Call), (Call, Store))

    def optimize(self, stmts: list[Call], **kwargs):
        last_stmt, stmt = stmts
        if InlinedStrcpyConsolidation._is_inlined_strcpy(last_stmt):
            s_last: bytes = self.kb.custom_strings[last_stmt.args[1].value]
            addr_last = last_stmt.args[0]
            new_str = None  # will be set if consolidation should happen

            if isinstance(stmt, Call) and InlinedStrcpyConsolidation._is_inlined_strcpy(stmt):
                # consolidating two calls
                s_curr: bytes = self.kb.custom_strings[stmt.args[1].value]
                addr_curr = stmt.args[0]
                # determine if the two addresses are consecutive
                delta = self._get_delta(addr_last, addr_curr)
                if delta is not None and delta == len(s_last):
                    # consolidate both calls!
                    new_str = s_last + s_curr
            elif isinstance(stmt, Store) and isinstance(stmt.data, Const):
                # consolidating a call and a store, in case the store statement is storing the suffix of a string (but
                # the suffix is too short to qualify an inlined strcpy optimization)
                addr_curr = stmt.addr
                delta = self._get_delta(addr_last, addr_curr)
                if delta is not None and delta == len(s_last):
                    if stmt.size == 1 and stmt.data.value == 0:
                        # it's probably the terminating null byte
                        r, s = True, "\x00"
                    else:
                        r, s = InlinedStrcpy.is_integer_likely_a_string(
                            stmt.data.value, stmt.size, stmt.endness, min_length=1
                        )
                    if r:
                        new_str = s_last + s.encode("ascii")

            if new_str is not None:
                if new_str.endswith(b"\x00"):
                    call_name = "strcpy"
                    new_str_idx = self.kb.custom_strings.allocate(new_str[:-1])
                    args = [
                        last_stmt.args[0],
                        Const(None, None, new_str_idx, last_stmt.args[0].bits, custom_string=True),
                    ]
                else:
                    call_name = "strncpy"
                    new_str_idx = self.kb.custom_strings.allocate(new_str)
                    args = [
                        last_stmt.args[0],
                        Const(None, None, new_str_idx, last_stmt.args[0].bits, custom_string=True),
                        Const(None, None, len(new_str), self.project.arch.bits),
                    ]

                return [Call(stmt.idx, call_name, args=args, **stmt.tags)]

        return None

    @staticmethod
    def _is_inlined_strcpy(stmt: Call):
        return (
            isinstance(stmt.target, str)
            and stmt.target == "strncpy"
            and len(stmt.args) == 3
            and isinstance(stmt.args[1], Const)
            and hasattr(stmt.args[1], "custom_string")
        )

    @staticmethod
    def _parse_addr(addr: Expression) -> tuple[Expression, int]:
        if isinstance(addr, Register):
            return addr, 0
        if isinstance(addr, StackBaseOffset):
            return StackBaseOffset(None, addr.bits, 0), addr.offset
        if isinstance(addr, BinaryOp):
            if addr.op == "Add" and isinstance(addr.operands[1], Const):
                base_0, offset_0 = InlinedStrcpyConsolidation._parse_addr(addr.operands[0])
                return base_0, offset_0 + addr.operands[1].value
            if addr.op == "Sub" and isinstance(addr.operands[1], Const):
                base_0, offset_0 = InlinedStrcpyConsolidation._parse_addr(addr.operands[0])
                return base_0, offset_0 - addr.operands[1].value

        return addr, 0

    @staticmethod
    def _get_delta(addr_0: Expression, addr_1: Expression) -> int | None:
        base_0, offset_0 = InlinedStrcpyConsolidation._parse_addr(addr_0)
        base_1, offset_1 = InlinedStrcpyConsolidation._parse_addr(addr_1)
        if base_0.likes(base_1):
            return offset_1 - offset_0
        return None
