# pylint:disable=arguments-differ
from __future__ import annotations
from typing import TYPE_CHECKING

from angr.ailment.expression import Expression, BinaryOp, Const, Register, StackBaseOffset, UnaryOp, VirtualVariable
from angr.ailment.statement import Call, Store, Assignment

from angr.sim_type import SimTypePointer, SimTypeWideChar
from .base import PeepholeOptimizationMultiStmtBase
from .inlined_wcscpy import InlinedWcscpy

if TYPE_CHECKING:
    from angr.ailment.statement import Statement


def match_statements(stmts: list[Statement], index: int) -> int:
    ending = index
    has_wcsncpy = False
    for i in range(index, len(stmts)):
        stmt = stmts[i]
        if isinstance(stmt, Call):
            if InlinedWcscpy.is_inlined_wcsncpy(stmt):
                has_wcsncpy = True
            else:
                break
        elif isinstance(stmt, Store):
            if not isinstance(stmt.data, Const):
                break
            _, off = InlinedWcscpyConsolidation._parse_addr(stmt.addr)
            if off is None:
                # unsupported offset - bail
                break
        elif (
            isinstance(stmt, Assignment)
            and isinstance(stmt.dst, VirtualVariable)
            and stmt.dst.was_stack
            and isinstance(stmt.src, Const)
        ):
            pass
        else:
            break
        ending = i + 1
    return ending - index if has_wcsncpy and ending - index >= 2 else 0


class InlinedWcscpyConsolidation(PeepholeOptimizationMultiStmtBase):
    """
    Consolidate multiple inlined wcscpy/wcsncpy calls.
    """

    __slots__ = ()

    NAME = "Consolidate multiple inlined wcsncpy calls"
    stmt_classes = (match_statements,)

    def optimize(  # type:ignore
        self, stmts: list[Call | Store | Assignment], stmt_idx: int | None = None, block=None, **kwargs
    ):  # pylint:disable=unused-argument
        reordered_stmts = self._reorder_stmts(stmts)
        if not reordered_stmts or len(reordered_stmts) <= 1:
            return None

        new_stmts = []
        optimized = False
        stop = False
        while not stop:
            new_stmts = []
            stop = True
            for i, stmt0 in enumerate(reordered_stmts):
                if i == len(reordered_stmts) - 1:
                    new_stmts.append(reordered_stmts[i])
                    break
                stmt1 = reordered_stmts[i + 1]
                opt_stmts = self._optimize_pair(stmt0, stmt1)
                if opt_stmts is None:
                    new_stmts.append(stmt0)
                else:
                    new_stmts += opt_stmts
                    # start again from the beginning
                    optimized = True
                    stop = False
                    reordered_stmts = new_stmts + reordered_stmts[i + 2 :]
                    break

        return new_stmts if optimized and new_stmts else None

    def _reorder_stmts(self, stmts: list[Call | Store | Assignment]) -> list[Call | Store] | None:
        """
        Order a list of statements based on ascending addresses of their destination buffers.
        """

        if not all(
            (
                InlinedWcscpy.is_inlined_wcsncpy(s)
                or (isinstance(s, Store) and isinstance(s.data, Const))
                or (
                    isinstance(s, Assignment)
                    and isinstance(s.dst, VirtualVariable)
                    and s.dst.was_stack
                    and isinstance(s.src, Const)
                )
            )
            for s in stmts
        ):
            return None
        offset_to_stmt = {}
        updated_offsets: set[int] = set()
        known_base = None
        for stmt in stmts:
            if isinstance(stmt, Call):
                assert (
                    stmt.args is not None
                    and len(stmt.args) == 3
                    and stmt.args[0] is not None
                    and stmt.args[2] is not None
                )
                base, off = self._parse_addr(stmt.args[0])
                store_size = stmt.args[2].value * 2 if isinstance(stmt.args[2], Const) else None
            elif isinstance(stmt, Store):
                base, off = self._parse_addr(stmt.addr)
                store_size = stmt.size
            elif isinstance(stmt, Assignment):
                base, off = self._parse_addr(stmt.dst)
                store_size = stmt.dst.size
            else:
                # unexpected!
                return None
            if off is None or store_size is None:
                # bad offset or size - bail
                return None
            if known_base is None:
                known_base = base
            elif not base.likes(known_base):
                # bail
                return None
            if off in offset_to_stmt:
                # duplicate offset - bail
                return None
            assert isinstance(store_size, int)
            for i in range(store_size):
                if off + i in updated_offsets:
                    # overlapping store - bail
                    return None
                updated_offsets.add(off + i)

            offset_to_stmt[off] = stmt

        return [offset_to_stmt[k] for k in sorted(offset_to_stmt)]

    def _optimize_pair(
        self, last_stmt: Call | Store | Assignment, stmt: Call | Store | Assignment
    ) -> list[Call] | None:
        # convert (store, wcsncpy()) to (wcsncpy(), store) if they do not overlap
        if (
            isinstance(stmt, Call)
            and InlinedWcscpy.is_inlined_wcsncpy(stmt)
            and stmt.args is not None
            and len(stmt.args) == 3
            and isinstance(stmt.args[2], Const)
            and isinstance(stmt.args[2].value, int)
            and isinstance(last_stmt, (Store, Assignment))
        ):
            if isinstance(last_stmt, Store) and isinstance(last_stmt.data, Const):
                store_addr = last_stmt.addr
                store_size = last_stmt.size
            elif isinstance(last_stmt, Assignment):
                store_addr = last_stmt.dst
                store_size = last_stmt.dst.size
            else:
                return None
            # check if they overlap
            wcsncpy_addr = stmt.args[0]
            wcsncpy_size = stmt.args[2].value * 2
            delta = self._get_delta(store_addr, wcsncpy_addr)
            if delta is not None:
                if (0 <= delta <= store_size) or (delta < 0 and -delta <= wcsncpy_size):
                    # they overlap, do not switch
                    pass
                else:
                    last_stmt, stmt = stmt, last_stmt

        # swap two statements if they are out of order
        if InlinedWcscpy.is_inlined_wcsncpy(last_stmt) and InlinedWcscpy.is_inlined_wcsncpy(stmt):
            assert last_stmt.args is not None and stmt.args is not None
            delta = self._get_delta(last_stmt.args[0], stmt.args[0])
            if delta is not None and delta < 0:
                last_stmt, stmt = stmt, last_stmt

        if InlinedWcscpy.is_inlined_wcsncpy(last_stmt):
            assert last_stmt.args is not None
            assert self.kb is not None
            s_last: bytes = self.kb.custom_strings[last_stmt.args[1].value]
            addr_last = last_stmt.args[0]
            new_str = None  # will be set if consolidation should happen

            if isinstance(stmt, Call) and InlinedWcscpy.is_inlined_wcsncpy(stmt):
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
                        r, s = InlinedWcscpy.is_integer_likely_a_wide_string(
                            stmt.data.value, stmt.size, stmt.endness, min_length=1  # type:ignore
                        )
                    if r and s is not None:
                        new_str = s_last + s
            elif (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and isinstance(stmt.src, Const)
                and isinstance(stmt.src.value, int)
            ):
                # consolidating a call and an assignment, in case the assignment statement is storing the suffix of a
                # string (but the suffix is too short to qualify an inlined strcpy optimization)
                addr_curr = stmt.dst
                delta = self._get_delta(addr_last, addr_curr)
                if delta is not None and delta == len(s_last):
                    r, s = InlinedWcscpy.is_integer_likely_a_wide_string(
                        stmt.src.value, stmt.dst.size, self.project.arch.memory_endness, min_length=1  # type:ignore
                    )
                    if r and s is not None:
                        new_str = s_last + s

            if new_str is not None:
                assert self.project is not None
                wstr_type = SimTypePointer(SimTypeWideChar()).with_arch(self.project.arch)
                if new_str.endswith(b"\x00\x00"):
                    call_name = "wcsncpy"
                    new_str_idx = self.kb.custom_strings.allocate(new_str[:-2])
                    args = [
                        last_stmt.args[0],
                        Const(None, None, new_str_idx, last_stmt.args[0].bits, custom_string=True, type=wstr_type),
                    ]
                    prototype = None
                else:
                    call_name = "wcsncpy"
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
        # we force the base to 64-bit because it does not really matter when we use it

        if isinstance(addr, VirtualVariable) and addr.was_stack:
            return StackBaseOffset(None, 64, 0), addr.stack_offset
        if isinstance(addr, Register):
            return addr, 0
        if isinstance(addr, StackBaseOffset):
            return StackBaseOffset(None, 64, 0), addr.offset
        if (
            isinstance(addr, UnaryOp)
            and addr.op == "Reference"
            and isinstance(addr.operand, VirtualVariable)
            and addr.operand.was_stack
        ):
            return StackBaseOffset(None, 64, 0), addr.operand.stack_offset
        if isinstance(addr, BinaryOp):
            if addr.op == "Add" and isinstance(addr.operands[1], Const) and isinstance(addr.operands[1].value, int):
                base_0, offset_0 = InlinedWcscpyConsolidation._parse_addr(addr.operands[0])
                return base_0, offset_0 + addr.operands[1].value
            if addr.op == "Sub" and isinstance(addr.operands[1], Const) and isinstance(addr.operands[1].value, int):
                base_0, offset_0 = InlinedWcscpyConsolidation._parse_addr(addr.operands[0])
                return base_0, offset_0 - addr.operands[1].value

        return addr, 0

    @staticmethod
    def _get_delta(addr_0: Expression, addr_1: Expression) -> int | None:
        base_0, offset_0 = InlinedWcscpyConsolidation._parse_addr(addr_0)
        base_1, offset_1 = InlinedWcscpyConsolidation._parse_addr(addr_1)
        if base_0.likes(base_1):
            return offset_1 - offset_0
        return None
