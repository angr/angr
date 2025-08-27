# pylint:disable=arguments-differ
from __future__ import annotations
import string

from archinfo import Endness

from angr.ailment import BinaryOp
from angr.ailment.expression import Const, StackBaseOffset, VirtualVariable
from angr.ailment.statement import Call, Assignment, Statement, Store

from angr.sim_type import SimTypePointer, SimTypeWideChar
from angr.utils.endness import ail_const_to_be
from .base import PeepholeOptimizationStmtBase


ASCII_PRINTABLES = {ord(x) for x in string.printable}
ASCII_DIGITS = {ord(x) for x in string.digits}


class InlinedWstrcpy(PeepholeOptimizationStmtBase):
    """
    Simplifies inlined wide string copying logic into calls to wstrcpy.
    """

    __slots__ = ()

    NAME = "Simplifying inlined wstrcpy"
    stmt_classes = (Assignment, Store)

    def optimize(self, stmt: Assignment | Store, stmt_idx: int | None = None, block=None, **kwargs):
        if (
            isinstance(stmt, Assignment)
            and isinstance(stmt.dst, VirtualVariable)
            and stmt.dst.was_stack
            and isinstance(stmt.src, Const)
            and isinstance(stmt.src.value, int)
        ):
            dst = StackBaseOffset(None, self.project.arch.bits, stmt.dst.stack_offset)
            value_size = stmt.src.size
            value = stmt.src.value
        elif isinstance(stmt, Store) and isinstance(stmt.data, Const) and isinstance(stmt.data.value, int):
            dst = stmt.addr
            value_size = stmt.data.size
            value = stmt.data.value
        else:
            return None

        r, s = self.is_integer_likely_a_wide_string(value, value_size, self.project.arch.memory_endness)
        if r:
            # replace it with a call to strncpy
            str_id = self.kb.custom_strings.allocate(s)
            wstr_type = SimTypePointer(SimTypeWideChar()).with_arch(self.project.arch)
            return Call(
                stmt.idx,
                "wstrncpy",
                args=[
                    dst,
                    Const(None, None, str_id, self.project.arch.bits, custom_string=True, type=wstr_type),
                    Const(None, None, len(s) // 2, self.project.arch.bits),
                ],
                **stmt.tags,
            )

        # scan forward in the current block to find all consecutive constant stores
        if block is not None and stmt_idx is not None:
            all_constant_stores: dict[int, tuple[int, Const | None]] = self.collect_constant_stores(block, stmt_idx)
            if all_constant_stores:
                offsets = sorted(all_constant_stores.keys())
                next_offset = min(offsets)
                stride = []
                for offset in offsets:
                    if next_offset is not None and offset != next_offset:
                        next_offset = None
                        stride = []
                    stmt_idx_, v = all_constant_stores[offset]
                    if v is not None:
                        stride.append((offset, stmt_idx_, v))
                        next_offset = offset + v.size
                    else:
                        next_offset = None
                        stride = []

                integer, size = self.stride_to_int(stride)
                r, s = self.is_integer_likely_a_wide_string(integer, size, Endness.BE, min_length=3)
                if r:
                    # we remove all involved statements whose statement IDs are greater than the current one
                    for _, stmt_idx_, _ in reversed(stride):
                        if stmt_idx_ <= stmt_idx:
                            continue
                        block.statements[stmt_idx_] = None
                    block.statements = [ss for ss in block.statements if ss is not None]

                    str_id = self.kb.custom_strings.allocate(s)
                    wstr_type = SimTypePointer(SimTypeWideChar()).with_arch(self.project.arch)
                    return Call(
                        stmt.idx,
                        "wstrncpy",
                        args=[
                            dst,
                            Const(None, None, str_id, self.project.arch.bits, custom_string=True, type=wstr_type),
                            Const(None, None, len(s) // 2, self.project.arch.bits),
                        ],
                        **stmt.tags,
                    )

        return None

    @staticmethod
    def stride_to_int(stride: list[tuple[int, int, Const]]) -> tuple[int, int]:
        stride = sorted(stride, key=lambda x: x[0])
        n = 0
        size = 0
        for _, _, v in stride:
            size += v.size
            n <<= v.bits
            n |= v.value
        return n, size

    def collect_constant_stores(self, block, starting_stmt_idx: int) -> dict[int, tuple[int, Const | None]]:
        r = {}
        expected_store_varid: int | None = None
        starting_stmt = block.statements[starting_stmt_idx]
        if (
            isinstance(starting_stmt, Assignment)
            and isinstance(starting_stmt.dst, VirtualVariable)
            and starting_stmt.dst.was_stack
            and isinstance(starting_stmt.dst.stack_offset, int)
        ):
            expected_type = "stack"
        elif isinstance(starting_stmt, Store):
            if isinstance(starting_stmt.addr, VirtualVariable):
                expected_store_varid = starting_stmt.addr.varid
            elif (
                isinstance(starting_stmt.addr, BinaryOp)
                and starting_stmt.addr.op == "Add"
                and isinstance(starting_stmt.addr.operands[0], VirtualVariable)
                and isinstance(starting_stmt.addr.operands[1], Const)
            ):
                expected_store_varid = starting_stmt.addr.operands[0].varid
            else:
                expected_store_varid = None
            expected_type = "store"
        else:
            return r

        for idx, stmt in enumerate(block.statements):
            if idx < starting_stmt_idx:
                continue
            if (
                expected_type == "stack"
                and isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.was_stack
                and isinstance(stmt.dst.stack_offset, int)
            ):
                offset = stmt.dst.stack_offset
                value = (
                    ail_const_to_be(stmt.src, self.project.arch.memory_endness) if isinstance(stmt.src, Const) else None
                )
            elif expected_type == "store" and isinstance(stmt, Store):
                if isinstance(stmt.addr, VirtualVariable) and stmt.addr.varid == expected_store_varid:
                    offset = 0
                elif (
                    isinstance(stmt.addr, BinaryOp)
                    and stmt.addr.op == "Add"
                    and isinstance(stmt.addr.operands[0], VirtualVariable)
                    and isinstance(stmt.addr.operands[1], Const)
                    and stmt.addr.operands[0].varid == expected_store_varid
                ):
                    offset = stmt.addr.operands[1].value
                else:
                    offset = None
                value = (
                    ail_const_to_be(stmt.data, self.project.arch.memory_endness)
                    if isinstance(stmt.data, Const)
                    else None
                )
            else:
                continue

            if offset is not None:
                r[offset] = idx, value

        return r

    @staticmethod
    def even_offsets_are_zero(lst: list[int]) -> bool:
        if len(lst) >= 2 and lst[-1] == 0 and lst[-2] == 0:
            lst = lst[:-2]
        return all((ch == 0 if i % 2 == 0 else ch != 0) for i, ch in enumerate(lst))

    @staticmethod
    def odd_offsets_are_zero(lst: list[int]) -> bool:
        if len(lst) >= 2 and lst[-1] == 0 and lst[-2] == 0:
            lst = lst[:-2]
        return all((ch == 0 if i % 2 == 1 else ch != 0) for i, ch in enumerate(lst))

    @staticmethod
    def is_integer_likely_a_wide_string(
        v: int, size: int, endness: Endness, min_length: int = 4
    ) -> tuple[bool, bytes | None]:
        # we need at least four bytes of printable characters

        chars: list[int] = []
        if endness == Endness.LE:
            while v != 0:
                byt = v & 0xFF
                if byt != 0 and byt not in ASCII_PRINTABLES:
                    return False, None
                chars.append(byt)
                v >>= 8
            if len(chars) % 2 == 1:
                chars.append(0)

        elif endness == Endness.BE:
            for _ in range(size):
                byt = v & 0xFF
                v >>= 8
                if byt != 0 and byt not in ASCII_PRINTABLES:
                    return False, None
                chars.append(byt)
            chars.reverse()
        else:
            # unsupported endness
            return False, None

        if not (InlinedWstrcpy.even_offsets_are_zero(chars) or InlinedWstrcpy.odd_offsets_are_zero(chars)):
            return False, None

        if chars and len(chars) >= 2 and chars[-1] == 0 and chars[-2] == 0:
            chars = chars[:-1]
        if len(chars) >= min_length * 2 and all((ch == 0 or ch in ASCII_PRINTABLES) for ch in chars):
            if len(chars) <= 4 * 2 and all((ch == 0 or ch in ASCII_DIGITS) for ch in chars):
                return False, None
            return True, bytes(chars)
        return False, None

    @staticmethod
    def is_inlined_wstrncpy(stmt: Statement) -> bool:
        return (
            isinstance(stmt, Call)
            and isinstance(stmt.target, str)
            and stmt.target == "wstrncpy"
            and stmt.args is not None
            and len(stmt.args) == 3
            and isinstance(stmt.args[1], Const)
            and hasattr(stmt.args[1], "custom_string")
        )
