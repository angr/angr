# pylint:disable=arguments-differ,too-many-boolean-expressions
from __future__ import annotations
import string

from archinfo import Endness

from angr.ailment.expression import Const, StackBaseOffset, VirtualVariable, UnaryOp
from angr.ailment.statement import Call, Assignment, Store, Statement

from angr import SIM_LIBRARIES
from angr.utils.endness import ail_const_to_be
from .base import PeepholeOptimizationStmtBase


ASCII_PRINTABLES = set(string.printable)
ASCII_DIGITS = set(string.digits)


class InlinedStrcpy(PeepholeOptimizationStmtBase):
    """
    Simplifies inlined string copying logic into calls to strcpy.
    """

    __slots__ = ()

    NAME = "Simplifying inlined strcpy"
    stmt_classes = (Assignment, Store)

    def optimize(self, stmt: Assignment | Store, stmt_idx: int | None = None, block=None, **kwargs):
        inlined_strcpy_candidate = False
        src: Const | None = None
        strcpy_dst: StackBaseOffset | UnaryOp | None = None

        assert self.project is not None

        if (
            isinstance(stmt, Assignment)
            and isinstance(stmt.dst, VirtualVariable)
            and stmt.dst.was_stack
            and isinstance(stmt.src, Const)
            and isinstance(stmt.src.value, int)
        ):
            inlined_strcpy_candidate = True
            src = stmt.src
            strcpy_dst = StackBaseOffset(None, self.project.arch.bits, stmt.dst.stack_offset)
        elif (
            isinstance(stmt, Store)
            and isinstance(stmt.addr, UnaryOp)
            and stmt.addr.op == "Reference"
            and isinstance(stmt.addr.operand, VirtualVariable)
            and stmt.addr.operand.was_stack
            and isinstance(stmt.data, Const)
            and isinstance(stmt.data.value, int)
        ):
            inlined_strcpy_candidate = True
            src = stmt.data
            strcpy_dst = stmt.addr

        if inlined_strcpy_candidate:
            assert src is not None and strcpy_dst is not None
            assert isinstance(src.value, int)
            assert self.kb is not None

            r, s = self.is_integer_likely_a_string(src.value, src.size, self.project.arch.memory_endness)
            if r:
                assert s is not None

                # replace it with a call to strncpy
                str_id = self.kb.custom_strings.allocate(s.encode("ascii"))
                return Call(
                    stmt.idx,
                    "strncpy",
                    args=[
                        strcpy_dst,
                        Const(None, None, str_id, self.project.arch.bits, custom_string=True),
                        Const(None, None, len(s), self.project.arch.bits),
                    ],
                    prototype=SIM_LIBRARIES["libc.so"][0].get_prototype("strncpy"),
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

                    if not stride:
                        return None
                    min_stride_stmt_idx = min(stmt_idx_ for _, stmt_idx_, _ in stride)
                    if min_stride_stmt_idx > stmt_idx:
                        # the current statement is not involved in the stride. we can't simplify here, otherwise we
                        # will incorrectly remove the current statement
                        return None

                    integer, size = self.stride_to_int(stride)
                    prev_stmt = None if stmt_idx == 0 else block.statements[stmt_idx - 1]
                    min_str_length = 1 if prev_stmt is not None and self.is_inlined_strcpy(prev_stmt) else 4
                    r, s = self.is_integer_likely_a_string(integer, size, Endness.BE, min_length=min_str_length)
                    if r:
                        assert s is not None

                        # we remove all involved statements whose statement IDs are greater than the current one
                        for _, stmt_idx_, _ in reversed(stride):
                            if stmt_idx_ <= stmt_idx:
                                continue
                            block.statements[stmt_idx_] = None
                        block.statements = [ss for ss in block.statements if ss is not None]

                        str_id = self.kb.custom_strings.allocate(s.encode("ascii"))
                        return Call(
                            stmt.idx,
                            "strncpy",
                            args=[
                                strcpy_dst,
                                Const(None, None, str_id, self.project.arch.bits, custom_string=True),
                                Const(None, None, len(s), self.project.arch.bits),
                            ],
                            prototype=SIM_LIBRARIES["libc.so"][0].get_prototype("strncpy"),
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
            assert isinstance(v.value, int)
            n |= v.value
        return n, size

    def collect_constant_stores(self, block, starting_stmt_idx: int) -> dict[int, tuple[int, Const | None]]:
        assert self.project is not None

        r = {}
        for idx, stmt in enumerate(block.statements):
            if idx < starting_stmt_idx:
                continue
            if (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.was_stack
                and isinstance(stmt.dst.stack_offset, int)
            ):
                if isinstance(stmt.src, Const):
                    r[stmt.dst.stack_offset] = idx, ail_const_to_be(stmt.src, self.project.arch.memory_endness)
                else:
                    r[stmt.dst.stack_offset] = idx, None

        return r

    @staticmethod
    def is_integer_likely_a_string(v: int, size: int, endness: Endness, min_length: int = 4) -> tuple[bool, str | None]:
        # we need at least four bytes of printable characters

        chars = []
        if endness == Endness.LE:
            while v != 0:
                byt = v & 0xFF
                if chr(byt) not in ASCII_PRINTABLES:
                    return False, None
                chars.append(chr(byt))
                v >>= 8

        elif endness == Endness.BE:
            first_non_zero = False
            for _ in range(size):
                byt = v & 0xFF
                v >>= 8
                if byt == 0:
                    if first_non_zero:
                        return False, None
                    continue
                first_non_zero = True  # this is the first non-zero byte
                if chr(byt) not in ASCII_PRINTABLES:
                    return False, None
                chars.append(chr(byt))
            chars.reverse()
        else:
            # unsupported endness
            return False, None

        if len(chars) >= min_length:
            if len(chars) <= 4 and all(ch in ASCII_DIGITS for ch in chars):
                return False, None
            return True, "".join(chars)
        return False, None

    @staticmethod
    def is_inlined_strcpy(stmt: Statement) -> bool:
        return (
            isinstance(stmt, Call)
            and isinstance(stmt.target, str)
            and stmt.target == "strncpy"
            and stmt.args is not None
            and len(stmt.args) == 3
            and isinstance(stmt.args[1], Const)
            and hasattr(stmt.args[1], "custom_string")
        )
