# pylint:disable=arguments-differ
import string

from archinfo import Endness

from ailment.expression import Const, StackBaseOffset
from ailment.statement import Call, Store

from angr.utils.endness import ail_const_to_be
from .base import PeepholeOptimizationStmtBase


ASCII_PRINTABLES = set(string.printable)
ASCII_DIGITS = set(string.digits)


class InlinedWstrcpy(PeepholeOptimizationStmtBase):
    """
    Simplifies inlined wide string copying logic into calls to wstrcpy.
    """

    __slots__ = ()

    NAME = "Simplifying inlined wstrcpy"
    stmt_classes = (Store,)

    def optimize(self, stmt: Store, stmt_idx: int = None, block=None, **kwargs):
        if isinstance(stmt.data, Const) and isinstance(stmt.data.value, int):
            r, s = self.is_integer_likely_a_wide_string(stmt.data.value, stmt.data.size, stmt.endness)
            if r:
                # replace it with a call to strncpy
                str_id = self.kb.custom_strings.allocate(s.encode("ascii"))
                return Call(
                    stmt.idx,
                    "wstrncpy",
                    args=[
                        stmt.addr,
                        Const(None, None, str_id, stmt.addr.bits, custom_string=True),
                        Const(None, None, len(s), self.project.arch.bits),
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
                    r, s = self.is_integer_likely_a_wide_string(integer, size, Endness.BE)
                    if r:
                        # we remove all involved statements whose statement IDs are greater than the current one
                        for _, stmt_idx_, _ in reversed(stride):
                            if stmt_idx_ <= stmt_idx:
                                continue
                            block.statements[stmt_idx_] = None
                        block.statements = [ss for ss in block.statements if ss is not None]

                        str_id = self.kb.custom_strings.allocate(s.encode("ascii"))
                        return Call(
                            stmt.idx,
                            "wstrncpy",
                            args=[
                                stmt.addr,
                                Const(None, None, str_id, stmt.addr.bits, custom_string=True),
                                Const(None, None, len(s), self.project.arch.bits),
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

    @staticmethod
    def collect_constant_stores(block, starting_stmt_idx: int) -> dict[int, tuple[int, Const | None]]:
        r = {}
        for idx, stmt in enumerate(block.statements):
            if idx < starting_stmt_idx:
                continue
            if isinstance(stmt, Store) and isinstance(stmt.addr, StackBaseOffset) and isinstance(stmt.addr.offset, int):
                if isinstance(stmt.data, Const):
                    r[stmt.addr.offset] = idx, ail_const_to_be(stmt.data, stmt.endness)
                else:
                    r[stmt.addr.offset] = idx, None

        return r

    @staticmethod
    def even_offsets_are_zero(lst: list[str]) -> bool:
        return all(ch == "\x00" for i, ch in enumerate(lst) if i % 2 == 0)

    @staticmethod
    def odd_offsets_are_zero(lst: list[str]) -> bool:
        return all(ch == "\x00" for i, ch in enumerate(lst) if i % 2 == 1)

    @staticmethod
    def is_integer_likely_a_wide_string(
        v: int, size: int, endness: Endness, min_length: int = 4
    ) -> tuple[bool, str | None]:
        # we need at least four bytes of printable characters

        chars = []
        if endness == Endness.LE:
            while v != 0:
                byt = v & 0xFF
                if byt != 0 and chr(byt) not in ASCII_PRINTABLES:
                    return False, None
                chars.append(chr(byt))
                v >>= 8

        elif endness == Endness.BE:
            for _ in range(size):
                byt = v & 0xFF
                v >>= 8
                if byt != 0 and chr(byt) not in ASCII_PRINTABLES:
                    return False, None
                chars.append(chr(byt))
            chars = chars[::-1]
        else:
            # unsupported endness
            return False, None

        if InlinedWstrcpy.even_offsets_are_zero(chars):
            chars = [ch for i, ch in enumerate(chars) if i % 2 == 1]
        elif InlinedWstrcpy.odd_offsets_are_zero(chars):
            chars = [ch for i, ch in enumerate(chars) if i % 2 == 0]
        else:
            return False, None

        if chars and chars[-1] == "\x00":
            chars = chars[:-1]
        if len(chars) >= min_length and all(ch in ASCII_PRINTABLES for ch in chars):
            if len(chars) <= 4 and all(ch in ASCII_DIGITS for ch in chars):
                return False, None
            return True, "".join(chars)
        return False, None
