# pylint:disable=arguments-differ
from __future__ import annotations
from typing import Literal, Any
from collections import defaultdict

from angr.ailment.expression import Const, StackBaseOffset, VirtualVariable, BinaryOp
from angr.ailment.statement import Call, Assignment, Store, Statement
from angr.ailment.utils import is_none_or_likeable
from angr import SIM_LIBRARIES
from .base import PeepholeOptimizationStmtBase


class ConstAssignmentInfo:
    """
    Holds information about a constant assignment.
    """

    __slots__ = ("base", "bits", "count", "kind", "offset", "value")

    def __init__(
        self, kind: Literal["stack", "heap", "global"], base: Any, offset: int, value: int, bits: int, count: int = 1
    ):
        self.kind: Literal["stack", "heap", "global"] = kind
        self.base = base
        self.offset = offset
        self.value = value
        self.bits = bits
        self.count = count

    def __repr__(self):
        base_str = str(self.base) if self.base is not None else ""
        offset_str = f"+{self.offset}" if self.offset >= 0 else f"{self.offset}"
        return (
            f"ConstAssignmentInfo({self.kind}@{base_str}{offset_str}, {self.value}|{self.bits}bits, count={self.count})"
        )


class InlinedMemset(PeepholeOptimizationStmtBase):
    """
    Simplifies inlined memory setting logic into calls to memset
    """

    MIN_ASSIGNMENTS = 2

    __slots__ = ()

    NAME = "Simplifying inlined memset"
    stmt_classes = (Assignment, Store)

    def optimize(self, stmt: Assignment | Store, stmt_idx: int | None = None, block=None, **kwargs):
        d = self._parse_const_assignment(stmt)
        if d is None:
            return None

        assert block is not None and self.project is not None

        stmt_idx = -1 if stmt_idx is None else stmt_idx
        info: list[tuple[int, ConstAssignmentInfo]] = [(stmt_idx, d)]
        # search forward for constant stores
        i = stmt_idx + 1
        while i < len(block.statements):
            d = self._parse_const_assignment(block.statements[i])
            if d is None:
                break
            info.append((i, d))
            i += 1

        # analyze the collected info
        info_by_kind = defaultdict(list)
        for idx, d in info:
            info_by_kind[d.kind].append((idx, d))

        result = None
        optimized = False
        for _kind, lst in info_by_kind.items():
            if len(lst) <= 1:
                continue
            candidates = self._find_memset_candidates(lst)
            for start_stmt_idx, end_stmt_idx, candidate in candidates:
                if end_stmt_idx - start_stmt_idx <= self.MIN_ASSIGNMENTS:
                    continue

                for i in range(start_stmt_idx, end_stmt_idx):
                    block.statements[i] = None  # remove these statements
                # create a new memset call
                base_expr = None

                match candidate.kind:
                    case "stack":
                        base_expr = StackBaseOffset(None, self.project.arch.bits, candidate.offset)
                    case "global":
                        base_expr = Const(None, None, candidate.offset, self.project.arch.bits)
                    case "heap":
                        base_expr = BinaryOp(
                            None,
                            "Add",
                            [
                                candidate.base,
                                Const(None, None, candidate.offset, self.project.arch.bits),
                            ],
                            False,
                            bits=self.project.arch.bits,
                        )

                if base_expr is None:
                    continue

                assert self.project is not None
                call_stmt = Call(
                    stmt.idx,
                    "memset",
                    args=[
                        base_expr,
                        Const(None, None, candidate.value, 8),
                        Const(None, None, candidate.count, self.project.arch.bits),
                    ],
                    prototype=SIM_LIBRARIES["libc.so"][0].get_prototype("memcpy"),
                    **stmt.tags,
                )
                if start_stmt_idx == stmt_idx:
                    result = call_stmt
                block.statements[start_stmt_idx] = call_stmt
                optimized = True

        if optimized:
            # some optimization has been made
            block.statements = [ss for ss in block.statements if ss is not None]

        return result

    @staticmethod
    def _parse_const_assignment(
        stmt: Statement,
    ) -> ConstAssignmentInfo | None:
        """
        Parse a constant assignment statement to see if it matches the pattern of a memset.

        :param stmt: The statement to parse.
        :return: A tuple of ("stack" | "heap" | "global", base, offset, value, bits) if it matches the pattern, else
                 None.
        """
        if isinstance(stmt, Assignment) and isinstance(stmt.src, Const) and stmt.src.is_int:
            dst = stmt.dst
            if isinstance(dst, VirtualVariable) and dst.was_stack:
                return ConstAssignmentInfo("stack", None, dst.stack_offset, stmt.src.value_int, stmt.src.bits)
        elif isinstance(stmt, Store) and isinstance(stmt.data, Const) and stmt.data.is_int:
            if isinstance(stmt.addr, StackBaseOffset):
                return ConstAssignmentInfo("stack", None, stmt.addr.offset, stmt.data.value_int, stmt.data.bits)
            if isinstance(stmt.addr, Const):
                return ConstAssignmentInfo("global", stmt.addr.value_int, 0, stmt.data.value_int, stmt.data.bits)
            if isinstance(stmt.addr, BinaryOp) and stmt.addr.op in {"Add", "Sub"}:
                base = stmt.addr.operands[0]
                offset_expr = stmt.addr.operands[1]
                if isinstance(offset_expr, Const):
                    offset = offset_expr.value_int if stmt.addr.op == "Add" else -offset_expr.value_int
                    return ConstAssignmentInfo("heap", base, offset, stmt.data.value_int, stmt.data.bits)
            else:
                base = stmt.addr
                return ConstAssignmentInfo("heap", base, 0, stmt.data.value_int, stmt.data.bits)
        return None

    @staticmethod
    def _find_memset_candidates(
        info_lst: list[tuple[int, ConstAssignmentInfo]],
    ) -> list[tuple[int, int, ConstAssignmentInfo]]:
        """
        Analyze a list of ConstAssignmentInfo to find candidates for memset.

        :param info_lst: The list of ConstAssignmentInfo.
        :return: A tuple of (base, start_offset, store_size, value) if they are candidates, else None.
        """
        if len(info_lst) < 2:
            return []

        candidates = []

        info_lst = sorted(info_lst, key=lambda x: x[0])
        start = 0
        while start < len(info_lst) - 1:
            # assignments must be in consecutive statements
            j = start
            while j < len(info_lst):
                if j - start != info_lst[j][0] - info_lst[start][0]:
                    break
                j += 1

            if j - start < 2:
                start += 1
                continue
            end = j

            # assignments from start to j - 1 must cover a continuous memory region
            base = info_lst[start][1].base
            regions = {}
            byte_values = set()
            has_same_base = True

            for j in range(start, end):
                ith_base = info_lst[j][1].base

                if not is_none_or_likeable(ith_base, base):
                    has_same_base = False
                    break
                regions[info_lst[j][1].offset] = info_lst[j][1].bits
                byte_values |= InlinedMemset._int_to_bytes(info_lst[j][1].value, info_lst[j][1].bits)

            if not has_same_base:
                end = j
                if end - start < 2:
                    start += 1
                    continue

            # must have the same byte value
            if len(byte_values) != 1:
                start += 1
                continue

            # last check: are regions continuous?
            next_region_offset = None
            start_region_offset = min(regions)
            has_gap = False
            for region_offset in sorted(regions):
                region_bits = regions[region_offset]
                if next_region_offset is not None and region_offset != next_region_offset:
                    has_gap = True
                    break
                next_region_offset = region_offset + region_bits // 8

            if next_region_offset is None or has_gap:
                start += 1
                continue

            candidate = ConstAssignmentInfo(
                info_lst[start][1].kind,
                base,
                start_region_offset,
                next(iter(byte_values)),
                8,
                next_region_offset - start_region_offset,
            )
            candidates.append(
                (info_lst[start][0], info_lst[end][0] if end < len(info_lst) else info_lst[end - 1][0] + 1, candidate)
            )
            start = end

        return candidates

    @staticmethod
    def _int_to_bytes(value: int, bits: int) -> set[int]:
        """
        Convert an integer value to a set of byte values.

        :param value: The integer value.
        :param bits: The number of bits in the integer.
        :return: A set of byte values.
        """
        byte_values = set()
        num_bytes = bits // 8
        for i in range(num_bytes):
            byte = (value >> (i * 8)) & 0xFF
            byte_values.add(byte)
        return byte_values
