# pylint:disable=no-self-use
from __future__ import annotations
from typing import Literal, Any
from collections import defaultdict

from angr.ailment.expression import Call, Const, StackBaseOffset, VirtualVariable, BinaryOp
from angr.ailment.statement import Assignment, Store, Statement, SideEffectStatement
from angr.ailment.utils import is_none_or_likeable
from angr import SIM_LIBRARIES
from .optimization_pass import OptimizationPass, OptimizationPassStage


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


class InlinedMemsetSimplifier(OptimizationPass):
    """
    Simplifies inlined memory setting logic into calls to memset.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_SSA_LEVEL1_TRANSFORMATION
    NAME = "Simplify inlined memset"
    DESCRIPTION = "Simplify inlined memset patterns into memset calls"

    MIN_ASSIGNMENTS = 2

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        for block in list(self._graph.nodes()):
            new_block = self._optimize_block(block)
            if new_block is not None:
                self._update_block(block, new_block)

    def _optimize_block(self, block):
        statements = block.statements
        if not statements:
            return None

        new_statements = []
        changed = False
        i = 0

        while i < len(statements):
            stmt = statements[i]
            d = self._parse_const_assignment(stmt)
            if d is None:
                new_statements.append(stmt)
                i += 1
                continue

            # collect consecutive constant assignments starting at i
            info: list[tuple[int, ConstAssignmentInfo]] = [(i, d)]
            j = i + 1
            while j < len(statements):
                d2 = self._parse_const_assignment(statements[j])
                if d2 is None:
                    break
                info.append((j, d2))
                j += 1

            if len(info) < 2:
                new_statements.append(stmt)
                i += 1
                continue

            # group by kind and find memset candidates
            info_by_kind: dict[str, list[tuple[int, ConstAssignmentInfo]]] = defaultdict(list)
            for idx, d in info:
                info_by_kind[d.kind].append((idx, d))

            replaced_indices: set[int] = set()
            replacements: dict[int, SideEffectStatement] = {}

            for _kind, lst in info_by_kind.items():
                if len(lst) <= 1:
                    continue
                candidates = self._find_memset_candidates(lst)
                for start_stmt_idx, end_stmt_idx, candidate in candidates:
                    if end_stmt_idx - start_stmt_idx <= self.MIN_ASSIGNMENTS:
                        continue

                    base_expr = None
                    match candidate.kind:
                        case "stack":
                            # Creating memsets on the stack is a recipe to screw up variable identification.
                            base_expr = None
                        case "global":
                            base_expr = Const(self.manager.next_atom(), None, candidate.offset, self.project.arch.bits)
                        case "heap":
                            base_expr = BinaryOp(
                                self.manager.next_atom(),
                                "Add",
                                [
                                    candidate.base,
                                    Const(self.manager.next_atom(), None, candidate.offset, self.project.arch.bits),
                                ],
                                False,
                                bits=self.project.arch.bits,
                            )

                    if base_expr is None:
                        continue

                    # mark statements for replacement
                    for k in range(start_stmt_idx, end_stmt_idx):
                        replaced_indices.add(k)

                    ref_stmt = statements[start_stmt_idx]
                    call_stmt = SideEffectStatement(
                        ref_stmt.idx,
                        Call(
                            ref_stmt.idx,
                            "memset",
                            args=[
                                base_expr,
                                Const(self.manager.next_atom(), None, candidate.value, 8),
                                Const(self.manager.next_atom(), None, candidate.count, self.project.arch.bits),
                            ],
                            prototype=SIM_LIBRARIES["libc.so"][0].get_prototype("memset", arch=self.project.arch),
                            **ref_stmt.tags,
                        ),
                        **ref_stmt.tags,
                    )
                    replacements[start_stmt_idx] = call_stmt
                    changed = True

            # emit statements for this range
            for k in range(i, j):
                if k in replacements:
                    new_statements.append(replacements[k])
                elif k not in replaced_indices:
                    new_statements.append(statements[k])

            i = j

        if changed:
            return block.copy(statements=new_statements)
        return None

    @staticmethod
    def _parse_const_assignment(stmt: Statement) -> ConstAssignmentInfo | None:
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
            byte_values: set[int] = set()
            has_same_base = True

            for j in range(start, end):
                ith_base = info_lst[j][1].base

                if not is_none_or_likeable(ith_base, base):
                    has_same_base = False
                    break
                regions[info_lst[j][1].offset] = info_lst[j][1].bits
                byte_values |= InlinedMemsetSimplifier._int_to_bytes(info_lst[j][1].value, info_lst[j][1].bits)

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
        byte_values: set[int] = set()
        num_bytes = bits // 8
        for i in range(num_bytes):
            byte = (value >> (i * 8)) & 0xFF
            byte_values.add(byte)
        return byte_values


class InlinedMemsetSimplifierLate(InlinedMemsetSimplifier):
    """
    Same as InlinedMemsetSimplifier but runs after SSA level 1 transformation.
    """

    STAGE = OptimizationPassStage.AFTER_SSA_LEVEL1_TRANSFORMATION
    NAME = "Simplify inlined memset (late)"
