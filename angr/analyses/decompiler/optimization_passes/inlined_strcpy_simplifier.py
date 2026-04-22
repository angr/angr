# pylint:disable=no-self-use,too-many-boolean-expressions
from __future__ import annotations
import string

from archinfo import Endness

from angr.ailment.expression import (
    Call,
    Const,
    BinaryOp,
    Register,
    StackBaseOffset,
    VirtualVariable,
    UnaryOp,
    Insert,
)
from angr.ailment.statement import Assignment, Store, SideEffectStatement
from angr.ailment.tagged_object import TagDict

from angr import SIM_LIBRARIES
from angr.utils.endness import ail_const_to_be
from .optimization_pass import OptimizationPass, OptimizationPassStage

ASCII_PRINTABLES = set(string.printable)
ASCII_DIGITS = set(string.digits)


class InlinedStrcpySimplifier(OptimizationPass):
    """
    Simplifies inlined string copying logic into calls to strcpy/strncpy, and consolidates multiple consecutive
    inlined strcpy calls.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_SSA_LEVEL1_TRANSFORMATION
    NAME = "Simplify inlined strcpy"
    DESCRIPTION = "Simplify inlined strcpy patterns and consolidate multiple inlined strcpy calls"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        for block in list(self._graph.nodes()):
            new_block = self._process_block(block)
            if new_block is not None:
                self._update_block(block, new_block)

    def _process_block(self, block):
        # Phase 1: single-statement strcpy optimizations
        statements = block.statements
        changed = False
        new_statements = []
        stmt_idx = 0
        while stmt_idx < len(statements):
            stmt = statements[stmt_idx]
            replacement = self._optimize_single_stmt(stmt, stmt_idx, statements)
            if replacement is not None:
                new_statements.append(replacement)
                changed = True
            else:
                new_statements.append(stmt)
            stmt_idx += 1
        # filter out None statements (removed by collect logic)
        new_statements = [s for s in new_statements if s is not None]

        if changed:
            statements = new_statements

        # Phase 2: consolidation of consecutive inlined strcpy calls
        consolidated_statements = self._consolidate_strcpy_calls(statements)
        if consolidated_statements is not None:
            statements = consolidated_statements
            changed = True

        if changed:
            return block.copy(statements=statements)
        return None

    def _optimize_single_stmt(self, stmt, stmt_idx, statements):
        inlined_strcpy_candidate = False
        src = None
        strcpy_dst = None

        if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_stack:
            if isinstance(stmt.src, Const) and isinstance(stmt.src.value, int):
                inlined_strcpy_candidate = True
                src = stmt.src
                strcpy_dst = StackBaseOffset(self.manager.next_atom(), self.project.arch.bits, stmt.dst.stack_offset)
            elif (
                isinstance(stmt.src, Insert)
                and isinstance(stmt.src.base, (Const, VirtualVariable))
                and isinstance(stmt.src.value, Const)
                and isinstance(stmt.src.offset, Const)
            ):
                inlined_strcpy_candidate = True
                src = stmt.src.value
                strcpy_dst = StackBaseOffset(
                    self.manager.next_atom(), self.project.arch.bits, stmt.dst.stack_offset + stmt.src.offset.value_int
                )
        elif (
            isinstance(stmt, Store)
            and isinstance(stmt.addr, UnaryOp)
            and stmt.addr.op == "Reference"
            and isinstance(stmt.addr.operand, VirtualVariable)
            and stmt.addr.operand.was_stack
            and isinstance(stmt.data, Const)
            and isinstance(stmt.data.value, int)
        ) or (
            isinstance(stmt, Store)
            and isinstance(stmt.addr, StackBaseOffset)
            and isinstance(stmt.data, Const)
            and isinstance(stmt.data.value, int)
        ):
            inlined_strcpy_candidate = True
            src = stmt.data
            strcpy_dst = stmt.addr

        if inlined_strcpy_candidate:
            assert src is not None and strcpy_dst is not None
            assert isinstance(src.value, int)

            r, s = self.is_integer_likely_a_string(src.value, src.size, self.project.arch.memory_endness)
            if r:
                assert s is not None
                str_id = self.kb.custom_strings.allocate(s.encode("ascii"))
                return SideEffectStatement(
                    stmt.idx,
                    Call(
                        stmt.idx,
                        "strncpy",
                        calling_convention=None,
                        args=[
                            strcpy_dst,
                            Const(None, None, str_id, self.project.arch.bits, custom_string=True),
                            Const(None, None, len(s), self.project.arch.bits),
                        ],
                        prototype=SIM_LIBRARIES["libc.so"][0].get_prototype("strncpy", arch=self.project.arch),
                        bits=None,
                        **stmt.tags,
                    ),
                    ret_expr=None,
                    fp_ret_expr=None,
                    **stmt.tags,
                )

            # scan forward to find all consecutive constant stores
            all_constant_stores = self._collect_constant_stores(statements, stmt_idx)
            if all_constant_stores:
                offsets = sorted(all_constant_stores.keys())
                next_offset = min(offsets)
                stride = []
                for offset in offsets:
                    if next_offset is not None and offset != next_offset:
                        next_offset = None
                        stride = []
                    sidx, v = all_constant_stores[offset]
                    if v is not None:
                        stride.append((offset, sidx, v))
                        next_offset = offset + v.size
                    else:
                        next_offset = None
                        stride = []

                if not stride:
                    return None
                min_stride_stmt_idx = min(sidx for _, sidx, _ in stride)
                if min_stride_stmt_idx > stmt_idx:
                    return None

                integer, size = self._stride_to_int(stride)
                prev_stmt = None if stmt_idx == 0 else statements[stmt_idx - 1]
                min_str_length = 1 if prev_stmt is not None and self.is_inlined_strcpy(prev_stmt) else 4
                r, s = self.is_integer_likely_a_string(integer, size, Endness.BE, min_length=min_str_length)
                if r:
                    assert s is not None
                    # remove all involved statements whose indices are greater than the current one
                    for _, sidx, _ in reversed(stride):
                        if sidx <= stmt_idx:
                            continue
                        statements[sidx] = None

                    str_id = self.kb.custom_strings.allocate(s.encode("ascii"))
                    return SideEffectStatement(
                        stmt.idx,
                        Call(
                            stmt.idx,
                            "strncpy",
                            calling_convention=None,
                            args=[
                                strcpy_dst,
                                Const(None, None, str_id, self.project.arch.bits, custom_string=True),
                                Const(None, None, len(s), self.project.arch.bits),
                            ],
                            prototype=SIM_LIBRARIES["libc.so"][0].get_prototype("strncpy", arch=self.project.arch),
                            bits=None,
                            **stmt.tags,
                        ),
                        ret_expr=None,
                        fp_ret_expr=None,
                        **stmt.tags,
                    )

        return None

    def _consolidate_strcpy_calls(self, statements):
        """Consolidate consecutive inlined strcpy calls (phase 2)."""
        any_update = False
        stmts = list(statements)

        stmt_idx = 0
        while stmt_idx < len(stmts) - 1:
            last_stmt = stmts[stmt_idx]
            stmt = stmts[stmt_idx + 1]

            result = self._consolidate_pair(last_stmt, stmt)
            if result is not None:
                stmts = stmts[:stmt_idx] + result + stmts[stmt_idx + 2 :]
                any_update = True
                # don't advance - try consolidating again from the same position
            else:
                stmt_idx += 1

        return stmts if any_update else None

    def _consolidate_pair(self, last_stmt, stmt):
        if not self.is_inlined_strcpy(last_stmt):
            return None

        s_last = self.kb.custom_strings[last_stmt.expr.args[1].value]
        addr_last = last_stmt.expr.args[0]
        new_str = None

        if isinstance(stmt, SideEffectStatement) and self.is_inlined_strcpy(stmt):
            assert stmt.expr.args is not None and isinstance(stmt.expr.args[1], Const)
            s_curr = self.kb.custom_strings[stmt.expr.args[1].value_int]
            addr_curr = stmt.expr.args[0]
            delta = self._get_delta(addr_last, addr_curr)
            if delta is not None and delta == len(s_last):
                new_str = s_last + s_curr
        elif isinstance(stmt, Store) and isinstance(stmt.data, Const):
            addr_curr = stmt.addr
            delta = self._get_delta(addr_last, addr_curr)
            if delta is not None and delta == len(s_last):
                if stmt.size == 1 and stmt.data.value == 0:
                    r, s = True, "\x00"
                else:
                    r, s = self.is_integer_likely_a_string(stmt.data.value, stmt.size, stmt.endness, min_length=1)
                if r:
                    assert s is not None
                    new_str = s_last + s.encode("ascii")

        if new_str is not None:
            if new_str.endswith(b"\x00"):
                call_name = "strcpy"
                new_str_idx = self.kb.custom_strings.allocate(new_str[:-1])
                args = [
                    last_stmt.expr.args[0],
                    Const(None, None, new_str_idx, last_stmt.expr.args[0].bits, custom_string=True),
                ]
                prototype = SIM_LIBRARIES["libc.so"][0].get_prototype("strcpy")
            else:
                call_name = "strncpy"
                new_str_idx = self.kb.custom_strings.allocate(new_str)
                args = [
                    last_stmt.expr.args[0],
                    Const(None, None, new_str_idx, last_stmt.expr.args[0].bits, custom_string=True),
                    Const(None, None, len(new_str), self.project.arch.bits),
                ]
                prototype = SIM_LIBRARIES["libc.so"][0].get_prototype("strncpy")

            tags = TagDict(stmt.tags)
            if args[0].tags.get("extra_def", False):
                assert isinstance(args[0], UnaryOp)
                assert args[0].op == "Reference"
                assert isinstance(args[0].operand, VirtualVariable)
                tags["extra_defs"] = [args[0].operand.varid]
            else:
                tags.pop("extra_defs", None)

            return [
                SideEffectStatement(stmt.idx, Call(stmt.idx, call_name, args=args, prototype=prototype, **tags), **tags)
            ]

        return None

    def _collect_constant_stores(self, statements, starting_stmt_idx):
        r = {}
        for idx, stmt in enumerate(statements):
            if idx < starting_stmt_idx:
                continue
            if stmt is None:
                continue
            if (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.was_stack
                and isinstance(stmt.dst.stack_offset, int)
            ):
                if isinstance(stmt.src, Const):
                    r[stmt.dst.stack_offset] = idx, ail_const_to_be(stmt.src, self.project.arch.memory_endness)
                if (
                    isinstance(stmt.src, Insert)
                    and (
                        isinstance(stmt.src.base, Const)
                        or (
                            isinstance(stmt.src.base, VirtualVariable)
                            and stmt.src.base.was_stack
                            and stmt.src.base.stack_offset == stmt.dst.stack_offset
                        )
                    )
                    and isinstance(stmt.src.offset, Const)
                    and isinstance(stmt.src.value, Const)
                ):
                    r[stmt.dst.stack_offset + stmt.src.offset.value] = (
                        idx,
                        ail_const_to_be(stmt.src.value, self.project.arch.memory_endness),
                    )
                else:
                    r[stmt.dst.stack_offset] = idx, None
            elif isinstance(stmt, Store) and isinstance(stmt.addr, StackBaseOffset):
                if isinstance(stmt.data, Const):
                    r[stmt.addr.offset] = idx, ail_const_to_be(stmt.data, self.project.arch.memory_endness)
                else:
                    r[stmt.addr.offset] = idx, None
        return r

    @staticmethod
    def _stride_to_int(stride):
        stride = sorted(stride, key=lambda x: x[0])
        n = 0
        size = 0
        for _, _, v in stride:
            size += v.size
            n <<= v.bits
            assert isinstance(v.value, int)
            n |= v.value
        return n, size

    @staticmethod
    def is_integer_likely_a_string(v, size, endness, min_length=4):
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
                first_non_zero = True
                if chr(byt) not in ASCII_PRINTABLES:
                    return False, None
                chars.append(chr(byt))
            chars.reverse()
        else:
            return False, None

        if len(chars) >= min_length:
            if len(chars) <= 4 and all(ch in ASCII_DIGITS for ch in chars):
                return False, None
            return True, "".join(chars)
        return False, None

    @staticmethod
    def is_inlined_strcpy(stmt):
        return (
            isinstance(stmt, SideEffectStatement)
            and isinstance(stmt.expr.target, str)
            and stmt.expr.target == "strncpy"
            and stmt.expr.args is not None
            and len(stmt.expr.args) == 3
            and isinstance(stmt.expr.args[1], Const)
            and "custom_string" in stmt.expr.args[1].tags
        )

    @staticmethod
    def _parse_addr(addr):
        if isinstance(addr, Register):
            return addr, 0
        if isinstance(addr, StackBaseOffset):
            return StackBaseOffset(-1, addr.bits, 0), addr.offset
        if (
            isinstance(addr, UnaryOp)
            and addr.op == "Reference"
            and isinstance(addr.operand, VirtualVariable)
            and addr.operand.was_stack
        ):
            return StackBaseOffset(-1, addr.bits, 0), addr.operand.stack_offset
        if isinstance(addr, BinaryOp):
            if addr.op == "Add" and isinstance(addr.operands[1], Const):
                base_0, offset_0 = InlinedStrcpySimplifier._parse_addr(addr.operands[0])
                return base_0, offset_0 + addr.operands[1].value
            if addr.op == "Sub" and isinstance(addr.operands[1], Const):
                base_0, offset_0 = InlinedStrcpySimplifier._parse_addr(addr.operands[0])
                return base_0, offset_0 - addr.operands[1].value
        return addr, 0

    @staticmethod
    def _get_delta(addr_0, addr_1):
        base_0, offset_0 = InlinedStrcpySimplifier._parse_addr(addr_0)
        base_1, offset_1 = InlinedStrcpySimplifier._parse_addr(addr_1)
        if base_0.likes(base_1):
            return offset_1 - offset_0
        return None


class InlinedStrcpySimplifierLate(InlinedStrcpySimplifier):
    """
    Same as InlinedStrcpySimplifier but runs after SSA level 1 transformation.
    """

    STAGE = OptimizationPassStage.AFTER_SSA_LEVEL1_TRANSFORMATION
    NAME = "Simplify inlined strcpy (late)"
