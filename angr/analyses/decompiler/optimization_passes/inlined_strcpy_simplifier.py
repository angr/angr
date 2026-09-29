# pylint:disable=no-self-use,too-many-boolean-expressions
from __future__ import annotations

import string

from archinfo import Endness

from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Insert,
    Register,
    StackBaseOffset,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.statement import Assignment, SideEffectStatement, Store
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.procedures import SIM_LIBRARIES
from angr.utils.endness import ail_const_to_be

from .inlined_string_utils import InlinedStringCopySimplifierBase
from .optimization_pass import OptimizationPassStage

ASCII_PRINTABLES = set(string.printable)
ASCII_DIGITS = set(string.digits)


class InlinedStrcpySimplifier(InlinedStringCopySimplifierBase):
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
                strcpy_dst = self._stack_vvar_ref(stmt.dst, stmt.dst.stack_offset)
            elif self._is_partial_stack_update(stmt):
                assert isinstance(stmt.src, Insert) and isinstance(stmt.src.value, Const)
                assert isinstance(stmt.src.offset, Const)
                inlined_strcpy_candidate = True
                src = stmt.src.value
                strcpy_dst = self._stack_vvar_ref(stmt.dst, stmt.dst.stack_offset + stmt.src.offset.value_int)
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
            if r and self._stmts_removable(statements, [stmt_idx]):
                assert s is not None
                tags = self._tags_with_extra_defs(stmt.tags, strcpy_dst)
                call = self._make_copy_call(strcpy_dst, s, tags)
                return SideEffectStatement(self.manager.next_atom(), call, ret_expr=None, fp_ret_expr=None, **tags)

            # scan forward to find all consecutive constant stores
            all_constant_stores = self._collect_constant_stores(statements, stmt_idx)
            prev_stmt = None if stmt_idx == 0 else statements[stmt_idx - 1]
            # a short string may extend an unterminated copy right before it
            prev_copied = self._copied_bytes(prev_stmt) if self.is_inlined_strcpy(prev_stmt) else None
            min_str_length = 1 if prev_copied is not None and b"\x00" not in prev_copied else 4
            found = self._find_string_stride(statements, stmt_idx, all_constant_stores, min_str_length)
            if found is not None:
                stride, s = found
                # copy into the stack variable at the lowest address of the stride
                first_offset, first_sidx, _ = min(stride, key=lambda x: x[0])
                first_stmt = statements[first_sidx]
                strcpy_dst = (
                    self._stack_vvar_ref(first_stmt.dst, first_offset)
                    if isinstance(first_stmt, Assignment)
                    else first_stmt.addr
                )
                tags = self._tags_with_extra_defs(stmt.tags, strcpy_dst)
                for _, sidx, _ in stride:
                    if sidx != stmt_idx:
                        statements[sidx] = None

                call = self._make_copy_call(strcpy_dst, s, tags)
                return SideEffectStatement(self.manager.next_atom(), call, ret_expr=None, fp_ret_expr=None, **tags)

        return None

    def _find_string_stride(self, statements, stmt_idx, all_constant_stores, min_length):
        """
        Find the longest valid string made of contiguous constant writes that include the write at stmt_idx.
        """
        pieces = sorted((off, sidx, v) for off, (sidx, v) in all_constant_stores.items() if v is not None)
        start = next((i for i, (_, sidx, _) in enumerate(pieces) if sidx == stmt_idx), None)
        if start is None:
            return None
        lo = start
        while lo > 0 and pieces[lo - 1][0] + pieces[lo - 1][2].size == pieces[lo][0]:
            lo -= 1
        hi = start
        while hi + 1 < len(pieces) and pieces[hi][0] + pieces[hi][2].size == pieces[hi + 1][0]:
            hi += 1

        # the write at stmt_idx is replaced, so it must be part of the stride
        for end in range(hi, start - 1, -1):
            stride = pieces[lo : end + 1]
            integer, size = self._stride_to_int(stride)
            r, s = self.is_integer_likely_a_string(integer, size, Endness.BE, min_length=min_length)
            if r and self._stmts_removable(statements, [sidx for _, sidx, _ in stride]):
                assert s is not None
                return stride, s
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

        s_last = self._copied_bytes(last_stmt)
        # nothing is appended after a terminator
        if s_last is None or b"\x00" in s_last:
            return None
        addr_last = last_stmt.expr.args[0]
        new_str = None

        if self.is_inlined_strcpy(stmt):
            s_curr = self._copied_bytes(stmt)
            delta = self._get_delta(addr_last, stmt.expr.args[0])
            if s_curr is not None and delta is not None and delta == len(s_last):
                new_str = s_last + s_curr
        elif isinstance(stmt, Store) and isinstance(stmt.data, Const) and stmt.data.is_int:
            delta = self._get_delta(addr_last, stmt.addr)
            if delta is not None and delta == len(s_last):
                if stmt.data.value_int == 0:
                    r, s = True, b"\x00" * stmt.size
                else:
                    r, s = self.is_integer_likely_a_string(stmt.data.value, stmt.size, stmt.endness, min_length=1)
                if r:
                    assert s is not None
                    new_str = s_last + s

        if new_str is not None:
            tags = self._tags_with_extra_defs(stmt.tags, addr_last)
            call = self._make_copy_call(addr_last, new_str, tags)
            return [SideEffectStatement(self.manager.next_atom(), call, **tags)]

        return None

    @staticmethod
    def _string_text(data: bytes) -> bytes:
        """
        The displayed string of copied bytes, without the terminator and padding.
        """
        return data.split(b"\x00", 1)[0]

    def _copied_bytes(self, stmt) -> bytes | None:
        """
        All bytes written by an inlined strcpy or strncpy call, including the terminator and padding.
        """
        assert isinstance(stmt, SideEffectStatement) and stmt.expr.args is not None
        str_const = stmt.expr.args[1]
        assert isinstance(str_const, Const)
        text = self.kb.custom_strings[str_const.value_int]
        if len(stmt.expr.args) == 2:
            return text + b"\x00"
        count = stmt.expr.args[2]
        if not isinstance(count, Const) or not count.is_int or count.value_int < len(text):
            return None
        return text + b"\x00" * (count.value_int - len(text))

    def _make_copy_call(self, dst, data: bytes, tags) -> Call:
        """
        Create a strcpy or strncpy call that writes all bytes in data.
        """
        text = self._string_text(data)
        str_const = Const(self.manager.next_atom(), self.kb.custom_strings.allocate(text), self.project.arch.bits)
        variable_map_of(self.manager).set_custom_string(str_const)
        if len(data) == len(text) + 1:
            # exactly one terminator
            name, args = "strcpy", [dst, str_const]
        else:
            # strncpy pads the rest of the destination with zeros
            name, args = "strncpy", [dst, str_const, Const(self.manager.next_atom(), len(data), self.project.arch.bits)]
        call = Call(self.manager.next_atom(), name, args=args, bits=None, **tags)
        variable_map_of(self.manager).set_prototype(
            call, SIM_LIBRARIES["libc.so"][0].get_prototype(name, arch=self.project.arch)
        )
        return call

    def _collect_constant_stores(self, statements, starting_stmt_idx):
        # stop at the first statement that may read or clobber the buffer, since writes after it cannot be hoisted
        r = {}
        covered = set()
        for idx in range(starting_stmt_idx, len(statements)):
            stmt = statements[idx]
            if stmt is None:
                continue
            if (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.was_stack
                and isinstance(stmt.dst.stack_offset, int)
            ):
                offset = stmt.dst.stack_offset
                size = stmt.dst.size
                value = None
                if isinstance(stmt.src, Const) and stmt.src.is_int:
                    value = ail_const_to_be(stmt.src, self.project.arch.memory_endness)
                elif self._is_partial_stack_update(stmt):
                    assert isinstance(stmt.src, Insert) and isinstance(stmt.src.value, Const)
                    assert isinstance(stmt.src.offset, Const)
                    offset += stmt.src.offset.value_int
                    size = stmt.src.value.size
                    value = ail_const_to_be(stmt.src.value, self.project.arch.memory_endness)
            elif isinstance(stmt, Store) and isinstance(stmt.addr, StackBaseOffset):
                offset = stmt.addr.offset
                size = stmt.size
                value = (
                    ail_const_to_be(stmt.data, self.project.arch.memory_endness)
                    if isinstance(stmt.data, Const) and stmt.data.is_int
                    else None
                )
            elif self._is_unrelated_stmt(stmt):
                continue
            else:
                break

            written = range(offset, offset + size)
            if any(o in covered for o in written):
                break
            r[offset] = idx, value
            if value is None:
                break
            covered.update(written)
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
        """
        Check if an integer of `size` bytes stored with `endness` holds a string, optionally followed by zero bytes.
        On success, return all `size` bytes in memory order, including the terminator and padding.
        """
        if not isinstance(v, int) or not isinstance(size, int):
            return False, None

        data = [(v >> (8 * i)) & 0xFF for i in range(size)]
        if endness == Endness.BE:
            data.reverse()
        elif endness != Endness.LE:
            return False, None
        text = InlinedStrcpySimplifier._string_text(bytes(data))
        if any(data[len(text) :]) or any(chr(ch) not in ASCII_PRINTABLES for ch in text):
            return False, None

        if len(text) >= min_length:
            if len(text) <= 4 and all(chr(ch) in ASCII_DIGITS for ch in text):
                return False, None
            return True, bytes(data)
        return False, None

    def is_inlined_strcpy(self, stmt):
        return (
            isinstance(stmt, SideEffectStatement)
            and isinstance(stmt.expr.target, str)
            and stmt.expr.args is not None
            and (
                (stmt.expr.target == "strncpy" and len(stmt.expr.args) == 3)
                or (stmt.expr.target == "strcpy" and len(stmt.expr.args) == 2)
            )
            and isinstance(stmt.expr.args[1], Const)
            and variable_map_of(self.manager).custom_string(stmt.expr.args[1])
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
            if addr.op == "Add" and isinstance(addr.operands[1], Const) and addr.operands[1].is_int:
                base_0, offset_0 = InlinedStrcpySimplifier._parse_addr(addr.operands[0])
                return base_0, offset_0 + addr.operands[1].value_int
            if addr.op == "Sub" and isinstance(addr.operands[1], Const) and addr.operands[1].is_int:
                base_0, offset_0 = InlinedStrcpySimplifier._parse_addr(addr.operands[0])
                return base_0, offset_0 - addr.operands[1].value_int
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
