# pylint:disable=no-self-use,too-many-boolean-expressions
from __future__ import annotations

import string

from archinfo import Endness

from angr.ailment import BinaryOp
from angr.ailment.expression import (
    Call,
    Const,
    Expression,
    Register,
    StackBaseOffset,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.statement import Assignment, SideEffectStatement, Store
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.sim_type import PointerDisposition, SimTypeFunction, SimTypeLong, SimTypePointer, SimTypeWideChar
from angr.utils.endness import ail_const_to_be

from .inlined_string_utils import InlinedStringCopySimplifierBase
from .optimization_pass import OptimizationPassStage

ASCII_PRINTABLES = {ord(x) for x in string.printable if ord(x) >= 0x20}
ASCII_DIGITS = {ord(x) for x in string.digits}


class InlinedWcscpySimplifier(InlinedStringCopySimplifierBase):
    """
    Simplifies inlined wide string copying logic into calls to wcsncpy, and consolidates multiple consecutive
    inlined wcsncpy calls.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_SSA_LEVEL1_TRANSFORMATION
    NAME = "Simplify inlined wcscpy"
    DESCRIPTION = "Simplify inlined wcscpy patterns and consolidate multiple inlined wcsncpy calls"

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
        # Phase 1: single-statement wcscpy optimizations
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

        # Phase 2: consolidation of consecutive inlined wcsncpy calls
        consolidated_statements = self._consolidate_wcscpy_calls(statements)
        if consolidated_statements is not None:
            statements = consolidated_statements
            changed = True

        if changed:
            return block.copy(statements=statements)
        return None

    def _optimize_single_stmt(self, stmt, stmt_idx, statements):
        if (
            isinstance(stmt, Assignment)
            and isinstance(stmt.dst, VirtualVariable)
            and stmt.dst.was_stack
            and isinstance(stmt.src, Const)
            and isinstance(stmt.src.value, int)
        ):
            dst = self._stack_vvar_ref(stmt.dst, stmt.dst.stack_offset)
            value_size = stmt.src.size
            value = stmt.src.value
        elif isinstance(stmt, Store) and isinstance(stmt.data, Const) and isinstance(stmt.data.value, int):
            dst = stmt.addr
            value_size = stmt.data.size
            value = stmt.data.value
        else:
            return None

        r, s = self.is_integer_likely_a_wide_string(
            value,
            value_size,
            self.project.arch.memory_endness,
            min_length=2,
            char_endness=self.project.arch.memory_endness,
        )
        if r and self._stmts_removable(statements, [stmt_idx]):
            assert s is not None
            return self._make_wcsncpy_call(stmt, dst, s)

        # scan forward to find all consecutive constant stores
        all_constant_stores = self._collect_constant_stores(statements, stmt_idx)
        found = self._find_wide_string_stride(statements, stmt_idx, all_constant_stores)
        if found is not None:
            stride, s = found
            _, first_sidx, _ = stride[0]
            first_stmt = statements[first_sidx]
            for _, sidx, _ in stride:
                if sidx != stmt_idx:
                    statements[sidx] = None
            # the lowest stack variable is now defined by the call
            dst = (
                self._stack_vvar_ref(first_stmt.dst, first_stmt.dst.stack_offset)
                if isinstance(first_stmt, Assignment)
                else first_stmt.addr
            )
            return self._make_wcsncpy_call(stmt, dst, s)

        return None

    def _find_wide_string_stride(self, statements, stmt_idx, all_constant_stores):
        """
        Find the longest valid wide string made of contiguous constant writes that include the write at stmt_idx.
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
            if size % 2 != 0:
                continue
            r, s = self.is_integer_likely_a_wide_string(
                integer, size, Endness.BE, min_length=2, char_endness=self.project.arch.memory_endness
            )
            if r and self._stmts_removable(statements, [sidx for _, sidx, _ in stride]):
                assert s is not None
                return stride, s
        return None

    @staticmethod
    def _wide_string_text(data: bytes) -> bytes:
        """
        The displayed string of copied bytes, without the terminator.
        """
        return data[:-2] if data.endswith(b"\x00\x00") else data

    def _copied_bytes(self, stmt) -> bytes | None:
        """
        All bytes written by an inlined wcscpy or wcsncpy call, including the terminator and padding.
        """
        assert isinstance(stmt, SideEffectStatement) and stmt.expr.args is not None
        str_const = stmt.expr.args[1]
        assert isinstance(str_const, Const)
        text = self.kb.custom_strings[str_const.value_int]
        if len(stmt.expr.args) == 2:
            return text + b"\x00\x00"
        count = stmt.expr.args[2]
        if not isinstance(count, Const) or not count.is_int:
            return None
        size = count.value_int * 2
        if size < len(text):
            return None
        return text + b"\x00" * (size - len(text))

    def _make_wcsncpy_call(self, stmt, dst, s):
        tags = self._tags_with_extra_defs(stmt.tags, dst)
        call = self._make_wide_copy_call(dst, s, tags)
        return SideEffectStatement(self.manager.next_atom(), call, **tags)

    def _make_wide_copy_call(self, dst, data: bytes, tags) -> Call:
        """
        Create a wcscpy or wcsncpy call that writes all bytes in data.
        """
        text = self._wide_string_text(data)
        wstr_type = SimTypePointer(SimTypeWideChar()).with_arch(self.project.arch)
        wstr_type_out = SimTypePointer(SimTypeWideChar(), disposition=PointerDisposition.OUT)
        str_const = Const(self.manager.next_atom(), self.kb.custom_strings.allocate(text), dst.bits, type=wstr_type)
        variable_map_of(self.manager).set_custom_string(str_const)
        if len(data) == len(text) + 2 and all(text[i : i + 2] != b"\x00\x00" for i in range(0, len(text), 2)):
            # exactly one terminator, and no earlier null character
            call = Call(self.manager.next_atom(), "wcscpy", args=[dst, str_const], **tags)
            prototype = SimTypeFunction([wstr_type_out, wstr_type], wstr_type)
        else:
            count = Const(self.manager.next_atom(), len(data) // 2, self.project.arch.bits)
            call = Call(self.manager.next_atom(), "wcsncpy", args=[dst, str_const, count], **tags)
            prototype = SimTypeFunction([wstr_type_out, wstr_type, SimTypeLong(signed=False)], wstr_type)
        variable_map_of(self.manager).set_prototype(call, prototype.with_arch(self.project.arch))
        return call

    def _consolidate_wcscpy_calls(self, statements):
        """Consolidate inlined wcsncpy calls (phase 2).

        Collects all wcsncpy calls, constant stores, and constant stack assignments in the block, groups them by base
        address, and consolidates adjacent entries within each group.
        """
        # Collect all candidate statements with their base/offset. Candidates separated by a statement that may read
        # or clobber memory, or by a write through a different base that may alias, are never merged, so each group
        # only spans one barrier-free segment.
        candidates = []  # list of (stmt_index, base, offset, store_size, stmt)
        segments = {}  # stmt_index -> segment id
        segment = 0
        for i, stmt in enumerate(statements):
            if self._is_inlined_wide_copy(stmt):
                assert isinstance(stmt, SideEffectStatement) and stmt.expr.args is not None
                base, off = self._parse_addr(stmt.expr.args[0])
                copied = self._copied_bytes(stmt)
                if copied is None:
                    return None
                store_size = len(copied)
                if off is not None:
                    candidates.append((i, base, off, store_size, stmt))
            elif isinstance(stmt, Store) and isinstance(stmt.data, Const):
                base, off = self._parse_addr(stmt.addr)
                if off is not None:
                    candidates.append((i, base, off, stmt.size, stmt))
            elif (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.was_stack
                and isinstance(stmt.src, Const)
            ):
                base, off = self._parse_addr(stmt.dst)
                if off is not None:
                    candidates.append((i, base, off, stmt.dst.size, stmt))
            elif not self._is_unrelated_stmt(stmt):
                segment += 1
            if len(candidates) >= 2 and candidates[-1][0] == i and not candidates[-2][1].likes(candidates[-1][1]):
                segment += 1
            segments[i] = segment

        if not candidates:
            return None

        # Must have at least one wcsncpy call
        has_wcsncpy = any(self._is_inlined_wide_copy(s) for _, _, _, _, s in candidates)
        if not has_wcsncpy:
            return None

        # Group candidates by base
        groups: dict[int, list] = {}
        base_map: dict[int, tuple[int, Expression]] = {}
        for entry in candidates:
            idx, base, off, sz, stmt = entry
            # Find matching group
            matched_group = None
            for gid, (gsegment, gbase) in base_map.items():
                if gsegment == segments[idx] and base.likes(gbase):
                    matched_group = gid
                    break
            if matched_group is None:
                matched_group = len(base_map)
                base_map[matched_group] = segments[idx], base
                groups[matched_group] = []
            groups[matched_group].append(entry)

        any_update = False
        stmts_to_remove = set()
        replacements = {}  # stmt_index -> replacement statement

        for group in groups.values():
            if len(group) < 2:
                continue
            # Must have at least one wcsncpy in the group
            if not any(self._is_inlined_wide_copy(s) for _, _, _, _, s in group):
                continue

            # Sort by offset
            group.sort(key=lambda x: x[2])

            # Check for overlaps
            has_overlap = False
            updated_offsets = set()
            for _, _, off, sz, _ in group:
                for j in range(sz):
                    if off + j in updated_offsets:
                        has_overlap = True
                        break
                    updated_offsets.add(off + j)
                if has_overlap:
                    break
            if has_overlap:
                continue

            # Iteratively try to consolidate adjacent pairs
            working = list(group)
            stop = False
            group_changed = False
            while not stop:
                stop = True
                for i in range(len(working) - 1):
                    idx0, _base0, _off0, sz0, stmt0 = working[i]
                    idx1, _base1, _off1, sz1, stmt1 = working[i + 1]
                    if not self._stmts_removable(statements, [idx0, idx1]):
                        continue
                    merged = self._optimize_pair(stmt0, stmt1)
                    if merged is not None and len(merged) == 1:
                        merged_stmt = merged[0]
                        new_base, new_off = self._parse_addr(merged_stmt.expr.args[0])
                        merged_bytes = self._copied_bytes(merged_stmt)
                        new_sz = len(merged_bytes) if merged_bytes is not None else sz0 + sz1
                        new_item = idx0, new_base, new_off, new_sz, merged_stmt
                        working = working[:i] + [new_item] + working[i + 2 :]  # noqa: RUF005
                        stmts_to_remove.add(idx1)
                        replacements[idx0] = merged_stmt
                        group_changed = True
                        stop = False
                        break

            if group_changed:
                any_update = True

        if not any_update:
            return None

        new_stmts = []
        for i, stmt in enumerate(statements):
            if i in stmts_to_remove:
                continue
            if i in replacements:
                new_stmts.append(replacements[i])
            else:
                new_stmts.append(stmt)
        return new_stmts

    def _optimize_pair(self, last_stmt, stmt):
        # convert (store, wcsncpy()) to (wcsncpy(), store) if they do not overlap
        copied = self._copied_bytes(stmt) if self._is_inlined_wide_copy(stmt) else None
        if copied is not None and isinstance(last_stmt, (Store, Assignment)):
            assert isinstance(stmt, SideEffectStatement) and stmt.expr.args is not None
            if isinstance(last_stmt, Store) and isinstance(last_stmt.data, Const):
                store_addr = last_stmt.addr
                store_size = last_stmt.size
            elif isinstance(last_stmt, Assignment):
                store_addr = last_stmt.dst
                store_size = last_stmt.dst.size
            else:
                return None
            wcsncpy_addr = stmt.expr.args[0]
            wcsncpy_size = len(copied)
            delta = self._get_delta(store_addr, wcsncpy_addr)
            if delta is not None:
                if (0 <= delta <= store_size) or (delta < 0 and -delta <= wcsncpy_size):
                    pass  # they overlap, do not switch
                else:
                    last_stmt, stmt = stmt, last_stmt

        # swap two statements if they are out of order
        if self._is_inlined_wide_copy(last_stmt) and self._is_inlined_wide_copy(stmt):
            assert isinstance(last_stmt, SideEffectStatement) and isinstance(stmt, SideEffectStatement)
            assert last_stmt.expr.args is not None and stmt.expr.args is not None
            delta = self._get_delta(last_stmt.expr.args[0], stmt.expr.args[0])
            if delta is not None and delta < 0:
                last_stmt, stmt = stmt, last_stmt

        if self._is_inlined_wide_copy(last_stmt):
            assert isinstance(last_stmt, SideEffectStatement)
            assert last_stmt.expr.args is not None and isinstance(last_stmt.expr.args[1], Const)
            s_last = self._copied_bytes(last_stmt)
            addr_last = last_stmt.expr.args[0]
            new_str = None
            if s_last is None or s_last.endswith(b"\x00\x00"):
                return None

            if self._is_inlined_wide_copy(stmt):
                s_curr = self._copied_bytes(stmt)
                addr_curr = stmt.expr.args[0]
                delta = self._get_delta(addr_last, addr_curr)
                if s_curr is not None and delta is not None and delta == len(s_last):
                    new_str = s_last + s_curr
            elif isinstance(stmt, Store) and isinstance(stmt.data, Const) and isinstance(stmt.data.value, int):
                addr_curr = stmt.addr
                delta = self._get_delta(addr_last, addr_curr)
                if delta is not None and delta == len(s_last):
                    if stmt.size == 2 and stmt.data.value == 0:
                        r, s = True, b"\x00\x00"
                    else:
                        r, s = self.is_integer_likely_a_wide_string(
                            stmt.data.value,
                            stmt.size,
                            stmt.endness,
                            min_length=1,
                            char_endness=self.project.arch.memory_endness,
                        )
                    if r and s is not None:
                        new_str = s_last + s
            elif (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and isinstance(stmt.src, Const)
                and isinstance(stmt.src.value, int)
            ):
                addr_curr = stmt.dst
                delta = self._get_delta(addr_last, addr_curr)
                if delta is not None and delta == len(s_last):
                    r, s = self.is_integer_likely_a_wide_string(
                        stmt.src.value,
                        stmt.dst.size,
                        self.project.arch.memory_endness,
                        min_length=1,
                        char_endness=self.project.arch.memory_endness,
                    )
                    if r and s is not None:
                        new_str = s_last + s

            if new_str is not None:
                dst = last_stmt.expr.args[0]
                tags = self._tags_with_extra_defs(stmt.tags, dst)
                call = self._make_wide_copy_call(dst, new_str, tags)
                return [
                    SideEffectStatement(
                        self.manager.next_atom(),
                        call,
                        **tags,
                    )
                ]

        return None

    def _collect_constant_stores(self, statements, starting_stmt_idx):
        r = {}
        starting_stmt = statements[starting_stmt_idx]
        if (
            isinstance(starting_stmt, Assignment)
            and isinstance(starting_stmt.dst, VirtualVariable)
            and starting_stmt.dst.was_stack
            and isinstance(starting_stmt.dst.stack_offset, int)
        ):
            expected_type = "stack"
            expected_store_varid = None
        elif isinstance(starting_stmt, Store) and isinstance(starting_stmt.addr, StackBaseOffset):
            # stack stores before stack variables are recovered
            expected_type = "stack_store"
            expected_store_varid = None
        elif isinstance(starting_stmt, Store):
            if isinstance(starting_stmt.addr, VirtualVariable):
                expected_store_varid = starting_stmt.addr.varid
            elif (
                isinstance(starting_stmt.addr, BinaryOp)
                and starting_stmt.addr.op == "Add"
                and isinstance(starting_stmt.addr.operands[0], VirtualVariable)
                and isinstance(starting_stmt.addr.operands[1], Const)
                and starting_stmt.addr.operands[1].is_int
            ):
                expected_store_varid = starting_stmt.addr.operands[0].varid
            else:
                expected_store_varid = None
            expected_type = "store"
        else:
            return r

        # stop at the first statement that may read or clobber the buffer, since writes after it cannot be hoisted
        covered = set()
        for idx in range(starting_stmt_idx, len(statements)):
            stmt = statements[idx]
            if stmt is None:
                continue
            if (
                expected_type == "stack"
                and isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.was_stack
                and isinstance(stmt.dst.stack_offset, int)
            ):
                offset = stmt.dst.stack_offset
                size = stmt.dst.size
                value = (
                    ail_const_to_be(stmt.src, self.project.arch.memory_endness)
                    if isinstance(stmt.src, Const) and stmt.src.is_int
                    else None
                )
            elif expected_type in {"store", "stack_store"} and isinstance(stmt, Store):
                if expected_type == "stack_store":
                    if not isinstance(stmt.addr, StackBaseOffset):
                        break
                    offset = stmt.addr.offset
                elif isinstance(stmt.addr, VirtualVariable) and stmt.addr.varid == expected_store_varid:
                    offset = 0
                elif (
                    isinstance(stmt.addr, BinaryOp)
                    and stmt.addr.op == "Add"
                    and isinstance(stmt.addr.operands[0], VirtualVariable)
                    and isinstance(stmt.addr.operands[1], Const)
                    and stmt.addr.operands[1].is_int
                    and stmt.addr.operands[0].varid == expected_store_varid
                ):
                    offset = stmt.addr.operands[1].value_int
                else:
                    break
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
            assert isinstance(v.value, int)
            n <<= v.bits
            n |= v.value
        return n, size

    @staticmethod
    def even_offsets_are_zero(lst):
        if len(lst) >= 2 and lst[-1] == 0 and lst[-2] == 0:
            lst = lst[:-2]
        return all(isinstance(ch, int) and (ch == 0 if i % 2 == 0 else ch != 0) for i, ch in enumerate(lst))

    @staticmethod
    def odd_offsets_are_zero(lst):
        if len(lst) >= 2 and lst[-1] == 0 and lst[-2] == 0:
            lst = lst[:-2]
        return all(isinstance(ch, int) and (ch == 0 if i % 2 == 1 else ch != 0) for i, ch in enumerate(lst))

    @staticmethod
    def is_integer_likely_a_wide_string(v, size, endness, min_length=4, char_endness=None):
        """
        Check if an integer of `size` bytes stored with `endness` holds a wide string. `char_endness` is the byte order
        of each wide character (both orders are accepted if it is None). On success, return all `size` bytes in
        memory order, including any trailing terminator.
        """
        if not isinstance(v, int) or not isinstance(size, int) or size % 2 != 0:
            return False, None

        chars = [(v >> (8 * i)) & 0xFF for i in range(size)]
        if endness == Endness.BE:
            chars.reverse()
        elif endness != Endness.LE:
            return False, None
        if any(byt != 0 and byt not in ASCII_PRINTABLES for byt in chars):
            return False, None

        if char_endness == Endness.LE:
            valid = InlinedWcscpySimplifier.odd_offsets_are_zero(chars)
        elif char_endness == Endness.BE:
            valid = InlinedWcscpySimplifier.even_offsets_are_zero(chars)
        else:
            valid = InlinedWcscpySimplifier.even_offsets_are_zero(
                chars
            ) or InlinedWcscpySimplifier.odd_offsets_are_zero(chars)
        if not valid:
            return False, None

        text = chars[:-2] if chars[-2:] == [0, 0] else chars
        if len(text) >= min_length * 2:
            if len(text) <= 4 * 2 and all((ch == 0 or ch in ASCII_DIGITS) for ch in text):
                return False, None
            return True, bytes(chars)
        return False, None

    def _is_inlined_wide_copy(self, stmt) -> bool:
        return self.is_inlined_wcsncpy(stmt) or self.is_inlined_wcscpy(stmt)

    def is_inlined_wcscpy(self, stmt):
        return (
            isinstance(stmt, SideEffectStatement)
            and isinstance(stmt.expr.target, str)
            and stmt.expr.target == "wcscpy"
            and stmt.expr.args is not None
            and len(stmt.expr.args) == 2
            and isinstance(stmt.expr.args[1], Const)
            and variable_map_of(self.manager).custom_string(stmt.expr.args[1])
        )

    def is_inlined_wcsncpy(self, stmt):
        return (
            isinstance(stmt, SideEffectStatement)
            and isinstance(stmt.expr.target, str)
            and stmt.expr.target == "wcsncpy"
            and stmt.expr.args is not None
            and len(stmt.expr.args) == 3
            and isinstance(stmt.expr.args[1], Const)
            and variable_map_of(self.manager).custom_string(stmt.expr.args[1])
        )

    @staticmethod
    def _parse_addr(addr):
        if isinstance(addr, VirtualVariable) and addr.was_stack:
            return StackBaseOffset(-1, 64, 0), addr.stack_offset
        if isinstance(addr, Register):
            return addr, 0
        if isinstance(addr, StackBaseOffset):
            return StackBaseOffset(-1, 64, 0), addr.offset
        if (
            isinstance(addr, UnaryOp)
            and addr.op == "Reference"
            and isinstance(addr.operand, VirtualVariable)
            and addr.operand.was_stack
        ):
            return StackBaseOffset(-1, 64, 0), addr.operand.stack_offset
        if isinstance(addr, BinaryOp):
            if addr.op == "Add" and isinstance(addr.operands[1], Const) and addr.operands[1].is_int:
                base_0, offset_0 = InlinedWcscpySimplifier._parse_addr(addr.operands[0])
                return base_0, offset_0 + addr.operands[1].value_int
            if addr.op == "Sub" and isinstance(addr.operands[1], Const) and addr.operands[1].is_int:
                base_0, offset_0 = InlinedWcscpySimplifier._parse_addr(addr.operands[0])
                return base_0, offset_0 - addr.operands[1].value_int
        return addr, 0

    @staticmethod
    def _get_delta(addr_0, addr_1):
        base_0, offset_0 = InlinedWcscpySimplifier._parse_addr(addr_0)
        base_1, offset_1 = InlinedWcscpySimplifier._parse_addr(addr_1)
        if base_0.likes(base_1):
            return offset_1 - offset_0
        return None


class InlinedWcscpySimplifierLate(InlinedWcscpySimplifier):
    """
    Same as InlinedWcscpySimplifier but runs after SSA level 1 transformation.
    """

    STAGE = OptimizationPassStage.AFTER_SSA_LEVEL1_TRANSFORMATION
    NAME = "Simplify inlined wcscpy (late)"
