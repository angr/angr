# pylint:disable=no-self-use,too-many-boolean-expressions
from __future__ import annotations

import string
from collections import defaultdict

from archinfo import Endness

from angr.ailment import AILBlockViewer, BinaryOp
from angr.ailment.expression import (
    Call,
    Const,
    DirtyExpression,
    Expression,
    Load,
    MultiStatementExpression,
    Register,
    StackBaseOffset,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.statement import Assignment, SideEffectStatement, Store
from angr.ailment.tagged_object import TagDict
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.sim_type import PointerDisposition, SimTypeFunction, SimTypeLong, SimTypePointer, SimTypeWideChar
from angr.utils.endness import ail_const_to_be
from angr.utils.ssa import phi_assignment_get_src

from .optimization_pass import OptimizationPass, OptimizationPassStage

ASCII_PRINTABLES = {ord(x) for x in string.printable if ord(x) >= 0x20}
ASCII_DIGITS = {ord(x) for x in string.digits}


class _MemoryAccessFinder(AILBlockViewer):
    """
    Determines if a statement may read memory, reference the stack, or have side effects.
    """

    def __init__(self):
        super().__init__()
        self.found = False

    def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):
        if self.found:
            return None
        if isinstance(expr, (Load, Call, DirtyExpression, MultiStatementExpression, StackBaseOffset)) or (
            isinstance(expr, VirtualVariable) and expr.was_stack
        ):
            self.found = True
            return None
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


class _VVarValueUseCounter(AILBlockViewer):
    """
    Counts value uses of virtual variables. Taking the address of a virtual variable is not a value use.
    """

    def __init__(self):
        super().__init__()
        self.counts: defaultdict[int, int] = defaultdict(int)

    def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.tags.get("extra_def", False):
            return None
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Assignment(self, stmt_idx, stmt, block):
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)

    def _handle_UnaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.op == "Reference" and isinstance(expr.operand, VirtualVariable):
            return None
        return super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        self.counts[expr.varid] += 1


class InlinedWcscpySimplifier(OptimizationPass):
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
        self._vvar_value_uses: dict[int, int] | None = None
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
            dst = StackBaseOffset(self.manager.next_atom(), self.project.arch.bits, stmt.dst.stack_offset)
            value_size = stmt.src.size
            value = stmt.src.value
        elif isinstance(stmt, Store) and isinstance(stmt.data, Const) and isinstance(stmt.data.value, int):
            dst = stmt.addr
            value_size = stmt.data.size
            value = stmt.data.value
        else:
            return None

        r, s = self.is_integer_likely_a_wide_string(value, value_size, self.project.arch.memory_endness, min_length=2)
        if r and self._stmts_removable(statements, [stmt_idx]):
            assert s is not None
            return self._make_wcsncpy_call(stmt, dst, s)

        # scan forward to find all consecutive constant stores
        all_constant_stores = self._collect_constant_stores(statements, stmt_idx)
        found = self._find_wide_string_stride(statements, stmt_idx, all_constant_stores)
        if found is not None:
            stride, s = found
            for _, sidx, _ in stride:
                if sidx != stmt_idx:
                    statements[sidx] = None
            first_offset, first_sidx, _ = stride[0]
            if isinstance(stmt, Assignment):
                dst = StackBaseOffset(self.manager.next_atom(), self.project.arch.bits, first_offset)
            else:
                dst = statements[first_sidx].addr if first_sidx != stmt_idx else stmt.addr
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
            r, s = self.is_integer_likely_a_wide_string(integer, size, Endness.BE, min_length=2)
            if r and self._stmts_removable(statements, [sidx for _, sidx, _ in stride]):
                assert s is not None
                return stride, s
        return None

    def _stmts_removable(self, statements, stmt_indices) -> bool:
        """
        Statements are removable if the virtual variables they define are not used by value anywhere else.
        """
        defined = [
            statements[i].dst.varid
            for i in stmt_indices
            if isinstance(statements[i], Assignment) and isinstance(statements[i].dst, VirtualVariable)
        ]
        if not defined:
            return True
        local_counter = _VVarValueUseCounter()
        for i in stmt_indices:
            local_counter.walk_statement(statements[i])
        all_uses = self._value_use_counts()
        return all(all_uses.get(varid, 0) == local_counter.counts.get(varid, 0) for varid in defined)

    def _value_use_counts(self) -> dict[int, int]:
        if self._vvar_value_uses is None:
            # uses by a phi only count if the phi variable itself is used, since dead phis are removed later
            counter = _VVarValueUseCounter()
            phi_srcs: dict[int, list[int]] = {}
            for block in self._graph:
                for stmt in block.statements:
                    phi = phi_assignment_get_src(stmt)
                    if phi is not None:
                        assert isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable)
                        phi_srcs[stmt.dst.varid] = [vvar.varid for _, vvar in phi.src_and_vvars if vvar is not None]
                    else:
                        counter.walk_statement(stmt, block=block)
            counts = counter.counts
            worklist = [varid for varid in phi_srcs if counts[varid] > 0]
            live = set(worklist)
            while worklist:
                for src_varid in phi_srcs.get(worklist.pop(), []):
                    counts[src_varid] += 1
                    if src_varid in phi_srcs and src_varid not in live:
                        live.add(src_varid)
                        worklist.append(src_varid)
            self._vvar_value_uses = dict(counts)
        return self._vvar_value_uses

    def _make_wcsncpy_call(self, stmt, dst, s):
        str_id = self.kb.custom_strings.allocate(s)
        wstr_type = SimTypePointer(SimTypeWideChar()).with_arch(self.project.arch)
        wstr_type_out = SimTypePointer(SimTypeWideChar(), disposition=PointerDisposition.OUT)
        str_const = Const(
            self.manager.next_atom(),
            str_id,
            self.project.arch.bits,
            type=wstr_type,
        )
        variable_map_of(self.manager).set_custom_string(str_const)
        call = Call(
            self.manager.next_atom(),
            "wcsncpy",
            args=[
                dst,
                str_const,
                Const(self.manager.next_atom(), len(s) // 2, self.project.arch.bits),
            ],
            **stmt.tags,
        )
        variable_map_of(self.manager).set_prototype(
            call,
            SimTypeFunction([wstr_type_out, wstr_type, SimTypeLong(signed=False)], wstr_type).with_arch(
                self.project.arch
            ),
        )
        return SideEffectStatement(
            self.manager.next_atom(),
            call,
            **stmt.tags,
        )

    def _consolidate_wcscpy_calls(self, statements):
        """Consolidate inlined wcsncpy calls (phase 2).

        Collects all wcsncpy calls, constant stores, and constant stack assignments in the block, groups them by base
        address, and consolidates adjacent entries within each group.
        """
        # Collect all candidate statements with their base/offset. Candidates separated by a statement that may read
        # or clobber memory are never merged, so each group only spans one barrier-free segment.
        candidates = []  # list of (stmt_index, base, offset, store_size, stmt)
        segments = {}  # stmt_index -> segment id
        segment = 0
        for i, stmt in enumerate(statements):
            segments[i] = segment
            if isinstance(stmt, SideEffectStatement) and self.is_inlined_wcsncpy(stmt):
                assert stmt.expr.args is not None and len(stmt.expr.args) >= 3
                base, off = self._parse_addr(stmt.expr.args[0])
                count = stmt.expr.args[2]
                if not isinstance(count, Const) or not count.is_int:
                    return None
                store_size = count.value_int * 2
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

        if not candidates:
            return None

        # Must have at least one wcsncpy call
        has_wcsncpy = any(
            isinstance(s, SideEffectStatement) and self.is_inlined_wcsncpy(s) for _, _, _, _, s in candidates
        )
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
            if not any(isinstance(s, SideEffectStatement) and self.is_inlined_wcsncpy(s) for _, _, _, _, s in group):
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
                        new_sz = (
                            merged_stmt.expr.args[2].value_int * 2
                            if len(merged_stmt.expr.args) >= 3
                            and isinstance(merged_stmt.expr.args[2], Const)
                            and merged_stmt.expr.args[2].is_int
                            else sz0 + sz1
                        )
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
        if (
            isinstance(stmt, SideEffectStatement)
            and self.is_inlined_wcsncpy(stmt)
            and stmt.expr.args is not None
            and len(stmt.expr.args) == 3
            and isinstance(stmt.expr.args[2], Const)
            and isinstance(stmt.expr.args[2].value, int)
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
            wcsncpy_addr = stmt.expr.args[0]
            wcsncpy_size = stmt.expr.args[2].value * 2
            delta = self._get_delta(store_addr, wcsncpy_addr)
            if delta is not None:
                if (0 <= delta <= store_size) or (delta < 0 and -delta <= wcsncpy_size):
                    pass  # they overlap, do not switch
                else:
                    last_stmt, stmt = stmt, last_stmt

        # swap two statements if they are out of order
        if self.is_inlined_wcsncpy(last_stmt) and self.is_inlined_wcsncpy(stmt):
            assert isinstance(last_stmt, SideEffectStatement) and isinstance(stmt, SideEffectStatement)
            assert last_stmt.expr.args is not None and stmt.expr.args is not None
            delta = self._get_delta(last_stmt.expr.args[0], stmt.expr.args[0])
            if delta is not None and delta < 0:
                last_stmt, stmt = stmt, last_stmt

        if self.is_inlined_wcsncpy(last_stmt):
            assert isinstance(last_stmt, SideEffectStatement)
            assert last_stmt.expr.args is not None and isinstance(last_stmt.expr.args[1], Const)
            s_last = self.kb.custom_strings[last_stmt.expr.args[1].value_int]
            addr_last = last_stmt.expr.args[0]
            new_str = None

            if isinstance(stmt, SideEffectStatement) and self.is_inlined_wcsncpy(stmt):
                assert stmt.expr.args is not None and isinstance(stmt.expr.args[1], Const)
                s_curr = self.kb.custom_strings[stmt.expr.args[1].value_int]
                addr_curr = stmt.expr.args[0]
                delta = self._get_delta(addr_last, addr_curr)
                if delta is not None and delta == len(s_last):
                    new_str = s_last + s_curr
            elif isinstance(stmt, Store) and isinstance(stmt.data, Const) and isinstance(stmt.data.value, int):
                addr_curr = stmt.addr
                delta = self._get_delta(addr_last, addr_curr)
                if delta is not None and delta == len(s_last):
                    if stmt.size == 2 and stmt.data.value == 0:
                        r, s = True, b"\x00\x00"
                    else:
                        r, s = self.is_integer_likely_a_wide_string(
                            stmt.data.value, stmt.size, stmt.endness, min_length=1
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
                        stmt.src.value, stmt.dst.size, self.project.arch.memory_endness, min_length=1
                    )
                    if r and s is not None:
                        new_str = s_last + s

            if new_str is not None:
                wstr_type = SimTypePointer(SimTypeWideChar()).with_arch(self.project.arch)
                wstr_type_out = SimTypePointer(SimTypeWideChar(), disposition=PointerDisposition.OUT)
                prototype = SimTypeFunction([wstr_type_out, wstr_type, SimTypeLong(signed=False)], wstr_type).with_arch(
                    self.project.arch
                )
                if new_str.endswith(b"\x00\x00"):
                    call_name = "wcsncpy"
                    new_str_idx = self.kb.custom_strings.allocate(new_str[:-2])
                    str_const = Const(
                        self.manager.next_atom(),
                        new_str_idx,
                        last_stmt.expr.args[0].bits,
                        type=wstr_type,
                    )
                    variable_map_of(self.manager).set_custom_string(str_const)
                    args = [
                        last_stmt.expr.args[0],
                        str_const,
                    ]
                else:
                    call_name = "wcsncpy"
                    new_str_idx = self.kb.custom_strings.allocate(new_str)
                    str_const = Const(
                        self.manager.next_atom(),
                        new_str_idx,
                        last_stmt.expr.args[0].bits,
                        type=wstr_type,
                    )
                    variable_map_of(self.manager).set_custom_string(str_const)
                    args = [
                        last_stmt.expr.args[0],
                        str_const,
                        Const(self.manager.next_atom(), len(new_str) // 2, self.project.arch.bits),
                    ]

                tags = TagDict(stmt.tags)
                if args[0].tags.get("extra_def", False):
                    assert isinstance(args[0], UnaryOp)
                    assert args[0].op == "Reference"
                    assert isinstance(args[0].operand, VirtualVariable)
                    tags["extra_defs"] = [args[0].operand.varid]
                else:
                    tags.pop("extra_defs", None)
                call = Call(self.manager.next_atom(), call_name, args=args, **tags)
                variable_map_of(self.manager).set_prototype(call, prototype)
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
            elif expected_type == "store" and isinstance(stmt, Store):
                if isinstance(stmt.addr, VirtualVariable) and stmt.addr.varid == expected_store_varid:
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
    def _is_unrelated_stmt(stmt) -> bool:
        """
        Whether a statement neither reads nor writes memory.
        """
        if not (isinstance(stmt, Assignment) and isinstance(stmt.dst, (VirtualVariable, Register))):
            return False
        if isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_stack:
            return False
        finder = _MemoryAccessFinder()
        finder.walk_expression(stmt.src)
        return not finder.found

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
    def is_integer_likely_a_wide_string(v, size, endness, min_length=4):
        if not isinstance(v, int) or not isinstance(size, int):
            return False, None

        chars = []
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
            return False, None

        if not (
            InlinedWcscpySimplifier.even_offsets_are_zero(chars) or InlinedWcscpySimplifier.odd_offsets_are_zero(chars)
        ):
            return False, None

        if chars and len(chars) >= 2 and chars[-1] == 0 and chars[-2] == 0:
            chars = chars[:-1]
        if len(chars) >= min_length * 2 and all((ch == 0 or ch in ASCII_PRINTABLES) for ch in chars):
            if len(chars) <= 4 * 2 and all((ch == 0 or ch in ASCII_DIGITS) for ch in chars):
                return False, None
            return True, bytes(chars)
        return False, None

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
