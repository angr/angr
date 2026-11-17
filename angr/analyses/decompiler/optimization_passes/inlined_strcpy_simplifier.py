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
from angr.ailment import AILBlockViewer
from angr.ailment.statement import ConditionalJump, Jump

ASCII_PRINTABLES = set(string.printable)
ASCII_DIGITS = set(string.digits)


class _ScalarUseFinder(AILBlockViewer):
    """
    v3 (R1+R2, M6): byte-faithful scalar-use detector.

    Evidence collected, in value position only:
      * Load overlapping the candidate region            -> hit (scalar read)
      * VirtualVariable with was_stack overlapping the
        candidate region                                 -> hit (SSA region read)
      * Phi virtual-variable children are walked normally -> hit likewise

    Counter-evidence / conservatism:
      * A Reference-of-stack address escapes the region without reading bytes.
        It is recorded as ``escaped`` unless the enclosing statement is a call
        to a known string function (``textual``); escaped-and-unresolved leads
        to ABSTAIN, never SAFE.
      * Any Load with an unresolvable address yields ``unresolved`` (ABSTAIN).
      * Any statement type this finder cannot classify yields ``unresolved``.

    Stores / Assignments whose destination is normalisable shrink the region so
    that later overlapping reads cannot be attributed to the original candidate.
    Shrinking is *disabled once a ConditionalJump was seen* in the block,
    because order is no longer linear.
    """

    STRING_CALLS = frozenset({
        "strcpy", "strncpy", "strcat", "strncat",
        "memcpy", "memmove", "memset",
        "strlen", "strcmp", "strncmp", "memcmp",
        "strchr", "strrchr",
    })

    def __init__(self, region: set[int]):
        super().__init__()
        self._region: set[int] = set(region)
        self._hit: bool = False
        self.unresolved: bool = False
        self.escaped: bool = False
        self.textual: bool = False
        self.branch_seen: bool = False
        self._addr_position: bool = False

    @staticmethod
    def _addr_off(addr) -> int | None:
        base, off = InlinedStrcpySimplifier._parse_addr(addr)
        if not isinstance(base, StackBaseOffset):
            return None
        return off if isinstance(off, int) else None

    @staticmethod
    def _overlap(off: int | None, size: int | None, region: set[int]) -> bool:
        if not isinstance(off, int) or not isinstance(size, int) or size <= 0:
            return False
        return bool(region & set(range(off, off + size)))

    @property
    def hit_scalar_use(self) -> bool:
        return self._hit

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.was_stack:
            off = expr.stack_offset
            size = expr.size
            if not isinstance(off, int) or not isinstance(size, int) or size <= 0:
                self.unresolved = True
            elif self._overlap(off, size, self._region):
                self._hit = True
        return None

    def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
        off = self._addr_off(expr.addr)
        size = getattr(expr, "size", None)
        if off is None or not isinstance(size, int) or size <= 0:
            self.unresolved = True
        elif self._overlap(off, size, self._region):
            self._hit = True
        # nested loads inside the address expression DO read bytes (e.g. cmp [sp], x)
        self._addr_position = True
        self._handle_expr(0, expr.addr, stmt_idx, stmt, block)
        self._addr_position = False
        return None

    def _handle_UnaryOp(self, expr_idx, op, stmt_idx, stmt, block):
        if op.op == "Reference":
            operand = op.operand
            if isinstance(operand, VirtualVariable) and operand.was_stack:
                if not self._addr_position:
                    # address-of-stack: escapes the region without reading bytes.
                    if self._overlap(operand.stack_offset, operand.size, self._region):
                        self.escaped = True
                return None  # never a scalar read, never walk the pointee as a read
        return super()._handle_UnaryOp(expr_idx, op, stmt_idx, stmt, block)

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        target = expr.target
        if isinstance(target, str) and target in self.STRING_CALLS:
            self.textual = True
        return super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Store(self, stmt_idx, stmt, block):
        off = self._addr_off(stmt.addr)
        size = getattr(stmt, "size", None)
        if off is not None and isinstance(size, int) and size > 0:
            self._region.difference_update(range(off, off + size))
        self._addr_position = True
        self._handle_expr(0, stmt.addr, stmt_idx, stmt, block)
        self._addr_position = False
        self._handle_expr(1, stmt.data, stmt_idx, stmt, block)
        return None

    def _handle_Assignment(self, stmt_idx, stmt, block):
        dst = stmt.dst
        if isinstance(dst, VirtualVariable) and dst.was_stack:
            off = dst.stack_offset
            size = getattr(dst, "size", None)
            if isinstance(off, int) and isinstance(size, int) and size > 0:
                self._region.difference_update(range(off, off + size))
            else:
                self.unresolved = True
        # the dst is a definition, never a use; src is a value read
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
        return None


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
        statements, float_writes = self._int_const_views(block.statements)
        changed = False
        new_statements = []
        stmt_idx = 0
        while stmt_idx < len(statements):
            stmt = statements[stmt_idx]
            replacement = self._optimize_single_stmt(stmt, stmt_idx, statements, block=block)
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
            return block.copy(statements=self._restore_float_consts(statements, float_writes))
        return None

    def _optimize_single_stmt(self, stmt, stmt_idx, statements, block=None):
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
            if self._scalar_use_present(stmt_idx, stmt, statements, block=block):
                return None

            r, s = self.is_integer_likely_a_string(src.value, src.size, self.project.arch.memory_endness)
            if r and self._stmts_removable(statements, [stmt_idx]):
                assert s is not None
                tags = self._tags_with_extra_defs(stmt.tags, strcpy_dst)
                call = self._make_copy_call(strcpy_dst, s, tags)
                return SideEffectStatement(self.manager.next_atom(), call, ret_expr=None, fp_ret_expr=None, **tags)

            # scan forward to find all consecutive constant stores
            all_constant_stores = self._collect_constant_stores(statements, stmt_idx)
            prev_stmt = None if stmt_idx == 0 else statements[stmt_idx - 1]
            # a short string may extend an unterminated string before it
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

    def _successor_evidence(self, region: set[int], block) -> str:
        """
        Scan every statement of every block reachable from the candidate block
        (function-wide, edges flow forward).  Returns:
          "clean"   -- scanned everything; no hit and no unresolved escape/addr.
          "hit"     -- some block executed after this one reads the region.
          "unknown" -- the graph was unusable; cannot prove coverage.

        No shrinking is applied across blocks (order unproven across sibling
        branches) -> this is evidence collection, never a proof of absence
        unless it also reports clean.
        """
        import networkx

        if block is None:
            return "not_scanned"
        graph = getattr(self, "_graph", None)
        if graph is None:
            return "unknown"
        try:
            successors = list(networkx.descendants(graph, block))
        except Exception:
            return "unknown"
        bad_stmts = False
        for succ in successors:
            for stmt in getattr(succ, "statements", []):
                if stmt is None:
                    continue
                finder = _ScalarUseFinder(set(region))
                finder.walk_statement(stmt)
                if finder._hit:
                    return "hit"
                if finder.unresolved or (finder.escaped and not finder.textual):
                    bad_stmts = True
        return "unknown" if bad_stmts else "clean"

    def _scalar_use_decision(self, stmt_idx, stmt, statements, block=None) -> str:
        """
        Classify the candidate Store for the consumer contract:
          SAFE_TO_TRANSFORM -- no scalar evidence anywhere; transform may proceed.
          PRESERVE_SCALAR   -- scalar evidence found (here or in successors); skip transform.
          ABSTAIN           -- memory/control flow not resolvable; must abstain.

        Bytes are tracked in range(off, off+size_bytes).  Scanning later
        statements in this block is order-dependent only until a conditional
        jump is found; after that point shrinking is disabled (order is no
        longer linear) but evidence collection continues.  Additionally,
        statements of all blocks reachable from this one in the same function
        graph are scanned conservatively (no shrinking across blocks).
        """
        region: set[int] | None = None
        if isinstance(stmt, Assignment):
            dst = stmt.dst
            if isinstance(dst, VirtualVariable) and dst.was_stack:
                off = dst.stack_offset
                size = getattr(dst, "size", None)
                if isinstance(off, int) and isinstance(size, int) and size > 0:
                    region = set(range(off, off + size))
            else:
                return "ABSTAIN"
        elif isinstance(stmt, Store):
            addr = stmt.addr
            size = getattr(stmt, "size", None)
            off = None
            if isinstance(addr, StackBaseOffset):
                off = addr.offset if isinstance(addr.offset, int) else None
            elif (isinstance(addr, UnaryOp) and addr.op == "Reference"
                  and isinstance(addr.operand, VirtualVariable)
                  and addr.operand.was_stack
                  and isinstance(addr.operand.stack_offset, int)):
                off = addr.operand.stack_offset
            if off is not None and isinstance(size, int) and size > 0:
                region = set(range(off, off + size))
            else:
                # Candidate address not resolvable: cannot establish the memory relation.
                return "ABSTAIN"
        else:
            return "ABSTAIN"

        # --- local block scan ---
        local_unresolved = False
        branch = False
        for nxt in range(stmt_idx + 1, len(statements)):
            other = statements[nxt]
            if other is None:
                continue
            if isinstance(other, Jump):
                # unreachable tail in this block
                break
            if isinstance(other, ConditionalJump):
                branch = True
                # keep scanning: evidence collection is order-independent; disable shrinking from now on
                f = _ScalarUseFinder(set(region))
                f.walk_statement(other)
                if f._hit:
                    return "PRESERVE_SCALAR"
                if f.unresolved or (f.escaped and not f.textual):
                    local_unresolved = True
                continue
            f = _ScalarUseFinder(set(region))
            f.walk_statement(other)
            if f._hit:
                return "PRESERVE_SCALAR"
            if f.unresolved or (f.escaped and not f.textual):
                local_unresolved = True
            if not branch:
                # only shrink while control flow is linear; after a branch order is unproven
                if isinstance(other, Store):
                    off = _ScalarUseFinder._addr_off(other.addr)
                    size = other.size
                    if isinstance(off, int) and isinstance(size, int) and size > 0:
                        region.difference_update(range(off, off + size))
                    # else: opaque Store is not a read and not a proof of overlap.
                    # Do not shrink, do not ABSTAIN: keep tracking bytes (option A, M7).
                elif isinstance(other, Assignment):
                    dst = other.dst
                    if isinstance(dst, VirtualVariable) and dst.was_stack:
                        off = dst.stack_offset
                        size = getattr(dst, "size", None)
                        if isinstance(off, int) and isinstance(size, int) and size > 0:
                            region.difference_update(range(off, off + size))
                        else:
                            # stack-vvar def with unknown width: real clobber chance; ABSTAIN
                            local_unresolved = True
                    # else: non-stack dst (Register/Phi/nested) writes no memory: not an obstacle

        # --- function-wide successors scan (R2) ---
        succ = self._successor_evidence(region, block)
        if succ == "hit":
            return "PRESERVE_SCALAR"
        if local_unresolved:
            return "ABSTAIN"
        if succ == "unknown":
            return "ABSTAIN"
        if succ in ("not_scanned", "clean"):
            if branch:
                return "ABSTAIN"   # T15: branch with no hit evidence -> abstain (contract)
            return "SAFE_TO_TRANSFORM"
        return "ABSTAIN"

    def _scalar_use_present(self, stmt_idx, stmt, statements, block=None) -> bool:
        return self._scalar_use_decision(stmt_idx, stmt, statements, block=block) != "SAFE_TO_TRANSFORM"

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
        # stop at the first statement that may read or clobber the buffer because writes after cannot be hoisted
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
