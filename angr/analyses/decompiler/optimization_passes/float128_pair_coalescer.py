from __future__ import annotations

import struct

from angr.ailment.block import Block
from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Convert,
    Expression,
    Load,
    StackBaseOffset,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, ConditionalJump, Label, Statement, Store
from angr.analyses.decompiler.ail_simplifier import AILBlockRewriter
from angr.utils.ssa import get_vvar_uselocs

from .optimization_pass import OptimizationPass, OptimizationPassStage


def _match_hi(expr: Expression) -> Expression | None:
    """Conv(128->64, x >> 64) -> x"""
    if (
        isinstance(expr, Convert)
        and expr.from_bits == 128
        and expr.to_bits == 64
        and expr.from_type == Convert.TYPE_INT
        and isinstance(expr.operand, BinaryOp)
        and expr.operand.op == "Shr"
        and isinstance(expr.operand.operands[1], Const)
        and expr.operand.operands[1].value == 64
    ):
        return expr.operand.operands[0]
    return None


def _match_lo(expr: Expression) -> Expression | None:
    """Conv(128->64, x) -> x"""
    if (
        isinstance(expr, Convert)
        and expr.from_bits == 128
        and expr.to_bits == 64
        and expr.from_type == Convert.TYPE_INT
        and expr.to_type == Convert.TYPE_INT
        and _match_hi(expr) is None
    ):
        return expr.operand
    return None


def _is_fp128_op(expr: Expression) -> bool:
    if expr.bits != 128:
        return False
    if isinstance(expr, (UnaryOp, BinaryOp)):
        return expr.floating_point and not (isinstance(expr, BinaryOp) and expr.vector_count is not None)
    return isinstance(expr, Convert) and expr.to_type == Convert.TYPE_FP and expr.vector_count is None


def _fp128_operands(expr: Expression) -> list[Expression]:
    """Operands of an expression that are 128-bit floating-point values."""
    if isinstance(expr, BinaryOp) and expr.floating_point and expr.vector_count is None:
        return [op for op in expr.operands if op.bits == 128]
    if isinstance(expr, UnaryOp) and expr.floating_point and expr.operand.bits == 128:
        return [expr.operand]
    if isinstance(expr, Convert) and expr.from_type == Convert.TYPE_FP and expr.from_bits == 128:
        return [expr.operand]
    return []


def _split_offset(addr: Expression) -> tuple[Expression, int]:
    if isinstance(addr, BinaryOp) and addr.op == "Add":
        for base, off in (addr.operands, addr.operands[::-1]):
            if isinstance(off, Const) and isinstance(off.value, int):
                return base, off.value
    return addr, 0


def _adjacent(addr_hi: Expression, addr_lo: Expression, big_endian: bool) -> bool:
    """Whether the high and the low 8-byte halves at these addresses form one 16-byte value."""
    base_hi, off_hi = _split_offset(addr_hi)
    base_lo, off_lo = _split_offset(addr_lo)
    expected = off_hi + 8 if big_endian else off_hi - 8
    return off_lo == expected and base_hi.likes(base_lo)


def _const_bits(c: Const) -> int | None:
    if isinstance(c.value, float):
        return struct.unpack(">Q", struct.pack(">d", c.value))[0]
    if isinstance(c.value, int):
        return c.value & 0xFFFF_FFFF_FFFF_FFFF
    return None


class _ConcatCollector(AILBlockViewer):
    """
    Collect (hi, lo) register vvar pairs concatenated into binary128 operands or stored to adjacent 8-byte slots, and
    note binary128 Concat constants.
    """

    def __init__(self):
        super().__init__()
        self.pairs: set[tuple[int, int]] = set()
        self.stored_pairs: set[tuple[int, int]] = set()
        self.has_const_concat = False

    def walk(self, block: Block):
        for s0, s1 in zip(block.statements, block.statements[1:]):
            halves = _store_pair_halves(s0, s1)
            if halves is not None:
                hi, lo = halves
                if isinstance(hi, VirtualVariable) and isinstance(lo, VirtualVariable) and hi.was_reg and lo.was_reg:
                    self.stored_pairs.add((hi.varid, lo.varid))
        return super().walk(block)

    def _handle_expr(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt, block):
        for op in _fp128_operands(expr):
            if isinstance(op, BinaryOp) and op.op == "Concat":
                hi, lo = op.operands
                if isinstance(hi, VirtualVariable) and isinstance(lo, VirtualVariable):
                    if hi.bits == 64 and lo.bits == 64 and hi.was_reg and lo.was_reg:
                        self.pairs.add((hi.varid, lo.varid))
                elif isinstance(hi, Const) and isinstance(lo, Const):
                    self.has_const_concat = True
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


def _store_pair_halves(s0: Statement, s1: Statement) -> tuple[Expression, Expression] | None:
    """The (high, low) data of two adjacent statements storing the halves of one 16-byte value."""
    if not (
        isinstance(s0, Store)
        and isinstance(s1, Store)
        and s0.size == 8
        and s1.size == 8
        and s0.endness == s1.endness
        and s0.guard is None
        and s1.guard is None
    ):
        return None
    big_endian = s0.endness == "Iend_BE"
    if _adjacent(s0.addr, s1.addr, big_endian):
        return s0.data, s1.data
    if _adjacent(s1.addr, s0.addr, big_endian):
        return s1.data, s0.data
    return None


def _renumbered(vvar: VirtualVariable, manager) -> VirtualVariable:
    """A copy of a vvar occurrence with a fresh expression index."""
    return VirtualVariable(manager.next_atom(), vvar.varid, vvar.bits, vvar.category, oident=vvar.oident, **vvar.tags)


def _fp128_tags(tags: dict) -> dict:
    return {**tags, "data_type": "Ity_F128"}


def _is_stack_addr(addr: Expression) -> bool:
    if isinstance(addr, StackBaseOffset):
        return True
    if isinstance(addr, UnaryOp) and addr.op == "Reference":
        return isinstance(addr.operand, VirtualVariable) and addr.operand.was_stack
    if isinstance(addr, BinaryOp) and addr.op in ("Add", "Sub"):
        return any(_is_stack_addr(op) for op in addr.operands)
    return False


class _PairRewriter(AILBlockRewriter):
    """Replace Concat(hi, lo) of coalesced pairs with their binary128 vvar and fold Concat constants."""

    def __init__(self, pair_vvars: dict[tuple[int, int], VirtualVariable], manager):
        super().__init__(update_block=False)
        self._pair_vvars = pair_vvars
        self._manager = manager
        self.changed = False

    def _handle_expr(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None):
        if isinstance(expr, BinaryOp) and expr.op == "Concat" and expr.bits == 128:
            hi, lo = expr.operands
            if isinstance(hi, VirtualVariable) and isinstance(lo, VirtualVariable):
                vvar = self._pair_vvars.get((hi.varid, lo.varid))
                if vvar is not None:
                    self.changed = True
                    return _renumbered(vvar, self._manager)
        new_expr = super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)
        target = new_expr if new_expr is not None else expr
        if _fp128_operands(target):
            folded = self._fold_const_operands(target)
            if folded is not None:
                self.changed = True
                return folded
        return new_expr

    def _fold_const_operands(self, expr: Expression) -> Expression | None:
        new_expr = expr
        for op in _fp128_operands(expr):
            if not (isinstance(op, BinaryOp) and op.op == "Concat"):
                continue
            hi, lo = op.operands
            if not (isinstance(hi, Const) and isinstance(lo, Const)):
                continue
            hi_bits, lo_bits = _const_bits(hi), _const_bits(lo)
            if hi_bits is None or lo_bits is None:
                continue
            const = Const(self._manager.next_atom(), (hi_bits << 64) | lo_bits, 128, **op.tags)
            _, new_expr = new_expr.replace(op, const)
        return new_expr if new_expr is not expr else None


class Float128PairCoalescer(OptimizationPass):
    """
    Coalesce binary128 (long double) values that VEX splits across a pair of 64-bit FP registers.

    s390x keeps a long double in a register pair (f0:f2, f4:f6, ...). VEX reads it with F64HLtoF128(hi, lo) and writes
    it back with F128HItoF64 / F128LOtoF64, so every long double turns into two 64-bit halves that are concatenated at
    each use. This pass gives each such pair one 128-bit variable, defined by the 128-bit operation that produced the
    halves or by one 16-byte load, and rewrites the uses: concatenations, stores of both halves, and spills of both
    halves to adjacent stack slots. 128-bit constants built from two 64-bit halves are folded too.
    """

    ARCHES = ["S390X"]
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Coalesce binary128 register pairs"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, *args, **kwargs):
        super().__init__(func, *args, **kwargs)
        self.analyze()

    def _check(self):
        if self._graph is None:
            return False, None
        collector = _ConcatCollector()
        for block in self._graph.nodes():
            collector.walk(block)
        if not collector.pairs and not collector.stored_pairs and not collector.has_const_concat:
            return False, None
        return True, (collector.pairs, collector.stored_pairs)

    def _analyze(self, cache=None):
        assert self._graph is not None
        fp_pairs, stored_pairs = cache if cache is not None else (set(), set())

        defs: dict[int, tuple[Block, int]] = {}
        for block in self._graph.nodes():
            for stmt_idx, stmt in enumerate(block.statements):
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    defs[stmt.dst.varid] = block, stmt_idx

        # new definitions to insert: block -> [(insert-after stmt idx, statement)]
        inserts: dict[Block, list[tuple[int, Statement]]] = {}
        pair_vvars: dict[tuple[int, int], VirtualVariable] = {}
        for hi_id, lo_id in sorted(fp_pairs | stored_pairs):
            if hi_id not in defs or lo_id not in defs:
                continue
            block, hi_idx = defs[hi_id]
            lo_block, lo_idx = defs[lo_id]
            if lo_block is not block:
                continue
            # a 16-byte load is a long double only if the pair is used as one
            src = self._pair_source(block, hi_idx, lo_idx, (hi_id, lo_id) in fp_pairs)
            if src is None:
                continue
            vvar = VirtualVariable(
                self.manager.next_atom(),
                self.vvar_id_start,
                128,
                VirtualVariableCategory.REGISTER,
                oident=block.statements[hi_idx].dst.oident,
                **block.statements[hi_idx].dst.tags,
            )
            self.vvar_id_start += 1
            pair_vvars[(hi_id, lo_id)] = vvar
            stmt = Assignment(self.manager.next_atom(), vvar, src, **block.statements[max(hi_idx, lo_idx)].tags)
            inserts.setdefault(block, []).append((max(hi_idx, lo_idx), stmt))

        changed = False
        for block in list(self._graph.nodes()):
            statements = list(block.statements)
            for after_idx, stmt in sorted(inserts.get(block, []), key=lambda t: t[0], reverse=True):
                statements.insert(after_idx + 1, stmt)
            new_block = block.copy(statements=statements) if block in inserts else block
            rewriter = _PairRewriter(pair_vvars, self.manager)
            rewritten = rewriter.walk(new_block)
            if rewritten is not None and rewriter.changed:
                new_block = rewritten
            new_block = self._merge_half_stores(new_block, pair_vvars)
            if new_block is not block:
                self._update_block(block, new_block)
                changed = True

        if changed:
            widened = self._merge_stack_spills(pair_vvars)
            widened.update(self._merge_copies())
            if widened:
                for block in list(self._graph.nodes()):
                    rewriter = _VVarWidener(widened, self.manager)
                    new_block = rewriter.walk(block)
                    if rewriter.changed and new_block is not None and new_block is not block:
                        self._update_block(block, new_block)

    def _pair_source(self, block: Block, hi_idx: int, lo_idx: int, allow_load: bool) -> Expression | None:
        """The binary128 value whose high and low halves the two statements define, if any."""
        hi_src = block.statements[hi_idx].src
        lo_src = block.statements[lo_idx].src
        first, last = min(hi_idx, lo_idx), max(hi_idx, lo_idx)
        # the value is re-evaluated after the later half; nothing in between may write the memory it reads
        for i in range(first + 1, last):
            stmt = block.statements[i]
            if isinstance(stmt, Assignment) and not isinstance(stmt.src, Call):
                continue
            if isinstance(stmt, (ConditionalJump, Label)):
                continue
            if isinstance(stmt, Store) and _is_stack_addr(stmt.addr):
                continue
            return None

        hi_x, lo_x = _match_hi(hi_src), _match_lo(lo_src)
        if hi_x is not None and lo_x is not None and hi_x.likes(lo_x) and _is_fp128_op(hi_x):
            return hi_x

        if (
            allow_load
            and isinstance(hi_src, Load)
            and isinstance(lo_src, Load)
            and hi_src.size == 8
            and lo_src.size == 8
            and hi_src.endness == lo_src.endness
            and _adjacent(hi_src.addr, lo_src.addr, hi_src.endness == "Iend_BE")
            and not _is_stack_addr(hi_src.addr)
        ):
            addr = hi_src.addr if hi_src.endness == "Iend_BE" else lo_src.addr
            tags = dict(hi_src.tags)
            tags["data_type"] = "Ity_F128"
            return Load(self.manager.next_atom(), addr, 16, hi_src.endness, **tags)
        return None

    def _merge_half_stores(self, block: Block, pair_vvars: dict[tuple[int, int], VirtualVariable]) -> Block:
        """Store(a, hi); Store(a+8, lo) -> Store(a, value) for a binary128 value split into halves."""
        statements = list(block.statements)
        merged = False
        i = 0
        while i + 1 < len(statements):
            s0, s1 = statements[i], statements[i + 1]
            value = self._store_pair_value(s0, s1, pair_vvars)
            if value is not None:
                assert isinstance(s0, Store) and isinstance(s1, Store)
                hi_store = s0 if _adjacent(s0.addr, s1.addr, s0.endness == "Iend_BE") else s1
                statements[i] = Store(
                    self.manager.next_atom(),
                    hi_store.addr,
                    value,
                    16,
                    s0.endness,
                    guard=s0.guard,
                    **_fp128_tags(hi_store.tags),
                )
                del statements[i + 1]
                merged = True
            i += 1
        return block.copy(statements=statements) if merged else block

    @staticmethod
    def _store_pair_value(
        s0: Statement, s1: Statement, pair_vvars: dict[tuple[int, int], VirtualVariable]
    ) -> Expression | None:
        halves = _store_pair_halves(s0, s1)
        if halves is None:
            return None
        hi, lo = halves
        if isinstance(hi, VirtualVariable) and isinstance(lo, VirtualVariable):
            return pair_vvars.get((hi.varid, lo.varid))
        hi_x, lo_x = _match_hi(hi), _match_lo(lo)
        if hi_x is not None and lo_x is not None and hi_x.likes(lo_x) and _is_fp128_op(hi_x):
            return hi_x
        return None

    def _merge_stack_spills(self, pair_vvars: dict[tuple[int, int], VirtualVariable]) -> dict[int, VirtualVariable]:
        """
        s{off} = hi; s{off+8} = lo -> s{off, 16 bytes} = value, when the second slot is otherwise unused and the first
        is only used by address.
        """
        assert self._graph is not None
        uses = get_vvar_uselocs(list(self._graph.nodes()))
        blocks = {(b.addr, b.idx): b for b in self._graph.nodes()}
        widened: dict[int, VirtualVariable] = {}
        for block in list(self._graph.nodes()):
            statements = list(block.statements)
            changed = False
            i = 0
            while i + 1 < len(statements):
                s0, s1 = statements[i], statements[i + 1]
                if (
                    isinstance(s0, Assignment)
                    and isinstance(s1, Assignment)
                    and isinstance(s0.dst, VirtualVariable)
                    and isinstance(s1.dst, VirtualVariable)
                    and s0.dst.was_stack
                    and s1.dst.was_stack
                    and s0.dst.bits == 64
                    and s1.dst.bits == 64
                    and s1.dst.stack_offset == s0.dst.stack_offset + 8
                    and isinstance(s0.src, VirtualVariable)
                    and isinstance(s1.src, VirtualVariable)
                    and (s0.src.varid, s1.src.varid) in pair_vvars
                    and not uses.get(s1.dst.varid)
                    and all(_used_by_address(blocks, loc, s0.dst.varid) for _, loc in uses.get(s0.dst.varid, []))
                ):
                    wide = VirtualVariable(
                        self.manager.next_atom(),
                        s0.dst.varid,
                        128,
                        VirtualVariableCategory.STACK,
                        oident=s0.dst.stack_offset,
                        **s0.dst.tags,
                    )
                    widened[s0.dst.varid] = wide
                    value = _renumbered(pair_vvars[(s0.src.varid, s1.src.varid)], self.manager)
                    statements[i] = Assignment(self.manager.next_atom(), wide, value, **s0.tags)
                    del statements[i + 1]
                    changed = True
                i += 1
            if changed:
                self._update_block(block, block.copy(statements=statements))
        return widened

    def _merge_copies(self) -> dict[int, VirtualVariable]:
        """
        Store(q, *p); Store(q+8, *(p+8)) -> Store(q, *p as 16 bytes), and the same for the two 8-byte halves of a stack
        buffer, when q or p also holds a long double elsewhere in the function.
        """
        assert self._graph is not None
        fp128_addrs: list[Expression] = []
        load_defs: dict[int, tuple[Block, int, Load]] = {}
        for block in self._graph.nodes():
            for stmt_idx, stmt in enumerate(block.statements):
                if isinstance(stmt, Store) and stmt.size == 16:
                    fp128_addrs.append(stmt.addr)
                elif (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.src, Load)
                    and isinstance(stmt.dst, VirtualVariable)
                ):
                    if stmt.src.size == 16 and stmt.src.tags.get("data_type") == "Ity_F128":
                        fp128_addrs.append(stmt.src.addr)
                    elif stmt.src.size == 8:
                        load_defs[stmt.dst.varid] = block, stmt_idx, stmt.src

        def holds_fp128(addr: Expression) -> bool:
            return any(addr.likes(a) for a in fp128_addrs)

        def as_load(expr: Expression, block: Block, stmt_idx: int) -> Load | None:
            if isinstance(expr, Load):
                return expr
            if isinstance(expr, VirtualVariable) and expr.varid in load_defs:
                def_block, def_idx, load = load_defs[expr.varid]
                # the loaded memory must still be intact at the store
                if def_block is block and all(
                    isinstance(st, Assignment) and not isinstance(st.src, Call)
                    for st in block.statements[def_idx + 1 : stmt_idx]
                ):
                    return load
            return None

        stack_copies: list[tuple[Block, int, VirtualVariable, VirtualVariable]] = []
        for block in list(self._graph.nodes()):
            statements = list(block.statements)
            changed = False
            for i in range(len(statements) - 1):
                halves = _store_pair_halves(statements[i], statements[i + 1])
                if halves is None:
                    continue
                s0, s1 = statements[i], statements[i + 1]
                assert isinstance(s0, Store) and isinstance(s1, Store)
                big_endian = s0.endness == "Iend_BE"
                hi_store = s0 if _adjacent(s0.addr, s1.addr, big_endian) else s1
                hi, lo = halves
                hi_load, lo_load = as_load(hi, block, i), as_load(lo, block, i)
                if (
                    hi_load is not None
                    and lo_load is not None
                    and hi_load.endness == lo_load.endness == s0.endness
                    and _adjacent(hi_load.addr, lo_load.addr, big_endian)
                    and (holds_fp128(hi_store.addr) or holds_fp128(hi_load.addr))
                ):
                    tags = dict(hi_load.tags)
                    tags["data_type"] = "Ity_F128"
                    value = Load(self.manager.next_atom(), hi_load.addr, 16, hi_load.endness, **tags)
                    statements[i] = Store(
                        self.manager.next_atom(), hi_store.addr, value, 16, s0.endness, **_fp128_tags(hi_store.tags)
                    )
                    statements[i + 1] = None
                    changed = True
                elif (
                    isinstance(hi, VirtualVariable)
                    and isinstance(lo, VirtualVariable)
                    and hi.was_stack
                    and lo.was_stack
                    and lo.stack_offset == hi.stack_offset + 8
                    and holds_fp128(hi_store.addr)
                ):
                    stack_copies.append((block, i, hi, lo))
            if changed:
                self._update_block(block, block.copy(statements=[st for st in statements if st is not None]))

        if not stack_copies:
            return {}
        # the halves must not be read anywhere else
        blocks = {(b.addr, b.idx): b for b in self._graph.nodes()}
        uses = get_vvar_uselocs(list(self._graph.nodes()))
        copy_count: dict[int, int] = {}
        for _, _, hi, lo in stack_copies:
            copy_count[hi.varid] = copy_count.get(hi.varid, 0) + 1
            copy_count[lo.varid] = copy_count.get(lo.varid, 0) + 1
        widened: dict[int, VirtualVariable] = {}
        rewrites: dict[tuple[int, int | None], list[int]] = {}
        for block, i, hi, lo in stack_copies:
            hi_value_uses = sum(not _used_by_address(blocks, loc, hi.varid) for _, loc in uses.get(hi.varid, []))
            if hi_value_uses != copy_count[hi.varid] or len(uses.get(lo.varid, [])) != copy_count[lo.varid]:
                continue
            widened[hi.varid] = VirtualVariable(
                self.manager.next_atom(),
                hi.varid,
                128,
                VirtualVariableCategory.STACK,
                oident=hi.stack_offset,
                **hi.tags,
            )
            rewrites.setdefault((block.addr, block.idx), []).append(i)
        for key, indices in rewrites.items():
            block = blocks[key]
            statements: list[Statement | None] = list(block.statements)
            for i in indices:
                s0, s1 = block.statements[i], block.statements[i + 1]
                assert isinstance(s0, Store) and isinstance(s1, Store)
                hi_store = s0 if _adjacent(s0.addr, s1.addr, s0.endness == "Iend_BE") else s1
                hi_data = hi_store.data
                assert isinstance(hi_data, VirtualVariable)
                statements[i] = Store(
                    self.manager.next_atom(),
                    hi_store.addr,
                    _renumbered(widened[hi_data.varid], self.manager),
                    16,
                    s0.endness,
                    **_fp128_tags(hi_store.tags),
                )
                statements[i + 1] = None
            self._update_block(block, block.copy(statements=[st for st in statements if st is not None]))
        return widened


def _used_by_address(blocks: dict[tuple[int, int | None], Block], loc, varid: int) -> bool:
    block = blocks[(loc.block_addr, loc.block_idx)]
    stmt = block.statements[loc.stmt_idx]
    finder = _AddressUseFinder(varid)
    finder.walk_statement(stmt, block, loc.stmt_idx)
    return finder.address_uses > 0 and finder.value_uses == 0


class _AddressUseFinder(AILBlockViewer):
    """Count the uses of a vvar inside and outside Reference() in a statement."""

    def __init__(self, varid: int):
        super().__init__()
        self._varid = varid
        self.address_uses = 0
        self.value_uses = 0

    def _handle_UnaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.op == "Reference" and isinstance(expr.operand, VirtualVariable) and expr.operand.varid == self._varid:
            self.address_uses += 1
            return None
        return super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.varid == self._varid:
            self.value_uses += 1


class _VVarWidener(AILBlockRewriter):
    def __init__(self, widened: dict[int, VirtualVariable], manager):
        super().__init__(update_block=False)
        self._widened = widened
        self._manager = manager
        self.changed = False

    def _handle_expr(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None):
        if isinstance(expr, VirtualVariable) and expr.varid in self._widened and expr.bits != 128:
            self.changed = True
            wide = self._widened[expr.varid]
            return VirtualVariable(
                self._manager.next_atom(), wide.varid, wide.bits, wide.category, oident=wide.oident, **expr.tags
            )
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)
