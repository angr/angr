"""
Stack-variable definitions that a read other than a use of the variable may observe.

Stack SSA turns every frame access at a known offset into a virtual variable, so a definition looks dead once none of
its versions is used. A frame slot can still be read without a use: through a load whose address is a frame address
that stack SSA did not resolve (``Load(Load(ctx) + 32)`` with a VM stack pointer in the VM context, ``Load(&v + 4)``,
a load wider than its variable), or by a callee given a pointer into the frame. Dead-store elimination must keep the
definitions such reads may observe.

Which values may be frame addresses is a flow-insensitive analysis. A value is a frame address at a set of offsets
(``StackBaseOffset``, ``&stack_var``, plus or minus constants, also once the sums and Xor chains through SSA
definitions cancel), or otherwise has a mask of bits that may depend on frame address bits: an operation spreads them
the way it spreads bits (masks and narrowing drop them, shifts move them, carries fill them upwards), and a comparison
or a condition-code helper depends in the bits it can set. Such a value can be a frame address only if its bits from
``ADDRESS_BITS`` up depend on one in a single run and no other bit there may be set; this assumes that the frame lies
above the null region and that data computed without frame addresses does not happen to equal one. It keeps a VM's
flags, built from its stack pointer, from counting as pointers.

Memory holds whole values: constant-address cells, frame slots, and what the function stores through other pointers.
Whatever a callee is given it may store anywhere it can reach, which excludes a private VM context, and a callee may copy
whatever it can reach.

A load reads the bytes at the offsets its address may have. A call reads, from each frame address it may obtain, up to
the next frame slot whose address the function takes (the top of the frame if there is none): the callee reaches the
caller's locals only through such pointers, and a stack object extends upwards from its address and does not reach
into another object whose address is taken (the convention variadic_call_reads uses for outgoing arguments). A backward
liveness over frame bytes finds the definitions that reach such a read.

A read through a frame address at an unknown offset may read the whole frame. Counting those (``unknown_reads``) is
sound, but in VM code whose stack pointer the VM encrypts with a rolling key it keeps most stack stores of the function
and slows decompilation several times over, so by default only reads at known offsets count.
"""

from __future__ import annotations

from bisect import bisect_right

from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Call,
    Const,
    Convert,
    DirtyExpression,
    Insert,
    Load,
    Phi,
    StackBaseOffset,
    Tmp,
    UnaryOp,
    VEXCCallExpression,
    VirtualVariable,
)
from angr.ailment.statement import CAS, Assignment, DirtyStatement, Store

# frame offsets a frame address may have before its offset is taken to be unknown
MAX_OFFSETS = 16
# no frame address is below 1 << ADDRESS_BITS
ADDRESS_BITS = 12
# changes of a stored value after which its dependent bits are widened
WIDEN_AFTER = 3


class _Unknown:
    """A frame address at an unknown offset."""

    __slots__ = ()

    def __repr__(self):
        return "UNKNOWN"


UNKNOWN = _Unknown()


def _full(bits: int) -> int:
    return (1 << bits) - 1


def _fill_up(mask: int, bits: int) -> int:
    """Every bit from the lowest set bit of ``mask`` up, within ``bits``."""
    if not mask:
        return 0
    low = (mask & -mask).bit_length() - 1
    return _full(bits) & ~_full(low)


class Val:
    """
    What a value knows of frame addresses: ``offsets`` (None, a frozenset of frame offsets, or UNKNOWN) if it may be a
    frame address, ``dep`` the bits that may depend on frame address bits, ``nz`` the bits that may be nonzero, and
    ``pure`` whether a value with offsets is always such a frame address.
    """

    __slots__ = ("dep", "nz", "offsets", "pure")

    def __init__(self, offsets, dep: int, nz: int, pure: bool = False):
        self.offsets = offsets
        self.dep = dep
        self.nz = nz
        self.pure = pure and offsets is not None

    def __eq__(self, other):
        return (
            isinstance(other, Val)
            and self.offsets == other.offsets
            and self.dep == other.dep
            and self.nz == other.nz
            and self.pure == other.pure
        )

    def __hash__(self):
        return hash((self.offsets, self.dep, self.nz, self.pure))

    def __repr__(self):
        return f"Val({self.offsets}, dep={self.dep:#x}, nz={self.nz:#x}, pure={self.pure})"

    def pointer(self):
        """
        The frame offsets this value may point to, UNKNOWN, or None if it cannot point into the frame: an address
        derived from a frame address has its bits from ADDRESS_BITS up depend on it, in one run, and no other bit there
        may be set.
        """
        if self.offsets is not None:
            return self.offsets
        high = self.dep >> ADDRESS_BITS
        if not high or (self.nz >> ADDRESS_BITS) & ~high or (high + (high & -high)) & high:
            return None
        return UNKNOWN


def _join_offsets(a, b):
    if a is None:
        return b
    if b is None or a is b:
        return a
    if a is UNKNOWN or b is UNKNOWN:
        return UNKNOWN
    u = a | b
    return UNKNOWN if len(u) > MAX_OFFSETS else u


def join(a: Val | None, b: Val | None) -> Val | None:
    """Join of two frame-dependent values; None is a value that does not depend on frame addresses."""
    if a is None:
        return b
    if b is None:
        return a
    return Val(_join_offsets(a.offsets, b.offsets), a.dep | b.dep, a.nz | b.nz, a.pure and b.pure)


def _frame(offsets, bits: int, pure: bool = True) -> Val:
    return Val(offsets, _full(bits), _full(bits), pure)


def _ccall_result_bits(callee: str) -> int | None:
    """The bits a condition-code helper may set, if known."""
    if callee.endswith(("calculate_condition", "calculate_eflags_c", "calculate_rflags_c")):
        return 1
    if callee.endswith(("calculate_eflags_all", "calculate_rflags_all")):
        # CF, PF, AF, ZF, SF, OF
        return 0x8D5
    return None


def _signed(value: int, bits: int) -> int:
    return value - (1 << bits) if value >= 1 << (bits - 1) else value


def _const_int(expr) -> int | None:
    if isinstance(expr, Const) and isinstance(expr.value, int):
        return expr.value
    return None


_FRAME = ("F",)
_LINEAR = frozenset({"Add", "Sub", "Xor"})
# a value that frame addresses cancel out of
_INDEPENDENT = object()


def _lin_parts(form, bits: int) -> tuple[dict, int]:
    if form[0] == "lin" and form[1] == bits:
        return dict(form[2]), form[3]
    return {form: 1}, 0


def _mk_lin(bits: int, terms: dict, const: int):
    mask = _full(bits)
    terms = {t: c & mask for t, c in terms.items() if c & mask}
    const &= mask
    if not const and len(terms) == 1:
        ((term, coeff),) = terms.items()
        if coeff == 1:
            return term
    return ("lin", bits, frozenset(terms.items()), const)


def _xor_parts(form, bits: int) -> tuple[set, int]:
    if form[0] == "xor" and form[1] == bits:
        return set(form[2]), form[3]
    if form[0] == "lin" and form[1] == bits and not form[2]:
        return set(), form[3]
    return {form}, 0


def _mk_xor(bits: int, terms: set, const: int):
    if not terms:
        return ("lin", bits, frozenset(), const)
    if not const and len(terms) == 1:
        return next(iter(terms))
    return ("xor", bits, frozenset(terms), const)


class _Linear:
    """
    Add/Sub/Mul-by-constant chains as sums of terms with coefficients and Xor chains as sets of terms, through the
    definitions of virtual variables (SSA: a variable equals its definition evaluated where it is defined), so that
    terms that cancel drop out. Two loads of the same constant address in one block are the same term when nothing
    between them may write it.
    """

    # deeper definition chains stay opaque terms
    MAX_DEPTH = 32

    def __init__(self, blocks: dict):
        self.blocks = blocks
        self.defs: dict[int, tuple] = {}
        self.tmp_defs: dict[tuple, tuple] = {}
        for key, block in blocks.items():
            for idx, stmt in enumerate(block.statements):
                if isinstance(stmt, Assignment) and not isinstance(stmt.src, Phi):
                    if isinstance(stmt.dst, VirtualVariable):
                        self.defs[stmt.dst.varid] = (stmt.src, key, idx)
                    elif isinstance(stmt.dst, Tmp):
                        self.tmp_defs[(key, stmt.dst.tmp_idx)] = (stmt.src, idx)
        self.memo: dict[int, tuple] = {}
        self._forms: dict = {}
        self._calls = 0
        # term -> (expression, block key, statement index) it stands for
        self.src: dict[tuple, tuple] = {}
        self._writers: dict = {}
        self._opaque = 0

    def _block_writers(self, key) -> list:
        writers = self._writers.get(key)
        if writers is None:
            writers = []
            calls = _CallOperands()
            for idx, stmt in enumerate(self.blocks[key].statements):
                calls.reset()
                calls.walk_statement(stmt)
                if calls.operands or calls.callees or isinstance(stmt, (CAS, DirtyStatement)):
                    writers.append((idx, None, None))
                elif isinstance(stmt, Store):
                    addr = _const_int(stmt.addr)
                    writers.append((idx, addr, None if addr is None else addr + stmt.size))
            self._writers[key] = writers
        return writers

    def _version(self, key, idx: int, lo: int | None, hi: int | None) -> int:
        """The last statement before ``idx`` that may write [lo, hi) (any memory if lo is None), or -1."""
        last = -1
        for w_idx, w_lo, w_hi in self._block_writers(key):
            if w_idx >= idx:
                break
            if w_lo is None or lo is None or (w_lo < hi and lo < w_hi):
                last = w_idx
        return last

    def _term(self, term, expr, key, idx):
        self.src.setdefault(term, (expr, key, idx))
        return term

    def form(self, expr, key, idx: int, depth: int = 0):
        memo_key = (expr, key, idx)
        found = self._forms.get(memo_key)
        if found is None:
            calls = self._calls
            found = self._form(expr, key, idx, depth)
            if self._calls == calls:
                # a call returns a value of its own each time it runs
                self._forms[memo_key] = found
        return found

    def _form(self, expr, key, idx: int, depth: int):
        bits = expr.bits
        if isinstance(expr, Const):
            if isinstance(expr.value, int):
                return ("lin", bits, frozenset(), expr.value & _full(bits))
        elif isinstance(expr, StackBaseOffset):
            if isinstance(expr.offset, int):
                return _mk_lin(bits, {_FRAME: 1}, expr.offset)
        elif isinstance(expr, UnaryOp):
            if expr.op == "Reference" and isinstance(expr.operand, VirtualVariable) and expr.operand.was_stack:
                return _mk_lin(bits, {_FRAME: 1}, expr.operand.stack_offset)
            if expr.op == "Neg":
                terms, const = _lin_parts(self.form(expr.operand, key, idx, depth), bits)
                return _mk_lin(bits, {t: -c for t, c in terms.items()}, -const)
            if expr.op == "Not":
                terms, const = _xor_parts(self.form(expr.operand, key, idx, depth), bits)
                return _mk_xor(bits, terms, const ^ _full(bits))
        elif isinstance(expr, VirtualVariable):
            found = self.defs.get(expr.varid)
            if found is not None and depth < self.MAX_DEPTH and found[0].bits == bits:
                cached = self.memo.get(expr.varid)
                if cached is None:
                    cached = self.form(found[0], found[1], found[2], depth + 1)
                    self.memo[expr.varid] = cached
                return cached
            return self._term(("V", expr.varid), expr, key, idx)
        elif isinstance(expr, Tmp):
            found = self.tmp_defs.get((key, expr.tmp_idx))
            if found is not None and found[1] < idx and depth < self.MAX_DEPTH:
                return self.form(found[0], key, found[1], depth + 1)
        elif isinstance(expr, Load):
            addr = _const_int(expr.addr)
            if addr is not None:
                version = self._version(key, idx, addr, addr + expr.size)
                return self._term(("L", key, addr, expr.size, version), expr, key, idx)
            addr_form = self.form(expr.addr, key, idx, depth)
            version = self._version(key, idx, None, None)
            return self._term(("M", key, addr_form, expr.size, version), expr, key, idx)
        elif isinstance(expr, BinaryOp):
            op = expr.op
            if op in {"Add", "Sub"}:
                left, l_const = _lin_parts(self.form(expr.operands[0], key, idx, depth), bits)
                right, r_const = _lin_parts(self.form(expr.operands[1], key, idx, depth), bits)
                sign = 1 if op == "Add" else -1
                for t, c in right.items():
                    left[t] = left.get(t, 0) + sign * c
                return _mk_lin(bits, left, l_const + sign * r_const)
            if op in {"Mul", "Shl"}:
                scale = _const_int(expr.operands[1])
                other = expr.operands[0]
                if scale is None and op == "Mul":
                    scale, other = _const_int(expr.operands[0]), expr.operands[1]
                if scale is not None and (op == "Mul" or scale < bits):
                    factor = scale if op == "Mul" else 1 << scale
                    terms, const = _lin_parts(self.form(other, key, idx, depth), bits)
                    return _mk_lin(bits, {t: c * factor for t, c in terms.items()}, const * factor)
            if op == "Xor":
                left, l_const = _xor_parts(self.form(expr.operands[0], key, idx, depth), bits)
                right, r_const = _xor_parts(self.form(expr.operands[1], key, idx, depth), bits)
                return _mk_xor(bits, left ^ right, l_const ^ r_const)
        # anything else is a term of its own, unique to this occurrence
        if isinstance(expr, (Call, DirtyExpression)):
            self._calls += 1
        self._opaque += 1
        return self._term(("X", self._opaque), expr, key, idx)



class _FrameValues:
    """
    Flow-insensitive frame-address values of SSA variables, block temporaries and memory.
    """

    def __init__(self, blocks: dict, hidden=None):
        self.blocks = blocks
        # constant addresses no callee can reach
        self.hidden = hidden
        self.vvars: dict[int, Val] = {}
        self.tmps: dict[tuple, Val] = {}
        # constant address -> [(size, value)] of every frame-dependent value stored there
        self.cells: dict[int, list] = {}
        self.cells_value: Val | None = None
        # of the cells a callee can reach
        self.visible_value: Val | None = None
        # frame-dependent values the function stores through other pointers
        self.stored: Val | None = None
        # those a callee may have obtained, and so may have stored anywhere it can reach
        self.escaped: Val | None = None
        # frame offset -> [(size, value)] of every frame-dependent value stored there
        self.slots: dict[int, list] = {}
        # frame-dependent values held in frame slots
        self.frame_value: Val | None = None
        # those stored at frame offsets that are not known
        self.frame_opaque: Val | None = None
        self.has_calls = False
        self._changed = False
        self.linear = _Linear(blocks)
        self._changed_vars: list = []
        self._call_operands: dict = {}
        self._memo: dict = {}
        self._changes: dict = {}
        # blocks in reverse post-order, so that most values are final after one round
        self.order = list(blocks)
        # index of the statement being evaluated in its block
        self.idx = 0

    # values

    def value(self, expr, key) -> Val | None:
        """The frame dependence of ``expr`` evaluated in block ``key``, or None if it has none."""
        # expression trees share subtrees; the memo lives for one statement (see reset_memo)
        memo_key = (expr, key, self.idx)
        try:
            return self._memo[memo_key]
        except KeyError:
            pass
        handler = _HANDLERS.get(expr.pykind)
        v = self._opaque(expr, key) if handler is None else handler(self, expr, key)
        self._memo[memo_key] = v
        return v

    def reset_memo(self) -> None:
        self._memo = {}

    def _v_const(self, expr, key):
        return None

    def _v_stack_base_offset(self, expr, key):
        return _frame(frozenset((expr.offset,)) if isinstance(expr.offset, int) else UNKNOWN, expr.bits)

    def _v_vvar(self, expr, key):
        return self.vvars.get(expr.varid)

    def _v_tmp(self, expr, key):
        return self.tmps.get((key, expr.tmp_idx))

    def _v_binop(self, expr, key):
        v = self._binop(expr, key)
        if v is not None and expr.op in _LINEAR and v.pointer() is UNKNOWN:
            # a pointer whose offset its normal form may still pin down
            exact = self._exact(expr, key)
            if exact is not None:
                return None if exact is _INDEPENDENT else _frame(exact, expr.bits)
        return v

    def _v_unop(self, expr, key):
        if expr.op == "Reference":
            operand = expr.operand
            if isinstance(operand, VirtualVariable):
                return _frame(frozenset((operand.stack_offset,)), expr.bits) if operand.was_stack else None
            return _frame(UNKNOWN, expr.bits)
        v = self.value(expr.operand, key)
        if v is None:
            return None
        if expr.op == "Not":
            return Val(None, v.dep, _full(expr.bits))
        return Val(None, _fill_up(v.dep, expr.bits), _full(expr.bits))

    def _v_load(self, expr, key):
        return self.load_value(expr, key)

    def _v_call(self, expr, key):
        if isinstance(expr.target, str):
            # an intrinsic returns what its operands or the memory they point to hold
            return self._fit(join(self.callee_visible(), join(self.cells_value, self.frame_value)), expr.bits)
        self.has_calls = True
        return self._fit(self.escaped, expr.bits)

    def _v_phi(self, expr, key):
        v = None
        for _, vvar in expr.src_and_vvars:
            if vvar is not None:
                v = join(v, self.vvars.get(vvar.varid))
        return v

    def _v_ite(self, expr, key):
        t, f = self.value(expr.iftrue, key), self.value(expr.iffalse, key)
        v = join(t, f)
        cond = self.value(expr.cond, key)
        if cond is not None and cond.dep:
            # the selection depends on frame address bits, in the bits where the two values may differ
            differ = self._nz(expr.iftrue, t) | self._nz(expr.iffalse, f)
            v = join(v, Val(None, differ, differ))
        return v

    def _v_ccall(self, expr, key):
        v = self._opaque(expr, key)
        # renamed ccalls keep their VEX helper in a tag
        callee = expr.tags.get("vex_callee", expr.callee) if expr.callee == "_ccall" else expr.callee
        flags = _ccall_result_bits(callee)
        if v is None or flags is None:
            return v
        return Val(None, flags if v.dep else 0, flags)

    def callee_visible(self) -> Val | None:
        """What a callee may find in memory: the cells it can reach, and frame slots once it may hold a frame address."""
        v = join(join(self.escaped, self.stored), self.visible_value)
        if v is not None and v.pointer() is not None:
            v = join(v, self.frame_value)
        return v

    def _term_value(self, term) -> Val | None:
        if term == _FRAME:
            return _frame(frozenset((0,)), 64)
        if term[0] in ("lin", "xor"):
            # a sum or Xor chain at another width
            exact = self._exact_form(term)
            if exact is _INDEPENDENT:
                return None
            return Val(None, _full(term[1]), _full(term[1])) if exact is None else _frame(exact, term[1])
        expr, key, idx = self.linear.src[term]
        saved, self.idx = self.idx, idx
        try:
            return self.value(expr, key)
        finally:
            self.idx = saved

    def _exact(self, expr, key):
        """
        Frame offsets of an address that its normal form makes exact, _INDEPENDENT if frame addresses cancel out of
        it, or None.
        """
        return self._exact_form(self.linear.form(expr, key, self.idx), expr.bits)

    def _exact_form(self, form, bits: int | None = None):
        if bits is None:
            bits = form[1]
        mask = _full(bits)
        if form[0] == "xor" and form[1] == bits:
            if all(self._term_value(t) is None for t in form[2]):
                return _INDEPENDENT
            return None
        terms, const = _lin_parts(form, bits)
        frame_coeff = 0
        offsets = {const}
        for term, coeff in terms.items():
            if term == _FRAME:
                frame_coeff += coeff
                continue
            v = self._term_value(term)
            if v is None:
                # a frame-independent term leaves the offset unknown
                offsets = None
                continue
            if v.offsets is None or v.offsets is UNKNOWN or not v.pure:
                return None
            frame_coeff += coeff
            if offsets is not None:
                offsets = {(o + coeff * x) & mask for o in offsets for x in v.offsets}
                if len(offsets) > MAX_OFFSETS:
                    return None
        frame_coeff &= mask
        if frame_coeff == 0:
            return _INDEPENDENT
        if frame_coeff == 1 and offsets is not None:
            return frozenset(_signed(o, bits) for o in offsets)
        return None

    @staticmethod
    def _fit(v: Val | None, bits: int) -> Val | None:
        """A value read back at ``bits`` bits from where it was stored."""
        if v is None:
            return None
        if v.offsets is not None:
            # a narrower read of an address keeps no offset
            return _frame(v.offsets, bits, v.pure) if bits >= 32 else Val(None, _full(bits), _full(bits))
        return Val(None, v.dep & _full(bits), v.nz & _full(bits))

    def _opaque(self, expr, key) -> Val | None:
        # any frame-dependent operand may affect every bit
        walker = _Operands(self, key)
        walker.walk_operands(expr)
        if walker.value is None:
            return None
        bits = expr.bits
        return Val(None, _full(bits) if walker.value.dep else 0, _full(bits))

    def _nz(self, expr, v: Val | None) -> int:
        # bits of an operand that may be nonzero
        if v is not None:
            return v.nz
        c = _const_int(expr)
        if c is not None:
            return c
        if isinstance(expr, BinaryOp) and expr.op.startswith("Cmp"):
            return 1
        if isinstance(expr, Convert) and expr.from_bits == 1 and not expr.is_signed:
            return 1
        if isinstance(expr, BinaryOp) and expr.op == "And":
            for operand in expr.operands:
                c = _const_int(operand)
                if c is not None:
                    return c
        return _full(expr.bits)

    def _binop(self, expr: BinaryOp, key) -> Val | None:
        op = expr.op
        a_expr, b_expr = expr.operands
        a = self.value(a_expr, key)
        b = self.value(b_expr, key)
        if a is None and b is None:
            return None
        bits = expr.bits
        full = _full(bits)
        if op.startswith("Cmp"):
            return Val(None, 1, 1)
        if op in {"Add", "Sub"}:
            c_b = _const_int(b_expr)
            if a is not None and a.offsets is not None and b is None and c_b is not None:
                delta = _signed(c_b, bits)
                return _frame(_shift(a.offsets, delta if op == "Add" else -delta), bits, a.pure)
            c_a = _const_int(a_expr)
            if op == "Add" and b is not None and b.offsets is not None and a is None and c_a is not None:
                return _frame(_shift(b.offsets, _signed(c_a, bits)), bits, b.pure)
            if op == "Sub" and a is not None and b is not None and a.offsets is not None and b.offsets is not None:
                # the distance between two frame addresses; a constant when both offsets are known
                if a.pure and b.pure and a.offsets is not UNKNOWN and b.offsets is not UNKNOWN:
                    return None
                return Val(None, full, full)
        na, nb = self._nz(a_expr, a), self._nz(b_expr, b)
        da = a.dep if a is not None else 0
        db = b.dep if b is not None else 0
        if op == "And":
            return Val(None, (da & nb) | (db & na), na & nb)
        if op in {"Or", "Xor"}:
            return Val(None, da | db, na | nb)
        if op in {"Add", "Sub"}:
            # the frame-dependent bits spread upwards by carries
            dep = da | db
            nz = _full(min((na | nb).bit_length() + 1, bits)) if op == "Add" else full
            return Val(None, _fill_up(dep, bits) & _full(min(dep.bit_length() + 1, bits)), nz)
        if op == "Mul":
            c = _const_int(b_expr) if b is None else _const_int(a_expr) if a is None else None
            if c is not None:
                other_n, other_d = (na, da) if b is None else (nb, db)
                if other_n == 1:
                    # a truth value times a constant
                    return Val(None, c & full if other_d else 0, c & full)
                if c and c & (c - 1) == 0:
                    shift = c.bit_length() - 1
                    return Val(None, (other_d << shift) & full, (other_n << shift) & full)
            return Val(None, _fill_up(da | db, bits), full)
        if op in {"Shl", "Shr", "Sar"}:
            amount = _const_int(b_expr)
            if amount is not None and db == 0:
                if op == "Shl":
                    return Val(None, (da << amount) & full, (na << amount) & full)
                if op == "Shr" or not (na >> (bits - 1)) & 1:
                    return Val(None, da >> amount, na >> amount)
            if op == "Shr":
                # never more than the shifted value
                span = _full(na.bit_length())
                return Val(None, span, span)
            return Val(None, full, full)
        if op in {"Div", "Mod"} and not expr.signed:
            span = _full(na.bit_length() if op == "Div" else min(na.bit_length(), nb.bit_length()))
            return Val(None, span, span)
        return Val(None, full, full)

    def _convert(self, expr: Convert, key) -> Val | None:
        v = self.value(expr.operand, key)
        if v is None:
            return None
        to_bits, from_bits = expr.to_bits, expr.from_bits
        if to_bits >= from_bits:
            if v.offsets is not None:
                return _frame(v.offsets, to_bits, v.pure)
            if expr.is_signed and (v.nz >> (from_bits - 1)) & 1:
                ext = _full(to_bits) & ~_full(from_bits)
                return Val(None, v.dep | (ext if (v.dep >> (from_bits - 1)) & 1 else 0), v.nz | ext)
            return Val(None, v.dep, v.nz)
        # a truncated address no longer has a known offset
        mask = _full(to_bits)
        return Val(None, v.dep & mask, v.nz & mask)

    def _insert(self, expr, key) -> Val | None:
        base = self.value(expr.base, key)
        value = self.value(expr.value, key)
        if base is None and value is None:
            return None
        bits = expr.bits
        offset = _const_int(expr.offset)
        if offset is None or expr.endness != "Iend_LE":
            return Val(None, _full(bits), _full(bits))
        field = (_full(expr.value.bits) << (offset * 8)) & _full(bits)
        base_dep = base.dep if base is not None else 0
        base_nz = base.nz if base is not None else _full(bits)
        value_dep = value.dep if value is not None else 0
        value_nz = value.nz if value is not None else _full(expr.value.bits)
        return Val(
            None,
            (base_dep & ~field) | ((value_dep << (offset * 8)) & field),
            (base_nz & ~field) | ((value_nz << (offset * 8)) & field),
        )

    def load_value(self, load: Load, key) -> Val | None:
        bits = load.bits
        addr = _const_int(load.addr)
        if addr is not None:
            # a callee cannot reach a hidden cell
            v = self.stored if self.hidden is not None and self.hidden(addr) else join(self.stored, self.escaped)
            return join(self._fit(v, bits), self._read_cells(self.cells, addr, load.size))
        av = self.value(load.addr, key)
        pointer = None if av is None else av.pointer()
        if pointer is None:
            # not into the frame
            return self._fit(join(join(self.stored, self.escaped), self.cells_value), bits)
        if pointer is UNKNOWN:
            return self._fit(join(join(self.stored, self.escaped), join(self.cells_value, self.frame_value)), bits)
        v = self._fit(join(self.escaped, self.frame_opaque), bits)
        for offset in pointer:
            v = join(v, self._read_cells(self.slots, offset, load.size))
        return v

    def _read_cells(self, table: dict, addr: int, size: int) -> Val | None:
        v = None
        for cell_addr, entries in table.items():
            for cell_size, value in entries:
                if cell_addr < addr + size and addr < cell_addr + cell_size:
                    v = join(v, self._cell_bits(value, cell_size, cell_addr - addr, size))
        return v

    def _cell_bits(self, value: Val, size: int, delta: int, load_size: int) -> Val:
        # the bits of a value stored ``delta`` bytes above the loaded address that the load reads (little-endian)
        if delta == 0 and size == load_size:
            return value
        bits = load_size * 8
        dep, nz = (_full(size * 8), _full(size * 8)) if value.offsets is not None else (value.dep, value.nz)
        if delta >= 0:
            dep, nz = dep << (8 * delta), nz << (8 * delta)
        else:
            dep, nz = dep >> (-8 * delta), nz >> (-8 * delta)
        return Val(None, dep & _full(bits), nz & _full(bits))

    # fixpoint

    def _widened(self, k, old: Val | None, new: Val) -> Val:
        # after a few changes, carries that creep up one bit per round fill all the bits the value may have, and
        # offsets that keep growing (a pointer stepping through a loop) become unknown
        if old is None:
            return new
        count = self._changes[k] = self._changes.get(k, 0) + 1
        if count < WIDEN_AFTER:
            return new
        offsets = new.offsets
        if offsets is not None and offsets is not UNKNOWN and old.offsets is not None and offsets != old.offsets:
            offsets = UNKNOWN
        return Val(offsets, _fill_up(new.dep, new.nz.bit_length()), new.nz, new.pure)

    def _update(self, table: dict, k, v: Val | None) -> None:
        if v is None:
            return
        old = table.get(k)
        new = join(old, v)
        if new != old:
            table[k] = self._widened((id(table), k), old, new)
            self._changed_vars.append(k)

    def _add_to(self, attr: str, v: Val | None) -> None:
        if v is None:
            return
        old = getattr(self, attr)
        new = join(old, v)
        if new != old:
            setattr(self, attr, self._widened(attr, old, new))
            self._changed = True

    def _put(self, table: dict, addr: int, size: int, data_v: Val) -> None:
        entries = table.setdefault(addr, [])
        for i, (s, value) in enumerate(entries):
            if s == size:
                new = join(value, data_v)
                if new != value:
                    entries[i] = (s, self._widened((id(table), addr, size), value, new))
                    self._changed = True
                return
        entries.append((size, data_v))
        self._changed = True

    def _store(self, addr_expr, data_v: Val | None, size: int, key) -> None:
        if data_v is None:
            return
        addr = _const_int(addr_expr)
        if addr is not None:
            self._put(self.cells, addr, size, data_v)
            self._add_to("cells_value", data_v)
            if self.hidden is None or not self.hidden(addr):
                self._add_to("visible_value", data_v)
            return
        av = self.value(addr_expr, key)
        pointer = None if av is None else av.pointer()
        if pointer is None:
            self._add_to("stored", data_v)
            return
        self._add_to("frame_value", data_v)
        if pointer is UNKNOWN:
            self._add_to("frame_opaque", data_v)
            self._add_to("stored", data_v)
            return
        for offset in pointer:
            self._put(self.slots, offset, size, data_v)

    def solve(self) -> None:
        collector = _CallOperands()
        while True:
            self._changed = False
            self._changed_vars = []
            for key in self.order:
                for idx, stmt in enumerate(self.blocks[key].statements):
                    self.idx = idx
                    self._memo = {}
                    self._visit(stmt, key, collector)
            if self.has_calls:
                # a callee may copy any value it can reach
                self._add_to("escaped", self.callee_visible())
            if not self._changed and not self._changed_vars:
                break

    def _visit(self, stmt, key, collector: _CallOperands) -> None:
        if isinstance(stmt, Assignment):
            v = self.value(stmt.src, key)
            dst = stmt.dst
            if isinstance(dst, VirtualVariable):
                self._update(self.vvars, dst.varid, v)
                if dst.was_stack and v is not None and not isinstance(stmt.src, Phi):
                    self._add_to("frame_value", v)
                    self._put(self.slots, dst.stack_offset, dst.size, v)
            elif isinstance(dst, Tmp):
                self._update(self.tmps, (key, dst.tmp_idx), v)
            else:
                self._add_to("stored", v)
        elif isinstance(stmt, Store):
            self._store(stmt.addr, self.value(stmt.data, key), stmt.size, key)
        elif isinstance(stmt, CAS):
            for data in (stmt.data_lo, stmt.data_hi):
                if data is not None:
                    self._store(stmt.addr, self.value(data, key), stmt.data_lo.size, key)
        # whatever a callee is given it may store anywhere
        found = self._call_operands.get((key, self.idx))
        if found is None:
            collector.reset()
            collector.walk_statement(stmt)
            found = (collector.operands, collector.callees or isinstance(stmt, DirtyStatement))
            self._call_operands[(key, self.idx)] = found
        operands, callees = found
        if callees:
            self.has_calls = True
        for operand in operands:
            self._add_to("escaped", self.value(operand, key))


# expression kind -> handler
_HANDLERS = {
    kind: handler
    for marker, handler in (
        (Const, _FrameValues._v_const),
        (StackBaseOffset, _FrameValues._v_stack_base_offset),
        (VirtualVariable, _FrameValues._v_vvar),
        (Tmp, _FrameValues._v_tmp),
        (BinaryOp, _FrameValues._v_binop),
        (UnaryOp, _FrameValues._v_unop),
        (Convert, _FrameValues._convert),
        (Load, _FrameValues._v_load),
        (Call, _FrameValues._v_call),
        (Phi, _FrameValues._v_phi),
        (ITE, _FrameValues._v_ite),
        (Insert, _FrameValues._insert),
        (VEXCCallExpression, _FrameValues._v_ccall),
    )
    # Call also matches macros, which stay opaque
    for kind in ((int(marker._kind),) if marker is Call else marker._match_kind_ints)
}


class _Operands(AILBlockViewer):
    """Joins the values of the immediate operands of an expression."""

    def __init__(self, values: _FrameValues, key):
        super().__init__()
        self.values = values
        self.key = key
        self.value: Val | None = None
        self._top_expr = None

    def walk_operands(self, expr) -> None:
        self._top_expr = expr
        self._handle_expr(0, expr, 0, None, None)

    def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr is self._top_expr:
            self._top_expr = None
            return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)
        self.value = join(self.value, self.values.value(expr, self.key))
        return None


class _CallOperands(AILBlockViewer):
    """The operands of every call and dirty helper in a statement."""

    def __init__(self):
        super().__init__()
        self.operands: list = []
        # calls of code other than intrinsics, and dirty helpers
        self.callees = 0

    def reset(self):
        self.operands = []
        self.callees = 0

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        if not isinstance(expr.target, str):
            self.operands.append(expr.target)
            self.callees += 1
        self.operands.extend(expr.args or ())
        super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_DirtyExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        self.operands.extend(expr.operands)
        self.callees += 1
        super()._handle_DirtyExpression(expr_idx, expr, stmt_idx, stmt, block)


class _Reads(AILBlockViewer):
    """The frame reads of a statement that are not uses of a stack variable."""

    def __init__(self, values: _FrameValues, key):
        super().__init__()
        self.values = values
        self.key = key
        # (offset, size) of each exact read; (offset, None) reads the frame at and above offset
        self.reads: list[tuple[int, int | None]] = []
        self.all = False

    def _read(self, v: Val | None, size: int | None) -> None:
        offsets = None if v is None else v.pointer()
        if offsets is None:
            return
        if offsets is UNKNOWN:
            self.all = True
        else:
            # a size of None reads the object at the offset (see frame_read_vvars)
            self.reads.extend((o, size) for o in offsets)

    def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
        self._read(self.values.value(expr.addr, self.key), expr.size)
        super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_CAS(self, stmt_idx, stmt, block):
        self._read(self.values.value(stmt.addr, self.key), stmt.data_lo.size)
        super()._handle_CAS(stmt_idx, stmt, block)

    def _callee_reads(self, operands, memory: bool = True) -> None:
        values = self.values
        # a callee may also use the frame addresses memory holds; an intrinsic only accesses its operands
        v = values.callee_visible() if memory else None
        for operand in operands:
            v = join(v, values.value(operand, self.key))
        self._read(v, None)

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        operands = list(expr.args or ())
        if not isinstance(expr.target, str):
            operands.append(expr.target)
        self._callee_reads(operands, memory=not isinstance(expr.target, str))
        super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_DirtyExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        self._callee_reads(expr.operands)
        super()._handle_DirtyExpression(expr_idx, expr, stmt_idx, stmt, block)


class _AddressTaken(AILBlockViewer):
    """Frame offsets whose address the function takes."""

    def __init__(self):
        super().__init__()
        self.offsets: set[int] = set()

    def _handle_StackBaseOffset(self, expr_idx, expr, stmt_idx, stmt, block):
        if isinstance(expr.offset, int):
            self.offsets.add(expr.offset)

    def _handle_UnaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        operand = expr.operand
        if expr.op == "Reference" and isinstance(operand, VirtualVariable):
            if operand.was_stack:
                self.offsets.add(operand.stack_offset)
            return
        super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)


def _shift(offsets, delta: int):
    if offsets is UNKNOWN:
        return offsets
    return frozenset(o + delta for o in offsets)


def _reverse_post_order(blocks: dict, succs: dict) -> list:
    has_pred = {succ for ss in succs.values() for succ in ss}
    roots = [key for key in blocks if key not in has_pred] + list(blocks)
    seen: set = set()
    post: list = []
    for root in roots:
        if root in seen:
            continue
        seen.add(root)
        stack = [(root, iter(succs.get(root, ())))]
        while stack:
            node, it = stack[-1]
            for succ in it:
                if succ in blocks and succ not in seen:
                    seen.add(succ)
                    stack.append((succ, iter(succs.get(succ, ()))))
                    break
            else:
                stack.pop()
                post.append(node)
    return post[::-1]


def _stack_def(stmt):
    if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_stack:
        return stmt.dst
    return None


def frame_read_vvars(blocks: dict, succs: dict, hidden=None, unknown_reads: bool = False) -> set[int]:
    """
    Stack variables whose definition reaches a frame read that is not a use of a stack variable.

    :param blocks:  Block key -> block.
    :param succs:   Block key -> successor block keys.
    :param hidden:  Whether a constant address is out of every callee's reach (a private VM context), or None.
    :param unknown_reads: Also count reads through pointers into the frame at unknown offsets, which read all of it.
    :return:        Ids of the stack variables to keep.
    """
    defs = [d for block in blocks.values() for d in map(_stack_def, block.statements) if d is not None]
    if not defs:
        return set()
    values = _FrameValues(blocks, hidden)
    values.order = _reverse_post_order(blocks, succs)
    values.solve()

    reads_at: dict = {}
    for key, block in blocks.items():
        for stmt_idx, stmt in enumerate(block.statements):
            values.idx = stmt_idx
            values.reset_memo()
            reads = _Reads(values, key)
            reads.walk_statement(stmt)
            if not unknown_reads:
                reads.all = False
            if reads.all or reads.reads:
                reads_at[(key, stmt_idx)] = (reads.all, reads.reads)
    if not reads_at:
        return set()

    # a stack object a callee is given ends below the next frame slot whose address the function takes
    taken = _AddressTaken()
    for block in blocks.values():
        taken.walk(block)
    starts = sorted(taken.offsets)
    for loc, (read_all, reads) in reads_at.items():
        bounded = []
        for off, size in reads:
            if size is None:
                end = starts[bisect_right(starts, off)] if bisect_right(starts, off) < len(starts) else None
                if end is not None:
                    size = end - off
            bounded.append((off, size))
        reads_at[loc] = (read_all, bounded)

    # frame bytes are tracked in segments between the boundaries of every interval involved
    points = {p for d in defs for p in (d.stack_offset, d.stack_offset + d.size)}
    for _, reads in reads_at.values():
        for off, size in reads:
            points.add(off)
            if size is not None:
                points.add(off + size)
    points = sorted(points)
    index = {p: i for i, p in enumerate(points)}
    lo, hi = points[0], points[-1]

    def mask(start: int, end: int) -> int:
        start, end = max(start, lo), min(end, hi)
        if start >= end:
            return 0
        return ((1 << (index[end] - index[start])) - 1) << index[start]

    everything = mask(lo, hi)
    gen: dict = {}
    for loc, (read_all, reads) in reads_at.items():
        if read_all:
            gen[loc] = everything
            continue
        m = 0
        for off, size in reads:
            m |= mask(off, hi if size is None else off + size)
        if m:
            gen[loc] = m

    preds: dict = {key: [] for key in blocks}
    for key, ss in succs.items():
        for succ in ss:
            if succ in preds and key in blocks:
                preds[succ].append(key)

    kept: set[int] = set()

    def transfer(key, live: int, final: bool) -> int:
        block = blocks[key]
        for stmt_idx in range(len(block.statements) - 1, -1, -1):
            stmt = block.statements[stmt_idx]
            dst = _stack_def(stmt)
            if dst is not None:
                written = mask(dst.stack_offset, dst.stack_offset + dst.size)
                if final and live & written:
                    kept.add(dst.varid)
                if not isinstance(stmt.src, Phi):
                    # a phi passes the earlier definitions through
                    live &= ~written
            live |= gen.get((key, stmt_idx), 0)
        return live

    def live_out(key) -> int:
        out = 0
        for succ in succs.get(key, ()):
            out |= live_in.get(succ, 0)
        return out

    live_in = dict.fromkeys(blocks, 0)
    worklist = list(blocks)
    in_worklist = set(worklist)
    while worklist:
        key = worklist.pop()
        in_worklist.discard(key)
        new_in = transfer(key, live_out(key), False)
        if new_in != live_in[key]:
            live_in[key] = new_in
            for pred in preds[key]:
                if pred not in in_worklist:
                    worklist.append(pred)
                    in_worklist.add(pred)
    for key in blocks:
        transfer(key, live_out(key), True)
    return kept
