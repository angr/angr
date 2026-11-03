from __future__ import annotations

from collections.abc import Callable, Mapping

from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Const,
    Convert,
    Expression,
    Insert,
    Phi,
    Tmp,
    UnaryOp,
    VEXCCallExpression,
    VirtualVariable,
)
from angr.analyses.decompiler.ccall_rewriters.flags_word import flag_bits, flags_word_ccall, flags_word_support
from angr.utils.ail import BlockDefs, GraphVVarDefs

from .base import PeepholeOptimizationExprBase
from .masked_insert import _insert_shift

_MAX_DEPTH = 24

KnownBits = tuple[int, int]
Resolver = Callable[[VirtualVariable, int], KnownBits]


def _mask(bits: int) -> int:
    return (1 << bits) - 1


def known_bits(
    expr: Expression, resolve: Resolver | None = None, depth: int = 0, tmps: Mapping[int, Expression] | None = None
) -> KnownBits:
    """
    (known zeros, known ones) of ``expr``: bits that are 0, resp. 1, whatever the free variables hold. ``resolve`` maps
    a virtual variable to the known bits of its (single) definition; ``tmps`` are the Tmp definitions of the block
    ``expr`` is evaluated in.
    """
    full = _mask(expr.bits)
    if depth > _MAX_DEPTH:
        return 0, 0
    if isinstance(expr, Const):
        if not isinstance(expr.value, int):
            return 0, 0
        c = expr.value_int & full
        return full & ~c, c
    if isinstance(expr, VirtualVariable):
        return resolve(expr, depth + 1) if resolve is not None else (0, 0)
    if isinstance(expr, Tmp):
        src = tmps.get(expr.tmp_idx) if tmps is not None else None
        if src is None or src.bits != expr.bits:
            return 0, 0
        return known_bits(src, resolve, depth + 1, tmps)
    if isinstance(expr, Convert):
        if expr.from_type != Convert.TYPE_INT or expr.to_type != Convert.TYPE_INT:
            return 0, 0
        z, o = known_bits(expr.operand, resolve, depth + 1, tmps)
        if expr.to_bits <= expr.from_bits:
            return z & full, o & full
        low = _mask(expr.from_bits)
        z, o = z & low, o & low
        high = full & ~low
        if not expr.is_signed:
            return z | high, o
        sign = 1 << (expr.from_bits - 1)
        if z & sign:
            return z | high, o
        if o & sign:
            return z, o | high
        return z, o
    if isinstance(expr, UnaryOp) and expr.op == "BitwiseNeg" and expr.operand.bits == expr.bits:
        z, o = known_bits(expr.operand, resolve, depth + 1, tmps)
        return o, z
    if isinstance(expr, VEXCCallExpression):
        split = flags_word_ccall(expr)
        if split is None:
            return 0, 0
        support = flags_word_support(*split)
        if support is None:
            # COPY: the stored flags, masked to the modelled ones
            z, o = known_bits(expr.operands[1], resolve, depth + 1, tmps)
            support = flag_bits(split[0])
            return (z | ~support) & full, o & support
        return full & ~support, 0
    if isinstance(expr, ITE):
        if expr.cond.bits == 1:
            zc, oc = known_bits(expr.cond, resolve, depth + 1, tmps)
            if zc & 1:
                return known_bits(expr.iffalse, resolve, depth + 1, tmps)
            if oc & 1:
                return known_bits(expr.iftrue, resolve, depth + 1, tmps)
        z0, o0 = known_bits(expr.iftrue, resolve, depth + 1, tmps)
        z1, o1 = known_bits(expr.iffalse, resolve, depth + 1, tmps)
        return z0 & z1, o0 & o1
    if isinstance(expr, Insert):
        shift = _insert_shift(expr)
        if shift is None:
            return 0, 0
        hole = _mask(expr.value.bits) << shift
        zb, ob = known_bits(expr.base, resolve, depth + 1, tmps)
        zv, ov = known_bits(expr.value, resolve, depth + 1, tmps)
        return (zb & ~hole) | (zv << shift), (ob & ~hole) | (ov << shift)
    if isinstance(expr, BinaryOp) and not expr.floating_point and not expr.vector_count:
        op0, op1 = expr.operands
        if expr.op == "Concat":
            z0, o0 = known_bits(op0, resolve, depth + 1, tmps)
            z1, o1 = known_bits(op1, resolve, depth + 1, tmps)
            return (z0 << op1.bits) | z1, (o0 << op1.bits) | o1
        if expr.op in {"CmpEQ", "CmpNE"} and expr.bits == 1 and op1.bits == op0.bits:
            z0, o0 = known_bits(op0, resolve, depth + 1, tmps)
            z1, o1 = known_bits(op1, resolve, depth + 1, tmps)
            if (z0 & o1) | (o0 & z1):
                differ = True
            elif (z0 | o0) == (z1 | o1) == _mask(op0.bits):
                differ = False
            else:
                return 0, 0
            return (0, 1) if differ == (expr.op == "CmpNE") else (1, 0)
        if op0.bits != expr.bits:
            return 0, 0
        if expr.op in {"And", "Or", "Xor", "Add"} and op1.bits == expr.bits:
            z0, o0 = known_bits(op0, resolve, depth + 1, tmps)
            z1, o1 = known_bits(op1, resolve, depth + 1, tmps)
            if expr.op == "And":
                return z0 | z1, o0 & o1
            if expr.op == "Or":
                return z0 & z1, o0 | o1
            if expr.op == "Add":
                if (z0 | z1) & full != full:
                    # a carry may come out of some bit position
                    return 0, 0
                # no bit is set in both operands: nothing carries, the sum is the disjunction
                return z0 & z1, o0 | o1
            k = (z0 | o0) & (z1 | o1)
            return k & ~(o0 ^ o1), k & (o0 ^ o1)
        if expr.op in {"Shl", "Shr", "Mul"}:
            amount = op1.value_int if isinstance(op1, Const) and isinstance(op1.value, int) else None
            if expr.op == "Mul":
                if amount is None or amount <= 0 or amount & (amount - 1):
                    return 0, 0
                amount = amount.bit_length() - 1
            if amount is None or amount >= expr.bits:
                return 0, 0
            z, o = known_bits(op0, resolve, depth + 1, tmps)
            if expr.op == "Shr":
                return (z >> amount) | (full & ~(full >> amount)), o >> amount
            return ((z << amount) | _mask(amount)) & full, (o << amount) & full
    return 0, 0


_MAX_PHI_ROUNDS = 32
# vvar definitions followed in one chain; each definition gets its own expression depth
_MAX_HOPS = 64


class _PhiNotReady(Exception):
    pass


def _meet(a: KnownBits | None, b: KnownBits) -> KnownBits:
    return b if a is None else (a[0] & b[0], a[1] & b[1])


class _DefResolver:
    """
    Known bits of vvars through their definitions, memoized per vvar unless a result was cut short by the hop limit.
    ``lookup`` gives (definition, its block's Tmps) or a precomputed result for a vvar.
    Cut-short results are kept for this resolver only, with the hop count they were computed at: without them, every
    path to a vvar past the hop limit re-walks it, exponential in the hops.
    """

    __slots__ = ("busy", "lookup", "memo", "partial", "truncated")

    def __init__(self, lookup, memo: dict[int, KnownBits]):
        self.lookup = lookup
        self.memo = memo
        # varid -> (cut-short result, hops in use when it was computed)
        self.partial: dict[int, tuple[KnownBits, int]] = {}
        self.busy: set[int] = set()
        self.truncated = False

    def __call__(self, vvar: VirtualVariable, depth: int) -> KnownBits:
        varid = vvar.varid
        if varid in self.memo:
            return self.memo[varid]
        found = self.lookup(vvar)
        if found is None:
            return 0, 0
        if not isinstance(found[0], Expression):
            return found
        src, tmps = found
        if src.bits != vvar.bits:
            return 0, 0
        if varid in self.busy or len(self.busy) >= _MAX_HOPS:
            self.truncated = True
            return 0, 0
        hops = len(self.busy)
        part = self.partial.get(varid)
        if part is not None and part[1] <= hops:
            # computed with at least the hop budget left now
            self.truncated = True
            return part[0]
        outer, self.truncated = self.truncated, False
        self.busy.add(varid)
        try:
            r = known_bits(src, self, 0, tmps)
        finally:
            self.busy.discard(varid)
        if self.truncated:
            self.partial[varid] = r, hops
        else:
            self.memo[varid] = r
        self.truncated |= outer
        return r


def phi_known_bits(graph: GraphVVarDefs) -> dict[int, KnownBits]:
    """
    Known bits of every phi-defined vvar: a descending fixpoint where each phi is the meet of its sources, starting
    from the sources that do not (yet) depend on an unsolved phi. At the fixpoint every phi is implied by all of its
    sources, so it holds on every path, around loops too.
    """
    if graph.phi_known_bits is not None:
        return graph.phi_known_bits
    phis = graph.phi_sources()
    state: dict[int, KnownBits | None] = dict.fromkeys(phis)

    def lookup(vvar: VirtualVariable):
        if vvar.varid in state:
            kb = state[vvar.varid]
            if kb is None:
                raise _PhiNotReady
            return kb
        return graph.definition(vvar.varid)

    for _ in range(_MAX_PHI_ROUNDS):
        resolve = _DefResolver(lookup, {})
        changed = False
        for varid, (bits, srcs) in phis.items():
            acc = state[varid]
            for src in srcs:
                if src is None or src.bits != bits:
                    kb = (0, 0)
                elif src.varid == varid:
                    continue
                else:
                    try:
                        kb = resolve(src, 0)
                    except _PhiNotReady:
                        resolve.busy.clear()
                        resolve.truncated = False
                        continue
                acc = _meet(acc, kb)
            if acc != state[varid]:
                state[varid] = acc
                changed = True
        if changed:
            continue
        unsolved = [varid for varid, kb in state.items() if kb is None]
        if not unsolved:
            break
        # phis that only depend on unsolved phis know nothing
        for varid in unsolved:
            state[varid] = (0, 0)
    else:
        state = dict.fromkeys(phis, (0, 0))
    graph.phi_known_bits = {varid: kb if kb is not None else (0, 0) for varid, kb in state.items()}
    return graph.phi_known_bits


def block_defs_resolver(block_defs: BlockDefs | None) -> Resolver | None:
    """Known bits of a vvar from its definition: block-local ones first, then the whole graph's (phis included)."""
    if block_defs is None:
        return None
    graph = block_defs.all_defs

    def lookup(vvar: VirtualVariable):
        src = block_defs.vvars.get(vvar.varid)
        if src is not None and not isinstance(src, Phi):
            return src, block_defs.tmps
        if graph is None:
            return None
        d = graph.definition(vvar.varid)
        if d is not None:
            return d
        return phi_known_bits(graph).get(vvar.varid)

    return _DefResolver(lookup, graph.known_bits_memo if graph is not None else {})


class KnownBitsAndMask(PeepholeOptimizationExprBase):
    """
    ``x & C`` ==> the constant it always is, when every bit of ``C`` is known in ``x`` -- seeing through the
    definitions of virtual variables. A devirtualized VM tests flags of a packed flags word it built itself, e.g. the
    overflow bit of a word whose overflow position is a constant 0.
    """

    __slots__ = ()

    NAME = "x & C => constant for known bits"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, *, block_defs: BlockDefs | None = None, **kwargs):
        if expr.op != "And" or expr.floating_point or expr.vector_count:
            return None
        op0, op1 = expr.operands
        if isinstance(op0, Const) and not isinstance(op1, Const):
            op0, op1 = op1, op0
        if not (isinstance(op1, Const) and isinstance(op1.value, int)) or op0.bits != expr.bits:
            return None
        mask = op1.value_int & _mask(expr.bits)
        z, o = known_bits(op0, block_defs_resolver(block_defs), tmps=block_defs.tmps if block_defs is not None else None)
        if (z | o) & mask != mask:
            return None
        return Const(expr.idx, o & mask, expr.bits, **expr.tags)


class KnownBitsITECondition(PeepholeOptimizationExprBase):
    """
    ``c ? a : b`` ==> ``a`` or ``b`` when the known bits of ``c`` decide it, e.g. a VM's direction flag
    ``(flags >> 10 & 1) ? -1 : 1`` read back from a flags word whose DF bit is a constant 0 on every path.
    """

    __slots__ = ()

    NAME = "c ? a : b => a or b for a condition of known bits"
    expr_classes = (ITE,)

    def optimize(self, expr: ITE, *, block_defs: BlockDefs | None = None, **kwargs):
        if expr.cond.bits != 1 or isinstance(expr.cond, Const):
            return None
        z, o = known_bits(
            expr.cond, block_defs_resolver(block_defs), tmps=block_defs.tmps if block_defs is not None else None
        )
        if z & 1:
            return expr.iffalse
        if o & 1:
            return expr.iftrue
        return None
