from __future__ import annotations

from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Const,
    Convert,
    Expression,
    Extract,
    Load,
    Tmp,
    UnaryOp,
    VEXCCallExpression,
    VirtualVariable,
)
from angr.analyses.decompiler.ccall_rewriters.flags_word import FlagsWordBuilder, flags_word_ccall
from angr.utils.ail import BlockDefs

from .base import PeepholeOptimizationExprBase
from .constant_derefs import ReadOnlyConstantDereferences
from .known_bits import block_defs_resolver, known_bits
from .masked_insert import _extract_shift
from .vm_bool_select import _eval_binop, _mask, _signed, same_value

_MAX_NODES = 4096
_MAX_DEPTH = 64


class _NotOneBool(Exception):
    """The value is not a function of one boolean."""


class _TwoBools(_NotOneBool):
    """Two booleans; they may yet turn out to be one, as definitions simplify."""


_FAILED = object()
_TWO = object()

# (boolean, value when it is 0, value when it is 1); the boolean is (kind, expression, bit), kind "bit" for a bit of
# a value and "cond" for a 1-bit condition, or None for a constant
_Atom = tuple[str, Expression, int]
_Result = tuple["_Atom | None", int, int]


def _checked(result) -> _Result:
    if result is _TWO:
        raise _TwoBools
    if result is _FAILED:
        raise _NotOneBool
    return result


def _same_atom(a: _Atom, b: _Atom) -> bool:
    return a[0] == b[0] and a[2] == b[2] and same_value(a[1], b[1])


def _common(*atoms: _Atom | None) -> _Atom | None:
    """The one boolean several values depend on."""
    found = None
    for atom in atoms:
        if atom is None:
            continue
        if found is None:
            found = atom
        elif not _same_atom(found, atom):
            raise _TwoBools
    return found


def _position_independent(expr: Expression, depth: int = 0) -> bool:
    """Built from virtual variables and constants only, so it has one value wherever it is evaluated."""
    if depth > 32:
        return False
    if isinstance(expr, (Const, VirtualVariable)):
        return True
    if isinstance(expr, BinaryOp):
        return all(_position_independent(op, depth + 1) for op in expr.operands)
    if isinstance(expr, (UnaryOp, Convert)):
        return _position_independent(expr.operand, depth + 1)
    if isinstance(expr, VEXCCallExpression):
        return all(_position_independent(op, depth + 1) for op in expr.operands)
    if isinstance(expr, Extract):
        return _position_independent(expr.base, depth + 1) and _position_independent(expr.offset, depth + 1)
    if isinstance(expr, ITE):
        return all(_position_independent(e, depth + 1) for e in (expr.cond, expr.iftrue, expr.iffalse))
    return False


def _bit_atom(expr: Expression) -> tuple[Expression, int] | None:
    """``(x, k)`` if ``expr`` is bit ``k`` of ``x`` as an integer: ``(x & 2**k) >> k`` or ``(x >> k) & 1``."""
    if not isinstance(expr, BinaryOp) or expr.floating_point:
        return None
    op0, op1 = expr.operands
    if expr.op == "Shr" and isinstance(op1, Const) and isinstance(op1.value, int) and isinstance(op0, BinaryOp):
        k = op1.value_int
        if op0.op == "And":
            a, b = op0.operands
            if isinstance(a, Const):
                a, b = b, a
            if isinstance(b, Const) and isinstance(b.value, int) and b.value_int == 1 << k:
                return a, k
        return None
    if expr.op == "And":
        a, b = op0, op1
        if isinstance(a, Const):
            a, b = b, a
        if (
            isinstance(b, Const)
            and isinstance(b.value, int)
            and b.value_int == 1
            and isinstance(a, BinaryOp)
            and a.op == "Shr"
            and isinstance(a.operands[1], Const)
            and isinstance(a.operands[1].value, int)
        ):
            return a.operands[0], a.operands[1].value_int
    return None


def _single_bit_mask(expr: Expression) -> tuple[Expression, int] | None:
    """``(y, j)`` if ``expr`` is ``y & 2**j``."""
    if not (isinstance(expr, BinaryOp) and expr.op == "And"):
        return None
    a, b = expr.operands
    if isinstance(a, Const):
        a, b = b, a
    if isinstance(b, Const) and isinstance(b.value, int) and b.value_int and b.value_int & (b.value_int - 1) == 0:
        return a, b.value_int.bit_length() - 1
    return None


class _Evaluator:
    """
    Evaluates an expression for both values of the one boolean it depends on, seeing through virtual variable
    definitions. The boolean is a single bit of one value, or a 1-bit condition; everything else must be constant
    or read from read-only memory.
    """

    def __init__(self, opt: SingleBoolToITE, block_defs: BlockDefs | None):
        self.opt = opt
        self.block_defs = block_defs
        self.graph = block_defs.all_defs if block_defs is not None else None
        self.resolver = block_defs_resolver(block_defs)
        # results by expression; shared by every evaluation over one graph
        self.memo: dict = self.graph.bool_value_memo if self.graph is not None else {}
        self.nodes = 0
        self._deref: ReadOnlyConstantDereferences | None = None

    def _bool(self, kind: str, expr: Expression, bit: int) -> _Result:
        """A boolean, reduced to a canonical spelling."""
        canon = self.canonical(kind, expr, bit)
        if isinstance(canon, int):
            return None, canon, canon
        kind, expr, bit, flip = canon
        if not _position_independent(expr):
            # the same expression may mean another value elsewhere
            raise _NotOneBool
        return (kind, expr, bit), flip, 1 - flip

    def canonical(self, kind: str, x: Expression, k: int) -> tuple[str, Expression, int, int] | int:
        """
        ``(kind, expr, bit, flip)`` with the boolean == (canonical boolean) ^ flip, or the constant 0/1. Bit ``k`` of
        ``x`` is followed through complements, operands whose bit ``k`` is known, shifts, widening, virtual variable
        definitions and x86 flags words; a 1-bit condition through ``!`` and ``==``/``!=`` swaps.
        """
        flip = 0
        for _ in range(32):
            if kind == "cond":
                if isinstance(x, UnaryOp) and x.op == "Not":
                    flip ^= 1
                    x = x.operand
                    continue
                if isinstance(x, BinaryOp) and x.op in ("CmpEQ", "CmpNE"):
                    a, b = x.operands
                    if isinstance(a, Const):
                        a, b = b, a
                    if isinstance(b, Const) and isinstance(b.value, int) and b.value_int == 0:
                        bit = _single_bit_mask(a)
                        if bit is not None:
                            # (y & 2**j) != 0 is bit j of y
                            flip ^= int(x.op == "CmpEQ")
                            kind, (x, k) = "bit", bit
                            continue
                    if x.op == "CmpNE":
                        flip ^= 1
                        x = BinaryOp(x.idx, "CmpEQ", list(x.operands), x.signed, bits=1)
                return "cond", x, 0, flip
            # bit k of x
            if k >= x.bits:
                return flip
            if isinstance(x, UnaryOp) and x.op == "BitwiseNeg":
                flip ^= 1
                x = x.operand
                continue
            if isinstance(x, BinaryOp) and not x.floating_point:
                op0, op1 = x.operands
                if x.op in ("Or", "And") and same_value(op0, op1):
                    x = op0
                    continue
                if x.op in ("Or", "And", "Xor"):
                    reduced = None
                    for keep, other in ((op0, op1), (op1, op0)):
                        zeros, ones = self._known_bits(other)
                        if not (zeros | ones) >> k & 1:
                            continue
                        value = ones >> k & 1
                        if (x.op == "Or" and value == 1) or (x.op == "And" and value == 0):
                            return value ^ flip
                        if x.op == "Xor":
                            flip ^= value
                        reduced = keep
                        break
                    if reduced is not None:
                        x = reduced
                        continue
                    break
                amount = op1.value_int if isinstance(op1, Const) and isinstance(op1.value, int) else None
                if x.op == "Mul" and amount and amount & (amount - 1) == 0:
                    amount, op = amount.bit_length() - 1, "Shl"
                else:
                    op = x.op
                if amount is not None and op == "Shl":
                    if k < amount:
                        return flip
                    x, k = op0, k - amount
                    continue
                if amount is not None and op == "Shr":
                    x, k = op0, k + amount
                    continue
                break
            if isinstance(x, Convert) and x.from_type == Convert.TYPE_INT and x.to_type == Convert.TYPE_INT:
                if k >= x.from_bits:
                    if x.is_signed:
                        k = x.from_bits - 1
                    else:
                        return flip
                if x.from_bits == 1:
                    kind, x = "cond", x.operand
                    continue
                x = x.operand
                continue
            if isinstance(x, ITE) and isinstance(x.iftrue, Const) and isinstance(x.iffalse, Const):
                # bit k of c ? a : b
                t, f = x.iftrue.value_int >> k & 1, x.iffalse.value_int >> k & 1
                if t == f:
                    return t ^ flip
                kind, x, k = "cond", x.cond, 0
                flip ^= f
                continue
            if isinstance(x, VirtualVariable) and self.graph is not None:
                src = self.graph.get(x.varid)
                if isinstance(src, (BinaryOp, UnaryOp, Convert, VEXCCallExpression, ITE)) and src.bits == x.bits:
                    x = src
                    continue
                break
            split = flags_word_ccall(x)
            if split is not None:
                built = FlagsWordBuilder(self.opt.manager, split[0], x.tags).build(
                    split[1], *x.operands[1:], self.opt.manager.next_atom()
                )
                if built is not None:
                    x = built
                    continue
            break
        return "bit", x, k, flip

    def _known_bits(self, expr: Expression) -> tuple[int, int]:
        """(known zeros, known ones), also of ``c ? a : b`` over constants."""
        if isinstance(expr, ITE) and isinstance(expr.iftrue, Const) and isinstance(expr.iffalse, Const):
            t, f = expr.iftrue.value_int, expr.iffalse.value_int
            return ~(t | f) & _mask(expr.bits), t & f
        if isinstance(expr, BinaryOp) and expr.op == "Or":
            z0, o0 = self._known_bits(expr.operands[0])
            z1, o1 = self._known_bits(expr.operands[1])
            return z0 & z1, o0 | o1
        return known_bits(expr, self.resolver)

    def evaluate(self, expr: Expression, tmps: dict | None, depth: int = 0) -> _Result:
        """
        ``(boolean, value when it is 0, value when it is 1)`` with values as unsigned integers of expr.bits bits;
        boolean None for a constant.
        """
        self.nodes += 1
        if self.nodes > _MAX_NODES or depth > _MAX_DEPTH:
            raise _NotOneBool
        if isinstance(expr, Const):
            if not isinstance(expr.value, int):
                raise _NotOneBool
            v = expr.value_int & _mask(expr.bits)
            return None, v, v
        if isinstance(expr, VirtualVariable):
            return self._vvar(expr, depth)
        # keyed by the expression itself: equal only to itself (same atom index and structure)
        key = expr
        result = self.memo.get(key)
        if result is None:
            try:
                result = self._evaluate(expr, tmps, depth)
            except _TwoBools:
                result = _TWO
            except _NotOneBool:
                result = _FAILED
            self.memo[key] = result
        return _checked(result)

    def _evaluate(self, expr: Expression, tmps: dict | None, depth: int) -> _Result:
        bit = _bit_atom(expr)
        if bit is not None:
            return self._bool("bit", *bit)
        if isinstance(expr, BinaryOp) and expr.op.startswith("Cmp") and expr.bits == 1:
            try:
                return self._binop(expr, tmps, depth)
            except _NotOneBool:
                return self._bool("cond", expr, 0)
        if isinstance(expr, Tmp):
            src = tmps.get(expr.tmp_idx) if tmps is not None else None
            if src is None or src.bits != expr.bits:
                raise _NotOneBool
            return self.evaluate(src, tmps, depth + 1)
        if isinstance(expr, BinaryOp):
            return self._binop(expr, tmps, depth)
        if isinstance(expr, UnaryOp):
            atom, v0, v1 = self.evaluate(expr.operand, tmps, depth + 1)
            m = _mask(expr.bits)
            if expr.op == "BitwiseNeg":
                return atom, ~v0 & m, ~v1 & m
            if expr.op == "Neg":
                return atom, -v0 & m, -v1 & m
            if expr.op == "Not" and expr.bits == 1:
                return atom, int(not v0), int(not v1)
            raise _NotOneBool
        if isinstance(expr, Convert):
            if expr.from_type != Convert.TYPE_INT or expr.to_type != Convert.TYPE_INT:
                raise _NotOneBool
            atom, v0, v1 = self.evaluate(expr.operand, tmps, depth + 1)
            if expr.is_signed and expr.to_bits > expr.from_bits:
                v0, v1 = _signed(v0, expr.from_bits), _signed(v1, expr.from_bits)
            m = _mask(expr.to_bits)
            return atom, v0 & m, v1 & m
        if isinstance(expr, Extract):
            shift = _extract_shift(expr)
            if shift is None:
                raise _NotOneBool
            atom, v0, v1 = self.evaluate(expr.base, tmps, depth + 1)
            m = _mask(expr.bits)
            return atom, (v0 >> shift) & m, (v1 >> shift) & m
        if isinstance(expr, ITE):
            cond = self.evaluate(expr.cond, tmps, depth + 1)
            iftrue = self.evaluate(expr.iftrue, tmps, depth + 1)
            iffalse = self.evaluate(expr.iffalse, tmps, depth + 1)
            atom = _common(cond[0], iftrue[0], iffalse[0])
            return atom, (iftrue[1] if cond[1] else iffalse[1]), (iftrue[2] if cond[2] else iffalse[2])
        if isinstance(expr, Load):
            return self._load(expr, tmps, depth)
        raise _NotOneBool

    def _binop(self, expr: BinaryOp, tmps, depth) -> _Result:
        if expr.floating_point or expr.vector_count:
            raise _NotOneBool
        op0, op1 = expr.operands
        a = self.evaluate(op0, tmps, depth + 1)
        b = self.evaluate(op1, tmps, depth + 1)
        atom = _common(a[0], b[0])
        r0 = _eval_binop(expr.op, a[1], b[1], op0.bits, expr.signed)
        r1 = _eval_binop(expr.op, a[2], b[2], op0.bits, expr.signed)
        if r0 is None or r1 is None or r0[1] != expr.bits:
            raise _NotOneBool
        return atom, r0[0], r1[0]

    def _vvar(self, vvar: VirtualVariable, depth: int) -> _Result:
        key = ("vvar", vvar.varid)
        result = self.memo.get(key)
        if result is None:
            result = _FAILED
            definition = self.graph.definition(vvar.varid) if self.graph is not None else None
            if definition is None and self.block_defs is not None and vvar.varid in self.block_defs.vvars:
                definition = self.block_defs.vvars[vvar.varid], self.block_defs.tmps
            if definition is not None and definition[0].bits == vvar.bits:
                try:
                    result = self.evaluate(definition[0], definition[1], depth + 1)
                except _TwoBools:
                    result = _TWO
                except _NotOneBool:
                    pass
            self.memo[key] = result
        return _checked(result)

    def _load(self, expr: Load, tmps, depth) -> _Result:
        if expr.guard is not None:
            raise _NotOneBool
        atom, a0, a1 = self.evaluate(expr.addr, tmps, depth + 1)
        if self._deref is None:
            opt = self.opt
            self._deref = ReadOnlyConstantDereferences(opt.project, opt.kb, opt.manager, opt.func_addr)
        values = []
        for addr in (a0, a1):
            manager = self.opt.manager
            load = Load(manager.next_atom(), Const(manager.next_atom(), addr, expr.addr.bits), expr.size, expr.endness)
            value = self._deref.optimize(load)
            if not (isinstance(value, Const) and isinstance(value.value, int)):
                raise _NotOneBool
            values.append(value.value_int & _mask(expr.bits))
        return atom, values[0], values[1]


class SingleBoolToITE(PeepholeOptimizationExprBase):
    """
    A value that depends on nothing but one boolean is ``b ? f(1) : f(0)``. Evaluating it for both values of the
    boolean is exhaustive, so the rewrite is exact.

    The boolean is one bit of one value (``(x & 2**k) >> k``, ``(x >> k) & 1``, or the same of ``~x``) or a 1-bit
    condition; the value may see it through virtual variable definitions and may read read-only memory at addresses
    computed from it. A VMProtect "ultra" handler selects the next rolling key this way:
    ``*(int *)((~m | 0xffffffff + ((~f & 64) >> 6) & K1) + (~n & ~m & K2) + base)`` is ``*(f & 64 ? A : B)``.
    """

    __slots__ = ()

    NAME = "f(b) => b ? f(1) : f(0) for a value of one boolean"
    expr_classes = (BinaryOp, UnaryOp, Convert, Load)

    def optimize(self, expr: Expression, *, block_defs: BlockDefs | None = None, **kwargs):
        if not (isinstance(expr, Load) or expr.bits == 1):
            # only what a selection ends in: a load from one of two addresses, or a branch condition; the arithmetic
            # in between stays as it is unless it folds away completely
            return None
        if expr.bits > 64 or getattr(expr, "floating_point", False) or _bit_atom(expr) is not None:
            return None
        if isinstance(expr, BinaryOp) and expr.op.startswith("Cmp") and _shallow(expr):
            return None
        evaluator = _Evaluator(self, block_defs)
        try:
            atom, v0, v1 = evaluator.evaluate(expr, block_defs.tmps if block_defs is not None else None)
        except _TwoBools:
            self.fixpoint_reached = False
            return None
        except _NotOneBool:
            return None
        if atom is None:
            # constant without the boolean; other peepholes fold those
            return None
        if expr.bits == 1:
            spelled = evaluator.canonical("cond", expr, 0)
            if not isinstance(spelled, int) and _same_atom(atom, spelled[:3]):
                # already a spelling of the boolean itself
                return None
        cond = self._condition(atom)
        if v0 == v1:
            out = Const(self.manager.next_atom(), v0, expr.bits, **expr.tags)
        elif expr.bits == 1:
            out = cond if v1 else UnaryOp(self.manager.next_atom(), "Not", cond, bits=1, **expr.tags)
        else:
            out = ITE(
                expr.idx,
                cond,
                Const(self.manager.next_atom(), v1, expr.bits),
                Const(self.manager.next_atom(), v0, expr.bits),
                **expr.tags,
            )
        # the boolean itself, already in its canonical spelling
        return None if same_value(out, expr) else out

    def _condition(self, atom: tuple[str, Expression, int]) -> Expression:
        kind, expr, bit = atom
        if kind == "cond":
            return expr
        mask = Const(self.manager.next_atom(), 1 << bit, expr.bits)
        masked = BinaryOp(self.manager.next_atom(), "And", [expr, mask], False, bits=expr.bits)
        zero = Const(self.manager.next_atom(), 0, expr.bits)
        return BinaryOp(self.manager.next_atom(), "CmpNE", [masked, zero], False, bits=1)


def _shallow(expr: BinaryOp) -> bool:
    """A comparison of a variable with a constant reads fine as it is."""
    return any(isinstance(op, Const) for op in expr.operands) and all(
        isinstance(op, (Const, VirtualVariable, Tmp)) for op in expr.operands
    )
