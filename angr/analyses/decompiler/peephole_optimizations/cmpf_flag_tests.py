from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, Convert, Expression, UnaryOp

from .base import PeepholeOptimizationExprBase

# VEX CmpF results: unordered, less than, greater than, equal
_CMPF_VALUES = (0x45, 0x01, 0x00, 0x40)
_UN, _LT, _GT, _EQ = range(4)

# outcomes for which the test holds => (comparison, negated)
_TRUTH_TO_CMP: dict[frozenset[int], tuple[str, bool]] = {
    frozenset({_LT}): ("CmpLT", False),
    frozenset({_LT, _EQ}): ("CmpLE", False),
    frozenset({_GT}): ("CmpGT", False),
    frozenset({_GT, _EQ}): ("CmpGE", False),
    frozenset({_EQ}): ("CmpEQ", False),
    frozenset({_UN, _LT, _GT}): ("CmpNE", False),
    frozenset({_UN, _GT, _EQ}): ("CmpLT", True),
    frozenset({_UN, _GT}): ("CmpLE", True),
    frozenset({_UN, _LT, _EQ}): ("CmpGT", True),
    frozenset({_UN, _LT}): ("CmpGE", True),
}

_BINOPS = {
    "And": lambda a, b, n: a & b,
    "Or": lambda a, b, n: a | b,
    "Xor": lambda a, b, n: a ^ b,
    "Add": lambda a, b, n: a + b,
    "Sub": lambda a, b, n: a - b,
    "Shl": lambda a, b, n: a << b,
    "Shr": lambda a, b, n: a >> b,
    "CmpEQ": lambda a, b, n: int(a == b),
    "CmpNE": lambda a, b, n: int(a != b),
}


class _NoMatch(Exception):
    pass


class CmpFFlagTests(PeepholeOptimizationExprBase):
    """
    Rewrite condition-flag tests on a ``CmpF`` result (e.g. ``(CmpF(a, b) & 69 | (CmpF(a, b) & 69) >> 6) & 1 == 1``
    after x86 ``ucomisd``) into float comparisons, by evaluating the test for each of the four ``CmpF`` outcomes.
    """

    __slots__ = ()

    NAME = "Rewrite flag tests on CmpF into float comparisons"
    expr_classes = (BinaryOp, Convert)

    def optimize(self, expr: BinaryOp | Convert, **kwargs):
        if isinstance(expr, BinaryOp):
            if expr.op not in {"CmpEQ", "CmpNE"}:
                return None
        elif expr.to_bits != 1:
            return None

        cmpfs: list[BinaryOp] = []
        try:
            self._collect(expr, cmpfs)
        except _NoMatch:
            return None
        if not cmpfs or not all(c.likes(cmpfs[0]) for c in cmpfs[1:]):
            return None
        cmpf = cmpfs[0]

        truth = set()
        try:
            for outcome, value in enumerate(_CMPF_VALUES):
                r = self._eval(expr, value)
                if r not in (0, 1):
                    return None
                if r:
                    truth.add(outcome)
        except _NoMatch:
            return None

        mapped = _TRUTH_TO_CMP.get(frozenset(truth))
        if mapped is None:
            return None
        op, negated = mapped
        r = BinaryOp(expr.idx, op, list(cmpf.operands), False, floating_point=True, bits=1, **expr.tags)
        if negated:
            r = UnaryOp(self.manager.next_atom(), "Not", r, bits=1, **expr.tags)
        return r

    @staticmethod
    def _collect(e: Expression, cmpfs: list[BinaryOp]) -> None:
        if isinstance(e, Const):
            if not isinstance(e.value, int):
                raise _NoMatch
            return
        if isinstance(e, BinaryOp):
            if e.op == "CmpF":
                cmpfs.append(e)
                return
            if e.op not in _BINOPS:
                raise _NoMatch
            for o in e.operands:
                CmpFFlagTests._collect(o, cmpfs)
            return
        if isinstance(e, Convert) and not e.is_signed:
            CmpFFlagTests._collect(e.operand, cmpfs)
            return
        if isinstance(e, UnaryOp) and e.op in {"Not", "BitwiseNeg"}:
            CmpFFlagTests._collect(e.operand, cmpfs)
            return
        raise _NoMatch

    @staticmethod
    def _eval(e: Expression, value: int) -> int:
        mask = (1 << e.bits) - 1
        if isinstance(e, Const):
            return e.value_int & mask
        if isinstance(e, BinaryOp):
            if e.op == "CmpF":
                return value
            a = CmpFFlagTests._eval(e.operands[0], value)
            b = CmpFFlagTests._eval(e.operands[1], value)
            return _BINOPS[e.op](a, b, e.bits) & mask
        if isinstance(e, Convert):
            return CmpFFlagTests._eval(e.operand, value) & mask
        if isinstance(e, UnaryOp):
            v = CmpFFlagTests._eval(e.operand, value)
            if e.op == "Not":
                return int(not v) if e.bits == 1 else ~v & mask
            return ~v & mask
        raise _NoMatch
