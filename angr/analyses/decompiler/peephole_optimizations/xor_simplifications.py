from angr.ailment.expression import BinaryOp, Const, UnaryOp, Convert

from .base import PeepholeOptimizationExprBase


class XorSimplifications(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "expr 2 ^ expr1 ^ expr1 => expr2"
    expr_classes = (BinaryOp,)  # all expressions are allowed

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op == "Xor" and isinstance(expr.operands[0], BinaryOp) and expr.operands[0].op == "Xor":
            if expr.operands[1].likes(expr.operands[0].operands[1]):
                return expr.operands[0].operands[0]
        # (a | b) & (~a | ~b) ==> a ^ b;  (a & ~b) | (~a & b) ==> a ^ b
        if expr.op in {"And", "Or"} and not expr.floating_point:
            op0, op1 = expr.operands
            inner = "Or" if expr.op == "And" else "And"
            if (
                isinstance(op0, BinaryOp)
                and isinstance(op1, BinaryOp)
                and op0.op == inner
                and op1.op == inner
                and op0.bits == op1.bits == expr.bits
            ):
                pair = self._xor_operands(op0, op1) if expr.op == "And" else self._xor_operands_disjunctive(op0, op1)
                if pair is not None:
                    return BinaryOp(expr.idx, "Xor", list(pair), expr.signed, bits=expr.bits, **expr.tags)
        return None

    @staticmethod
    def _negated(expr):
        return expr.operand if isinstance(expr, UnaryOp) and expr.op == "BitwiseNeg" else None

    @classmethod
    def _xor_operands(cls, op0: BinaryOp, op1: BinaryOp):
        """(a | b) & (~a | ~b): op0 and op1 are the two disjunctions, in either order."""
        for plain, negated in ((op0, op1), (op1, op0)):
            a, b = plain.operands
            n0, n1 = cls._negated(negated.operands[0]), cls._negated(negated.operands[1])
            if n0 is None or n1 is None:
                continue
            if (a.likes(n0) and b.likes(n1)) or (a.likes(n1) and b.likes(n0)):
                return a, b
        return None

    @classmethod
    def _xor_operands_disjunctive(cls, op0: BinaryOp, op1: BinaryOp):
        """(a & ~b) | (~a & b)."""
        for x, y in ((op0.operands, op0.operands[::-1])):
            nb = cls._negated(y)
            if nb is None:
                continue
            for u, v in ((op1.operands, op1.operands[::-1])):
                na = cls._negated(u)
                if na is not None and na.likes(x) and v.likes(nb):
                    return x, nb
        return None
