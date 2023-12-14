from ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class ADivConstAddAMulNDivConst(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "a / N0 + (a * N1) / N0 => a * (N1 + 1) / N0"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op == "Add" and len(expr.operands) == 2:
            op0, op1 = expr.operands
            if isinstance(op0, BinaryOp) and op0.op == "Div" and isinstance(op0.operands[1], Const):
                if isinstance(op1, BinaryOp) and op1.op == "Div" and isinstance(op1.operands[1], Const):
                    if (
                        isinstance(op1.operands[0], BinaryOp)
                        and op1.operands[0].op == "Mul"
                        and isinstance(op1.operands[0].operands[1], Const)
                    ):
                        a0 = op0.operands[0]
                        a1 = op1.operands[0].operands[0]
                        if a0.likes(a1):
                            N0 = op0.operands[1]
                            N1: int = op1.operands[0].operands[1].value
                            if N0.value == op1.operands[1].value:
                                mul = BinaryOp(
                                    op0.idx,
                                    "Mul",
                                    [a0, Const(None, None, N1 + 1, expr.bits, **expr.operands[0].operands[1].tags)],
                                    False,
                                    **op0.tags,
                                )
                                div = BinaryOp(expr.idx, "Div", [mul, N0], False, **expr.tags)
                                return div

        return None
