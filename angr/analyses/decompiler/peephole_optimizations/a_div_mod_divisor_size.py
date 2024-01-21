from ailment.expression import BinaryOp, UnaryOp, Const

from .base import PeepholeOptimizationExprBase


class DivModDivisorSize(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "DivMod(expr_size_a, const_size_b) => DivMod(expr_size_a, const_size_a)"
    expr_classes = (BinaryOp,)  # all expressions are allowed

    def optimize(self, expr: BinaryOp, **kwargs):
        #DivMod((0x0<64> CONCAT rax<8>), 0xa<64>)
        # change the size of the second argument to 128 bits as well, otherwise claripy complains

        if expr.op == "DivMod" and isinstance(expr.operands[1], Const) and expr.operands[1].size < expr.operands[0].size:
            return BinaryOp(
                    expr.idx,
                    "DivMod",
                    [expr.operands[0], Const(None, None, expr.operands[1].value, expr.operands[0].bits, **expr.operands[1].tags)],
                    expr.signed,
                    **expr.tags,
                )


        return None
