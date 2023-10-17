from ailment.expression import UnaryOp, BinaryOp

from .base import PeepholeOptimizationExprBase


class InvertNegatedLogicalConjunctionsAndDisjunctions(PeepholeOptimizationExprBase):
    """
    Push negations into subexpressions of logical conjunctions and logical disjunctions.
    """

    __slots__ = ()

    NAME = "!(A && B) => A || B; !(A || B) => A && B"
    expr_classes = (UnaryOp,)  # all expressions are allowed

    def optimize(self, expr: UnaryOp, **kwargs):
        if expr.op == "Not":
            if isinstance(expr.operand, BinaryOp):
                if expr.operand.op == "LogicalAnd":
                    inner_operands = [
                        UnaryOp(None, "Not", expr.operand.operands[0], **expr.operand.operands[0].tags),
                        UnaryOp(None, "Not", expr.operand.operands[1], **expr.operand.operands[1].tags),
                    ]
                    return BinaryOp(
                        expr.operand.idx,
                        "LogicalOr",
                        inner_operands,
                        expr.operand.signed,
                        variable=expr.operand.variable,
                        variable_offset=expr.operand.variable_offset,
                        bits=expr.operand.bits,
                        **expr.tags,
                    )
                elif expr.operand.op == "LogicalOr":
                    inner_operands = [
                        UnaryOp(None, "Not", expr.operand.operands[0], **expr.operand.operands[0].tags),
                        UnaryOp(None, "Not", expr.operand.operands[1], **expr.operand.operands[1].tags),
                    ]
                    return BinaryOp(
                        expr.idx,
                        "LogicalAnd",
                        inner_operands,
                        expr.operand.signed,
                        variable=expr.operand.variable,
                        variable_offset=expr.operand.variable_offset,
                        bits=expr.operand.bits,
                        **expr.tags,
                    )

        return None
