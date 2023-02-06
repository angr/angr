import logging

from ailment import Expr

from .engine_base import SimplifierAILEngine, SimplifierAILState
from .optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(name=__name__)


class MultiSimplifierAILEngine(SimplifierAILEngine):
    """
    An AIL pass for the multi simplifier
    """

    def _ail_handle_Add(self, expr):
        operand_0 = self._expr(expr.operands[0])
        operand_1 = self._expr(expr.operands[1])

        # x + x = 2*x
        if type(operand_0) in [Expr.Convert, Expr.Register]:
            if isinstance(operand_1, (Expr.Convert, Expr.Register)):
                if operand_0 == operand_1:
                    count = Expr.Const(expr.idx, None, 2, 8)
                    return Expr.BinaryOp(expr.idx, "Mul", [operand_1, count], expr.signed, **expr.tags)
        # 2*x + x = 3*x
        if Expr.BinaryOp in [type(operand_0), type(operand_1)]:
            if (
                isinstance(operand_1, Expr.BinaryOp)
                and operand_1.op == "Mul"
                and (
                    not isinstance(operand_0, Expr.BinaryOp)
                    or (isinstance(operand_0, Expr.BinaryOp) and operand_0.op != "Mul")
                )
            ):
                x0 = operand_0
                x1_index = 0 if isinstance(operand_1.operands[1], Expr.Const) else 1
                x1 = operand_1.operands[x1_index]
                const_x1 = operand_1.operands[1 - x1_index]
                if x0 == x1:
                    new_const = Expr.Const(const_x1.idx, None, const_x1.value + 1, const_x1.bits)
                    new_expr = Expr.BinaryOp(expr.idx, "Mul", [x0, new_const], expr.signed, **expr.tags)
                    return new_expr
            elif (
                isinstance(operand_0, Expr.BinaryOp)
                and operand_0.op == "Mul"
                and (
                    not isinstance(operand_1, Expr.BinaryOp)
                    or (isinstance(operand_1, Expr.BinaryOp) and operand_1.op != "Mul")
                )
            ):
                x1 = operand_1
                x0_index = 0 if isinstance(operand_0.operands[1], Expr.Const) else 1
                x0 = operand_0.operands[x0_index]
                const_x0 = operand_0.operands[1 - x0_index]
                if x0 == x1:
                    new_const = Expr.Const(const_x0.idx, None, const_x0.value + 1, const_x0.bits)
                    new_expr = Expr.BinaryOp(expr.idx, "Mul", [x1, new_const], expr.signed, **expr.tags)
                    return new_expr
            # 2*x + 3*x = 5*x
            elif (
                isinstance(operand_0, Expr.BinaryOp)
                and isinstance(operand_1, Expr.BinaryOp)
                and operand_0.op == "Mul"
                and operand_1.op == "Mul"
            ):
                if Expr.Const in [type(operand_0.operands[0]), type(operand_0.operands[1])] and Expr.Const in [
                    type(operand_1.operands[0]),
                    type(operand_1.operands[1]),
                ]:
                    x0_index = 0 if isinstance(operand_0.operands[1], Expr.Const) else 1
                    x0 = operand_0.operands[x0_index]
                    const_x0 = operand_0.operands[1 - x0_index]

                    x1_index = 0 if isinstance(operand_1.operands[1], Expr.Const) else 1
                    x1 = operand_1.operands[x1_index]
                    const_x1 = operand_1.operands[1 - x1_index]
                    if x0 == x1:
                        new_const = Expr.Const(const_x1.idx, None, const_x1.value + const_x0.value, const_x1.bits)
                        new_expr = Expr.BinaryOp(expr.idx, "Mul", [x0, new_const], expr.signed, **expr.tags)
                        return new_expr

        if (operand_0, operand_1) != (expr.operands[0], expr.operands[1]):
            return Expr.BinaryOp(expr.idx, "Add", [operand_0, operand_1], expr.signed, **expr.tags)
        return expr

    def _ail_handle_Sub(self, expr):
        operand_0 = self._expr(expr.operands[0])
        operand_1 = self._expr(expr.operands[1])

        # x + x = 2*x
        if type(operand_0) in [Expr.Convert, Expr.Register]:
            if isinstance(operand_1, (Expr.Convert, Expr.Register)):
                if operand_0 == operand_1:
                    count = Expr.Const(expr.idx, None, 0, 8)
                    new_expr = Expr.BinaryOp(expr.idx, "Mul", [operand_1, count], expr.signed, **expr.tags)
                    return new_expr

        # 2*x - x = x
        if Expr.BinaryOp in [type(operand_0), type(operand_1)]:
            if (
                isinstance(operand_1, Expr.BinaryOp)
                and operand_1.op == "Mul"
                and (
                    not isinstance(operand_0, Expr.BinaryOp)
                    or (isinstance(operand_0, Expr.BinaryOp) and operand_0.op != "Mul")
                )
            ):
                x0 = operand_0
                x1_index = 0 if isinstance(operand_1.operands[1], Expr.Const) else 1
                x1 = operand_1.operands[x1_index]
                const_x1 = operand_1.operands[1 - x1_index]
                if x0 == x1:
                    new_const = Expr.Const(const_x1.idx, None, const_x1.value - 1, const_x1.bits)
                    new_expr = Expr.BinaryOp(expr.idx, "Mul", [x0, new_const], expr.signed, **expr.tags)
                    return new_expr
            elif (
                isinstance(operand_0, Expr.BinaryOp)
                and operand_0.op == "Mul"
                and (
                    not isinstance(operand_1, Expr.BinaryOp)
                    or (isinstance(operand_1, Expr.BinaryOp) and operand_1.op != "Mul")
                )
            ):
                x1 = operand_1
                x0_index = 0 if isinstance(operand_0.operands[1], Expr.Const) else 1
                x0 = operand_0.operands[x0_index]
                const_x0 = operand_0.operands[1 - x0_index]
                if x0 == x1:
                    new_const = Expr.Const(const_x0.idx, None, const_x0.value - 1, const_x0.bits)
                    new_expr = Expr.BinaryOp(expr.idx, "Mul", [x1, new_const], expr.signed, **expr.tags)
                    return new_expr
            # 3*x - 2*x = x
            elif (
                isinstance(operand_0, Expr.BinaryOp)
                and isinstance(operand_1, Expr.BinaryOp)
                and operand_0.op == "Mul"
                and operand_1.op == "Mul"
            ):
                if Expr.Const in [type(operand_0.operands[0]), type(operand_0.operands[1])] and Expr.Const in [
                    type(operand_1.operands[0]),
                    type(operand_1.operands[1]),
                ]:
                    x0_index = 0 if isinstance(operand_0.operands[1], Expr.Const) else 1
                    x0 = operand_0.operands[x0_index]
                    const_x0 = operand_0.operands[1 - x0_index]

                    x1_index = 0 if isinstance(operand_1.operands[1], Expr.Const) else 1
                    x1 = operand_1.operands[x1_index]
                    const_x1 = operand_1.operands[1 - x1_index]
                    if x0 == x1:
                        new_const = Expr.Const(const_x1.idx, None, const_x0.value - const_x1.value, const_x1.bits)
                        new_expr = Expr.BinaryOp(expr.idx, "Mul", [x0, new_const], expr.signed, **expr.tags)
                        return new_expr

        if (operand_0, operand_1) != (expr.operands[0], expr.operands[1]):
            return Expr.BinaryOp(expr.idx, "Sub", [operand_0, operand_1], expr.signed, **expr.tags)
        return expr

    def _ail_handle_Shl(self, expr):
        operand_0 = self._expr(expr.operands[0])
        operand_1 = self._expr(expr.operands[1])

        if isinstance(operand_1, Expr.Const):
            new_operand = Expr.Const(operand_1.idx, None, 2**operand_1.value, operand_0.bits)
            return Expr.BinaryOp(expr.idx, "Mul", [operand_0, new_operand], expr.signed, **expr.tags)

        if (operand_0, operand_1) != (expr.operands[0], expr.operands[1]):
            return Expr.BinaryOp(expr.idx, "Shl", [operand_0, operand_1], expr.signed, **expr.tags)
        return expr

    def _ail_handle_Mul(self, expr):
        operand_0 = self._expr(expr.operands[0])
        operand_1 = self._expr(expr.operands[1])

        if Expr.Const in [type(operand_0), type(operand_1)]:
            if Expr.BinaryOp in [type(operand_0), type(operand_1)]:
                const_, x0 = (operand_0, operand_1) if isinstance(operand_0, Expr.Const) else (operand_1, operand_0)
                if x0.op == "Mul" and Expr.Const in [type(x0.operands[0]), type(x0.operands[1])]:
                    if isinstance(x0.operands[0], Expr.Const):
                        const_x0, x = x0.operands[0], x0.operands[1]
                    else:
                        const_x0, x = x0.operands[1], x0.operands[0]
                    new_const = Expr.Const(const_.idx, None, const_.value * const_x0.value, const_.bits)
                    new_expr = Expr.BinaryOp(expr.idx, "Mul", [x, new_const], expr.signed, **expr.tags)
                    return new_expr
            elif (
                isinstance(operand_0, Expr.Convert)
                and isinstance(operand_0.operand, Expr.BinaryOp)
                and operand_0.operand.op == "Mul"
                and isinstance(operand_0.operand.operands[1], Expr.Const)
            ):
                x = operand_0.operand.operands[0]
                new_const = Expr.Const(
                    operand_1.idx, None, operand_1.value * operand_0.operand.operands[1].value, operand_1.bits
                )
                new_expr = Expr.BinaryOp(expr.idx, "Mul", [x, new_const], expr.signed, **expr.tags)
                return new_expr

        if (operand_0, operand_1) != (expr.operands[0], expr.operands[1]):
            return Expr.BinaryOp(expr.idx, "Mul", [operand_0, operand_1], expr.signed, **expr.tags)
        return expr


class MultiSimplifier(OptimizationPass):
    """
    Implements several different arithmetic optimizations.
    """

    ARCHES = ["X86", "AMD64"]
    PLATFORMS = ["linux", "windows"]
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify various arithmetic expressions"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.state = SimplifierAILState(self.project.arch)
        self.engine = MultiSimplifierAILEngine()

        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        for block in list(self._graph.nodes()):
            new_block = block
            old_block = None

            while new_block != old_block:
                old_block = new_block
                new_block = self.engine.process(state=self.state.copy(), block=old_block.copy())
                _l.debug("new block: %s", new_block.statements)

            self._update_block(block, new_block)
