import logging

from ailment import Expr
from unique_log_filter import UniqueLogFilter

from .engine_base import SimplifierAILEngine, SimplifierAILState
from .optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(name=__name__)
_l.addFilter(UniqueLogFilter())


class ModSimplifierAILEngine(SimplifierAILEngine):
    def _ail_handle_Sub(self, expr):
        operand_0 = self._expr(expr.operands[0])
        operand_1 = self._expr(expr.operands[1])

        x_0, c_0, x_1, c_1 = None, None, None, None
        if isinstance(operand_1, Expr.BinaryOp) and isinstance(operand_1.operands[1], Expr.Const):
            if operand_1.op == "Mul":
                if (
                    isinstance(operand_1.operands[0], Expr.BinaryOp)
                    and isinstance(operand_1.operands[0].operands[1], Expr.Const)
                    and operand_1.operands[0].op in ["Div", "Mod"]
                ):
                    x_0 = operand_1.operands[0].operands[0]
                    x_1 = operand_0
                    c_0 = operand_1.operands[1]
                    c_1 = operand_1.operands[0].operands[1]
                elif (
                    isinstance(operand_1.operands[0], Expr.Convert)
                    and isinstance(operand_1.operands[0].operand, Expr.BinaryOp)
                    and operand_1.operands[0].operand.op in ["Div", "Mod"]
                ):
                    x_0 = operand_1.operands[0].operand.operands[0]
                    x_1 = operand_0
                    c_0 = operand_1.operands[1]
                    c_1 = operand_1.operands[0].operand.operands[1]

                if x_0 is not None and x_1 is not None and x_0.likes(x_1) and c_0.value == c_1.value:
                    return Expr.BinaryOp(expr.idx, "Mod", [x_0, c_0], expr.signed, **expr.tags)

        if (operand_0, operand_1) != (expr.operands[0], expr.operands[1]):
            return Expr.BinaryOp(expr.idx, "Sub", [operand_0, operand_1], expr.signed, **expr.tags)
        return expr


class ModSimplifier(OptimizationPass):
    """
    Simplifies optimized forms of modulo computation back to "mod".
    """

    ARCHES = [
        "X86",
        "AMD64",
        "ARMCortexM",
        "ARMHF",
        "ARMEL",
    ]
    PLATFORMS = ["linux", "windows"]
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify optimized mod forms"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.state = SimplifierAILState(self.project.arch)
        self.engine = ModSimplifierAILEngine()

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
