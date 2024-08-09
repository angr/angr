from ailment.expression import BinaryOp, Load
from ailment.statement import Call, ConditionalJump

from .base import TransformationPass
from ... import SIM_LIBRARIES
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage

UNWRAP_FUNCTIONS = ("core::result::unwrap_failed",)


class UnwrapSimplifier(TransformationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify unwrap-like operations"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.librust = SIM_LIBRARIES["librust"]
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _extract_expr_from_condition(self, cond: BinaryOp):
        for op in cond.operands:
            if isinstance(op, Load):
                return op.addr
        return None

    def _simplify_non_returning_calls(self):
        removed = set()
        for block in self._graph.nodes:
            if (
                block.statements
                and isinstance(block.statements[-1], ConditionalJump)
                and self.num_successors(block) == 2
            ):
                should_update = False
                cond = block.statements[-1].condition
                block0, block1 = self.get_two_successors(block)
                if self.match_call(block0, UNWRAP_FUNCTIONS):
                    self.replace_jump_target(block, block0, block1)
                    removed.add(block0)
                    should_update = True
                elif self.match_call(block1, UNWRAP_FUNCTIONS):
                    self.replace_jump_target(block, block1, block0)
                    removed.add(block1)
                    should_update = True
                if should_update:
                    expr = self._extract_expr_from_condition(cond)
                    if expr:
                        last_stmt = block.statements[-1]
                        new_stmt = Call(
                            idx=last_stmt.idx,
                            target="core::result::unwrap",
                            prototype=self.librust.get_prototype("core::result::unwrap").with_arch(self.project.arch),
                            args=[expr],
                            ret_expr=None,
                            **last_stmt.tags,
                        )
                        block.statements[-1] = new_stmt

        for block in removed:
            self._graph.remove_node(block)

    def _analyze(self, cache=None):
        self._simplify_non_returning_calls()
