from ailment import Const, AILBlockWalker, Block, Statement
from ailment.statement import Call

from angr.analyses.decompiler.clinic import ClinicMode
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage
from angr.rust.optimization_passes.base import TransformationPass
from angr.rust.sim_type import RustSimTypeFunction
from angr.rust.utils.ail_util import get_terminal_call


class FunctionPrototypeInference(TransformationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Infer potential struct/enum argument types and return types"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze(self, cache=None):
        if not isinstance(self._func.prototype, RustSimTypeFunction):
            rcc = self.project.analyses.RustCallingConvention(self._func)
            self._func.prototype = rcc.model.inferred_prototype

        class CallWalker(AILBlockWalker):

            def __init__(self, context: "FunctionPrototypeInference"):
                super().__init__()
                self.context = context

            def _handle_call(self, call):
                if (
                    call
                    and not isinstance(call.prototype, RustSimTypeFunction)
                    and isinstance(call.target, Const)
                    and call.target.value in self.context.kb.functions
                ):
                    func = self.context.kb.functions[call.target.value]
                    if isinstance(func.prototype, RustSimTypeFunction):
                        call.prototype = func.prototype
                    else:
                        post_callsite_block = (
                            self.context.get_one_successor(block) if self.context.num_successors(block) == 1 else None
                        )
                        rcc = self.context.project.analyses.RustCallingConvention(
                            func, callsite_block=block, post_callsite_block=post_callsite_block
                        )
                        call.prototype = rcc.model.inferred_prototype
                        func.prototype = call.prototype

            def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
                self._handle_call(stmt)

            def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
                self._handle_call(expr)

        walker = CallWalker(self)
        for block in self._graph.nodes:
            walker.walk(block)
