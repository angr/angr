from ailment import Const, UnaryOp
from ailment.expression import VirtualVariable
from ailment.statement import Assignment

from angr import SIM_LIBRARIES
from angr.rust.mixins import CFAMixin
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.rust.optimization_passes.utils import CallReplacer
from angr.rust.sim_type import RustSimTypeFunction, is_composite_type


class FunctionPrototypeInference(OptimizationPass, CFAMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Infer potential struct/enum argument types and return types"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        CFAMixin.__init__(self, self._graph, self.project)

        self.librust = SIM_LIBRARIES["librust"][0]
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze_and_replace_call(self, call, block, is_expr):
        # Perform calling convention analysis on target function if it's never analyzed
        if (
            call
            and not isinstance(call.prototype, RustSimTypeFunction)
            and isinstance(call.target, Const)
            and call.target.value in self.kb.functions
        ):
            func = self.kb.functions[call.target.value]
            if isinstance(func.prototype, RustSimTypeFunction):
                call.prototype = func.prototype
            else:
                post_callsite_block = self.get_one_successor(block) if self.num_successors(block) == 1 else None
                rcc = self.project.analyses.RustCallingConvention(
                    func, callsite_block=block, post_callsite_block=post_callsite_block
                )
                call.prototype = rcc.model.inferred_prototype
                func.prototype = call.prototype

        if call and isinstance(call.prototype, RustSimTypeFunction) and call.prototype.is_arg0_retbuf:
            prototype = call.prototype.normalize()
            returnty = prototype.returnty
            if is_composite_type(returnty) and call.args:
                arg0 = call.args[0]
                if isinstance(arg0, UnaryOp) and arg0.op == "Reference" and isinstance(arg0.operand, VirtualVariable):
                    dst_vvar = arg0.operand
                    call = call.copy()
                    call.args = call.args[1:]
                    call.bits = returnty.size
                    call.prototype = prototype
                    if is_expr:
                        return call
                    assignment = Assignment(idx=None, dst=dst_vvar, src=call, **call.tags)
                    return assignment
        return None

    def _analyze(self, cache=None):
        # Run calling convention analysis on current function if it's never analyzed
        if not isinstance(self._func.prototype, RustSimTypeFunction):
            rcc = self.project.analyses.RustCallingConvention(self._func)
            self._func.prototype = rcc.model.inferred_prototype

        walker = CallReplacer(callback=self._analyze_and_replace_call)
        for block in self._graph.nodes:
            walker.walk(block)
