from angr.ailment.expression import VirtualVariable, Const, UnaryOp
from angr.ailment.statement import Assignment
from angr.rust.mixins import CFAMixin, SSAVariableMixin
from angr.rust.analyses.rust_calling_convention import Pathfinder
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.rust.optimization_passes.cleanup_code_remover import CLEANUP_FUNCTIONS
from angr.rust.optimization_passes.utils import CallReplacer
from angr.rust.sim_type import RustSimTypeFunction, is_composite_type


class FunctionPrototypeInference(OptimizationPass, CFAMixin, SSAVariableMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Infer potential struct/enum argument types and return types"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        CFAMixin.__init__(self, self._graph, self.project)
        SSAVariableMixin.__init__(self, self)

        self.librust = self.project.kb.librust
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze_and_replace_call(self, call, block, stmt, is_expr):
        # For debug purpose
        if self.match_call(call, CLEANUP_FUNCTIONS):
            return

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
                    func,
                    callsite_path=Pathfinder(self._graph).find_backward_path(block),
                    post_callsite_path=(
                        Pathfinder(self._graph).find_forward_path(post_callsite_block) if post_callsite_block else None
                    ),
                    is_call_expr=is_expr,
                )
                call.prototype = rcc.model.inferred_prototype
                func.prototype = call.prototype

        if call and isinstance(call.prototype, RustSimTypeFunction):
            is_arg0_retbuf = call.prototype.is_arg0_retbuf
            prototype = call.prototype.normalize()
            returnty = prototype.returnty
            if is_composite_type(returnty):
                if is_arg0_retbuf:
                    arg0 = call.args[0] if call.args else None
                    if (
                        isinstance(arg0, UnaryOp)
                        and arg0.op == "Reference"
                        and isinstance(arg0.operand, VirtualVariable)
                        and arg0.operand.was_stack
                    ):
                        call = call.copy()
                        call.args = call.args[1:]
                        call.bits = returnty.size
                        call.prototype = prototype
                        if is_expr:
                            return call
                        dst_vvar = self.new_stack_vvar(arg0.operand.stack_offset, call.bits, arg0.operand.tags)
                        dst_vvar.tags["type"] = returnty
                        assignment = Assignment(idx=None, dst=dst_vvar, src=call, **call.tags)
                        return assignment
                else:
                    if is_expr:
                        if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_reg:
                            stmt.dst.tags["type"] = returnty
        return None

    def _analyze(self, cache=None):
        # Run calling convention analysis on current function if it's never analyzed
        if not isinstance(self._func.prototype, RustSimTypeFunction):
            rcc = self.project.analyses.RustCallingConvention(self._func)
            self._func.prototype = rcc.model.inferred_prototype

        walker = CallReplacer(callback=self._analyze_and_replace_call)
        for block in self._graph.nodes:
            walker.walk(block)
        self.fix_stack_vvar_uses()
        self.out_graph = self._graph
