from ailment import Const, UnaryOp, AILBlockWalker, Statement, Block
from ailment.expression import VirtualVariable
from ailment.statement import Assignment

from angr.rust.mixins import CFAMixin, SRDAMixin
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.rust.optimization_passes.base import SSAVariableHelper
from angr.rust.optimization_passes.cleanup_code_remover import CLEANUP_FUNCTIONS
from angr.rust.optimization_passes.utils import CallReplacer
from angr.rust.sim_type import RustSimTypeFunction, is_composite_type


class FunctionPrototypeInference(OptimizationPass, CFAMixin, SSAVariableHelper):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Infer potential struct/enum argument types and return types"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        CFAMixin.__init__(self, self._graph, self.project)
        SSAVariableHelper.__init__(self, self)

        self._new_stack_vvars = set()

        self.librust = self.project.kb.librust
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _fix_stack_vvar_uses(self):

        class StackVvarWalker(AILBlockWalker):
            def __init__(self, context: FunctionPrototypeInference):
                self.context = context
                self.srda = SRDAMixin(context._func, context._graph, context.project)
                super().__init__()

            def _handle_VirtualVariable(
                self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement, block: Block | None
            ):
                if expr.varid in self.context._new_stack_vvars:
                    return None
                if expr.was_stack:
                    vvar = self.srda.get_stack_vvar_by_insn(expr.stack_offset, stmt.ins_addr, block.idx)
                    if vvar and vvar.varid in self.context._new_stack_vvars:
                        return vvar
                return None

        walker = StackVvarWalker(self)
        for block in self._graph.nodes:
            walker.walk(block)

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
                    func, callsite_block=block, post_callsite_block=post_callsite_block
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
                    ):
                        call = call.copy()
                        call.args = call.args[1:]
                        call.bits = returnty.size
                        call.prototype = prototype
                        if is_expr:
                            return call
                        dst_vvar = self.new_stack_vvar(arg0.operand.stack_offset, call.bits, arg0.operand.tags)
                        dst_vvar.tags["type"] = returnty
                        self._new_stack_vvars.add(dst_vvar.varid)
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
        self._fix_stack_vvar_uses()
        self.out_graph = self._graph
