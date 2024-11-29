from ailment import AILBlockWalker, Block
from ailment.expression import BasePointerOffset, VirtualVariable
from ailment.statement import Call, Statement, Assignment

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.rust.optimization_passes.base import SSAVariableHelper
from angr.rust.sim_type import RustSimTypeFunction
from angr.rust.mixins.srda_mixin import SRDAMixin


class CallsiteCorrectorWalker(AILBlockWalker, SRDAMixin):
    def __init__(self, context: "CallsiteCorrector"):
        super().__init__()
        SRDAMixin.__init__(self, context._func, context._graph, context.project)
        self.context = context

    def _handle_VirtualVariable(
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        if block and expr.was_stack and expr not in self.context.new_stack_vvars:
            replacement = self.get_stack_vvar_by_insn(expr.stack_offset, stmt.ins_addr, block.idx, expr.size)
            if replacement and replacement in self.context.new_stack_vvars and not replacement.likes(expr):
                return replacement
        return None


class CallsiteCorrector(OptimizationPass, SSAVariableHelper):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify callsites"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        SSAVariableHelper.__init__(self, self)

        self.new_stack_vvars = set()

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _correct_call(self, call: Call, is_expr):
        if isinstance(call.prototype, RustSimTypeFunction) and call.args:
            prototype = call.prototype.normalize()
            if prototype:
                struct_ty = prototype.returnty
                first_arg = call.args[0]
                if isinstance(first_arg, BasePointerOffset):
                    call = call.copy()
                    call.args = call.args[1:]
                    call.bits = struct_ty.size
                    call.prototype = prototype
                    if is_expr:
                        return call
                    vvar = self.new_stack_vvar(first_arg.offset, struct_ty.size, call.tags)
                    self.new_stack_vvars.add(vvar)
                    assignment = Assignment(idx=None, dst=vvar, src=call, **call.tags)
                    return assignment
        return None

    def _analyze(self, cache=None):
        class CallWalker(AILBlockWalker):
            def __init__(self, context: CallsiteCorrector):
                super().__init__()
                self.context = context

            def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
                new_stmt = self.context._correct_call(stmt, False)
                if new_stmt and block is not None:
                    block.statements[stmt_idx] = new_stmt
                return new_stmt

            def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
                return self.context._correct_call(expr, True)

        for block in self._graph.nodes:
            walker = CallWalker(self)
            walker.walk(block)

        self.out_graph = self._graph

        for block in self._graph.nodes:
            walker = CallsiteCorrectorWalker(self)
            walker.walk(block)
