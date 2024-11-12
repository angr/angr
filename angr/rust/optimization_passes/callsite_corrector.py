from ailment import Const, AILBlockWalker, Block
from ailment.expression import BasePointerOffset, VirtualVariable, VirtualVariableCategory
from ailment.statement import Call, Statement, Assignment

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.rust.optimization_passes.base import TransformationPass, SSAVariableHelper
from angr.rust.sim_type import (
    RustSimTypeFunction,
    RustSimTypeReference,
    RustSimStruct,
    RustSimEnum,
    is_composite_type,
)


class CallsiteCorrector(OptimizationPass, SSAVariableHelper):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify callsites"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        SSAVariableHelper.__init__(self, self)
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
