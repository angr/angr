from ailment import Const, AILBlockWalker, Block
from ailment.expression import BasePointerOffset, VirtualVariable, VirtualVariableCategory
from ailment.statement import Call, Statement

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage
from angr.rust.optimization_passes.base import TransformationPass
from angr.rust.sim_type import RustSimTypeFunction, RustSimTypeReference, RustSimStruct


class CallsiteCorrector(TransformationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_MAKING_CALLSITES
    NAME = "Simplify callsites"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _correct_callsite(self, call: Call):
        prototype = call.prototype
        if (
            isinstance(prototype, RustSimTypeFunction)
            and prototype.is_returnty_struct
            and call.args
            and len(call.args) >= 1
            and isinstance(prototype.args[0], RustSimTypeReference)
            and isinstance(prototype.args[0].pts_to, RustSimStruct)
        ):
            struct_ty = prototype.args[0].pts_to
            first_arg = call.args[0]
            if isinstance(first_arg, BasePointerOffset):
                vvar_id = self.vvar_id_start
                self.vvar_id_start += 1
                vvar_bits = struct_ty.size
                vvar = VirtualVariable(
                    None,
                    vvar_id,
                    vvar_bits,
                    VirtualVariableCategory.STACK,
                    oident=first_arg.offset,
                    **call.tags,
                )
                call.ret_expr = vvar
                call.args = call.args[1:]
                call.prototype.returnty = struct_ty
                call.prototype.args = call.prototype.args[1:]
                call.prototype.is_returnty_struct = False

    def _analyze(self, cache=None):
        class CallWalker(AILBlockWalker):
            def __init__(self, context: CallsiteCorrector):
                super().__init__()
                self.context = context

            def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
                self.context._correct_callsite(stmt)

            def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
                self.context._correct_callsite(expr)

        for block in self._graph.nodes:
            walker = CallWalker(self)
            walker.walk(block)
