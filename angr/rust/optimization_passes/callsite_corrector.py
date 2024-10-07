from ailment import Const, AILBlockWalker, Block
from ailment.expression import BasePointerOffset, VirtualVariable, VirtualVariableCategory
from ailment.statement import Call, Statement, Assignment

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage
from angr.rust.optimization_passes.base import TransformationPass
from angr.rust.sim_type import RustSimTypeFunction, RustSimTypeReference, RustSimStruct


class CallsiteCorrector(TransformationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify callsites"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _correct_callsite(self, call: Call) -> Assignment | None:
        if not call.prototype:
            return None
        prototype = call.prototype.copy()
        call = call.copy()
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
                call.args = call.args[1:]
                call.bits = vvar_bits
                prototype.returnty = struct_ty
                prototype.args = call.prototype.args[1:]
                prototype.is_returnty_struct = False
                call.prototype = prototype
                assignment = Assignment(idx=None, dst=vvar, src=call, **call.tags)
                return assignment
        return None

    def _analyze(self, cache=None):
        class CallWalker(AILBlockWalker):
            def __init__(self, context: CallsiteCorrector):
                super().__init__()
                self.context = context
                self.calls_to_replace = []

            def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
                replacement = self.context._correct_callsite(stmt)
                if replacement:
                    self.calls_to_replace.append((block, stmt_idx, replacement))

            # def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
            #     replacement = self.context._correct_callsite(expr)
            #     self.calls_to_replace.append((block, stmt_idx, replacement))

        for block in self._graph.nodes:
            walker = CallWalker(self)
            walker.walk(block)
            for block, stmt_idx, replacement in walker.calls_to_replace:
                block.statements[stmt_idx] = replacement
        self.out_graph = self._graph
