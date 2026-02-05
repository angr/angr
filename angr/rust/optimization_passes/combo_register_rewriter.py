from angr.ailment.expression import ComboRegister, VirtualVariable, VirtualVariableCategory, UnaryOp
from angr.ailment.statement import Call
from .utils import CallRewriter, replace_argument_pairs
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.rust.mixins import SRDAMixin
from angr.ailment import AILBlockWalker, Statement, Block


class ComboRegisterRewriter(OptimizationPass, SRDAMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Rewrite return expressions for functions returning struct via multiple registers"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        SRDAMixin.__init__(self, func, self._graph, self.project)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze(self, cache=None):
        ident_to_vvar = {}
        first_offset_to_vvar = {}
        for arg_vvar, _ in self._arg_vvars.values():
            if (
                isinstance(arg_vvar, VirtualVariable)
                and arg_vvar.was_parameter
                and arg_vvar.parameter_category == VirtualVariableCategory.COMBO_REGISTER
            ):
                ident_to_vvar[":".join(str(reg_offset) for reg_offset in arg_vvar.reg_offsets)] = arg_vvar
                first_offset_to_vvar[arg_vvar.reg_offsets[0]] = arg_vvar

        def handle_Call(call: Call, block, stmt, is_expr):
            def replace_argument_pair(arg, next_arg):
                if (
                    isinstance(arg, VirtualVariable)
                    and isinstance(next_arg, VirtualVariable)
                    and arg.was_reg
                    and next_arg.was_reg
                ):
                    if self.get_vvar_value(arg) is None and self.get_vvar_value(next_arg) is None:
                        ident = f"{arg.reg_offset}:{next_arg.reg_offset}"
                        if ident in ident_to_vvar:
                            return True, [ident_to_vvar[ident]]
                return False, None

            return replace_argument_pairs(call, replace_argument_pair)

        def handle_UnaryOp(expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt: Statement, block: Block | None):
            if (
                expr.op == "Reference"
                and isinstance(expr.operand, VirtualVariable)
                and expr.operand.was_reg
                and expr.operand.reg_offset in first_offset_to_vvar
                and self.get_vvar_value(expr.operand) is None
            ):
                vvar = first_offset_to_vvar[expr.operand.reg_offset]
                result = expr.copy()
                result.operand = vvar
                return result
            return expr

        rewriter = CallRewriter(handle_Call)
        rewriter.expr_handlers[UnaryOp] = handle_UnaryOp

        for block in self._graph.nodes:
            rewriter.walk(block)

        self.out_graph = self._graph
