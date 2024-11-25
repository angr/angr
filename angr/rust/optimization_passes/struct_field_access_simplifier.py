from ailment import AILBlockWalker, Block, Const
from ailment.expression import VirtualVariable, BinaryOp
from ailment.statement import Statement

from .struct_instantiation_simplifier import StructResolver
from ...rust.sim_type import RustSimStruct
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from ...rust.mixins.cfa_mixin import CFAMixin
from ...rust.mixins.srda_mixin import SRDAMixin


class StructFieldAccessSimplifierWalker(AILBlockWalker):
    def __init__(self, context: "StructFieldAccessSimplifier"):
        super().__init__()
        self.context = context
        self.project = context.project

    def _handle_VirtualVariable(
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        if block and isinstance(expr, VirtualVariable) and expr.was_stack:
            base_vvar, offset = self.context.get_stack_vvar_and_offset_by_insn(
                expr.stack_offset, stmt.ins_addr, block.idx
            )
            if base_vvar:
                vvar_type = self.context.get_vvar_type(base_vvar)
                if isinstance(vvar_type, RustSimStruct):
                    offset = Const(None, None, offset, bits=self.project.arch.bits)
                    new_expr = BinaryOp(expr.idx, "AccessField", operands=[base_vvar, offset], signed=False)
                    field_name, field_type = StructResolver(vvar_type).find_field(offset.value)
                    new_expr.tags["struct_type"] = vvar_type
                    new_expr.tags["field_name"] = field_name
                    new_expr.tags["field_type"] = field_type
                    if offset.value > 0:
                        return new_expr
                    # expr.tags["alternative"] = new_expr
                    # return expr
        return None


class StructFieldAccessSimplifier(OptimizationPass, CFAMixin, SRDAMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify struct member access operations"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        CFAMixin.__init__(self, self._graph, self.project)
        SRDAMixin.__init__(self, self._func, self._graph, self.project)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze(self, cache=None):
        walker = StructFieldAccessSimplifierWalker(self)
        for block in self._graph.nodes:
            walker.walk(block)
