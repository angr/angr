from angr.ailment import AILBlockWalker, Statement, Block, Assignment
from angr.ailment.expression import VirtualVariable, VirtualVariableCategory, UnaryOp, Load
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass
from angr.rust.mixins.srda_mixin import SRDAMixin


class SSAVariableMixin:
    def __init__(self, context: OptimizationPass):
        self.context = context

        self._new_stack_vvars = {}

    def new_stack_vvar(self, dst_offset, bits, tags):
        vvar_id = self.context.vvar_id_start
        self.context.vvar_id_start += 1
        vvar_bits = bits
        vvar = VirtualVariable(
            None,
            vvar_id,
            vvar_bits,
            VirtualVariableCategory.STACK,
            oident=dst_offset,
            **tags,
        )
        self._new_stack_vvars[vvar.varid] = vvar
        return vvar

    def fix_stack_vvar_uses(self):
        srda = SRDAMixin(self.context._func, self.context._graph, self.context.project)

        def _handle_UnaryOp(expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt: Statement, block: Block | None):
            if expr.op == "Reference":
                new_expr = expr.copy()
                expr = expr.operand
                if not isinstance(expr, VirtualVariable) or expr.varid in self._new_stack_vvars:
                    return None
                if expr.was_stack:
                    vvar = srda.get_stack_vvar_by_insn(expr.stack_offset, stmt.ins_addr, block.idx)
                    if vvar and vvar.varid in self._new_stack_vvars:
                        new_expr.operand = vvar
                        return new_expr
            return None

        def _handle_VirtualVariable(
            expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement, block: Block | None
        ):
            if expr.varid in self._new_stack_vvars or (isinstance(stmt, Assignment) and stmt.dst is expr):
                return None
            if expr.was_stack:
                vvar = srda.get_stack_vvar_by_insn(expr.stack_offset, stmt.ins_addr, block.idx)
                if vvar and vvar.varid in self._new_stack_vvars:
                    if expr.size < vvar.size:
                        return Load(
                            None,
                            UnaryOp(None, "Reference", vvar),
                            expr.size,
                            self.context.project.arch.memory_endness,
                        )
                    return vvar
            return None

        walker = AILBlockWalker()
        walker.expr_handlers.update({UnaryOp: _handle_UnaryOp, VirtualVariable: _handle_VirtualVariable})
        for block in self.context._graph.nodes:
            walker.walk(block)
