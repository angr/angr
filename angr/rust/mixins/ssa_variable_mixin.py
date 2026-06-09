from __future__ import annotations

from typing import TYPE_CHECKING

from angr.ailment import AILBlockRewriter, Assignment, Block, Statement
from angr.ailment.expression import Load, UnaryOp, VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.rust.mixins.srda_mixin import SRDAMixin

if TYPE_CHECKING:
    from angr.ailment import Manager


class SSAVariableMixin:
    """Mixin for creating and fixing SSA stack virtual variables."""

    def __init__(self, context: OptimizationPass):
        self.context = context

        self._new_stack_vvars = {}

    def new_stack_vvar(self, dst_offset, bits, tags, record=True):
        vvar_id = self.context.vvar_id_start
        self.context.vvar_id_start += 1
        vvar_bits = bits
        vvar = VirtualVariable(
            self.context.manager.next_atom(),
            vvar_id,
            vvar_bits,
            VirtualVariableCategory.STACK,
            oident=dst_offset,
            **tags,
        )
        if record:
            self._new_stack_vvars[vvar.varid] = vvar
        return vvar

    def fix_stack_vvar_uses(self):
        srda = SRDAMixin(
            self.context._func, self.context._graph, self.context.project, variable_map_of(self.context.manager)
        )

        rewriter = _StackVVarRewriter(srda, self._new_stack_vvars, self.context.project, self.context.manager)
        for block in self.context._graph.nodes:
            rewriter.walk(block)


class _StackVVarRewriter(AILBlockRewriter):
    """Rewrite stack virtual variable references to use newly created variables."""

    def __init__(self, srda: SRDAMixin, new_stack_vvars: dict, project, manager: Manager):
        super().__init__()
        self._srda = srda
        self._new_stack_vvars = new_stack_vvars
        self._project = project
        self.manager = manager

    def _handle_UnaryOp(self, expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt: Statement | None, block: Block | None):
        if stmt is not None and block is not None and expr.op == "Reference":
            operand = expr.operand
            if (
                isinstance(operand, VirtualVariable)
                and operand.was_stack
                and operand.varid not in self._new_stack_vvars
            ):
                ins_addr = stmt.tags.get("ins_addr")
                if ins_addr is None:
                    return super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)
                vvar = self._srda.get_stack_vvar_by_insn(operand.stack_offset, ins_addr, block.idx)
                if vvar and vvar.varid in self._new_stack_vvars:
                    new_expr = expr.copy()
                    new_expr.operand = vvar
                    return new_expr
        return super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_VirtualVariable(
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        if expr.varid in self._new_stack_vvars or (isinstance(stmt, Assignment) and stmt.dst is expr):
            return expr
        if stmt is not None and block is not None and expr.was_stack:
            ins_addr = stmt.tags.get("ins_addr")
            if ins_addr is None:
                return expr
            vvar = self._srda.get_stack_vvar_by_insn(expr.stack_offset, ins_addr, block.idx)
            if vvar and vvar.varid in self._new_stack_vvars:
                if expr.size < vvar.size:
                    return Load(
                        self.manager.next_atom(),
                        UnaryOp(self.manager.next_atom(), "Reference", vvar),
                        expr.size,
                        self._project.arch.memory_endness,
                    )
                return vvar
        return expr

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement | None, block: Block | None):
        result = super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)
        if isinstance(result, Load) and isinstance(result.addr, UnaryOp) and result.addr.op == "Reference":
            operand = result.addr.operand
            if operand.size == result.size:
                return operand
        return result
