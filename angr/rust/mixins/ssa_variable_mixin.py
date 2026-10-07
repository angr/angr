from __future__ import annotations

from typing import TYPE_CHECKING

from angr.ailment import AILBlockRewriter, Assignment, Block, Statement
from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import Load, Phi, UnaryOp, VirtualVariable, VirtualVariableCategory
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

    def _make_srda(self) -> SRDAMixin:
        return SRDAMixin(
            self.context._func, self.context._graph, self.context.project, variable_map_of(self.context.manager)
        )

    def ambiguous_new_stack_vvars(self) -> set[int]:
        """
        Varids of new stack vvars that reach a use of their slot together with a pre-existing definition, i.e., the
        slot's earlier value is still live where the new value arrives. No phi merges them.
        """
        if not self._new_stack_vvars:
            return set()
        finder = _AmbiguousStackVVarFinder(self._make_srda(), self._new_stack_vvars)
        for block in self.context._graph.nodes:
            finder.walk(block)
        return finder.ambiguous

    def fix_stack_vvar_uses(self):
        rewriter = _StackVVarRewriter(
            self._make_srda(), self._new_stack_vvars, self.context.project, self.context.manager
        )
        for block in self.context._graph.nodes:
            rewriter.walk(block)


class _AmbiguousStackVVarFinder(AILBlockViewer):
    """Visit the uses _StackVVarRewriter resolves and collect new vvars that share one with an old def."""

    def __init__(self, srda: SRDAMixin, new_stack_vvars: dict):
        super().__init__()
        self._srda = srda
        self._new_stack_vvars = new_stack_vvars
        self.ambiguous: set[int] = set()

    def _check(self, vvar: VirtualVariable, stmt: Statement | None, block: Block | None) -> None:
        if stmt is None or block is None or not vvar.was_stack or vvar.varid in self._new_stack_vvars:
            return
        ins_addr = stmt.tags.get("ins_addr")
        if ins_addr is None:
            return
        defs = self._srda.get_stack_vvars_by_insn(vvar.stack_offset, ins_addr, block.idx)
        new_varids = {d.varid for d in defs if d.varid in self._new_stack_vvars}
        if new_varids and len(new_varids) < len(defs):
            self.ambiguous |= new_varids

    def _handle_UnaryOp(self, expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt: Statement | None, block: Block | None):
        if expr.op == "Reference" and isinstance(expr.operand, VirtualVariable):
            self._check(expr.operand, stmt, block)
        return super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_VirtualVariable(
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        if not (isinstance(stmt, Assignment) and stmt.dst.idx == expr.idx):
            self._check(expr, stmt, block)
        return super()._handle_VirtualVariable(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Phi(self, expr_idx: int, expr: Phi, stmt_idx: int, stmt: Statement | None, block: Block | None):
        # the rewriter leaves phis alone
        return None


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
        if expr.varid in self._new_stack_vvars or (isinstance(stmt, Assignment) and stmt.dst.idx == expr.idx):
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
