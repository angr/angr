from typing import Tuple

from ailment.expression import VirtualVariable, BinaryOp, Const
from ailment.statement import Return, Store

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass


class StructReturnSimplifier(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_VARIABLE_RECOVERY
    NAME = "Simplify function return sites"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _get_vvar_and_offset(self, expr) -> Tuple[VirtualVariable | None, int | None]:
        if isinstance(expr, VirtualVariable):
            return expr, 0
        elif (
            isinstance(expr, BinaryOp)
            and expr.op == "Add"
            and isinstance(expr.operands[0], VirtualVariable)
            and isinstance(expr.operands[1], Const)
        ):
            return expr.operands[0], expr.operands[1].value
        return None, None

    def collect_ret_expr(self, block):
        stmts = []
        fields = {}
        for stmt in block.statements:
            if isinstance(stmt, Store):
                vvar, offset = self._get_vvar_and_offset(stmt.addr)
                if vvar.was_parameter and vvar.varid == 0:
                    stmts.append(stmt)
                    fields[offset] = stmt.data
        if 0 in fields and len(fields) == 1:
            return stmts, fields[0]
        return None, None

    def _analyze(self, cache=None):
        for block in self._graph.nodes:
            if block.statements and isinstance(block.statements[-1], Return):
                stmts, ret_expr = self.collect_ret_expr(block)
                if stmts:
                    for stmt in stmts:
                        block.statements.remove(stmt)
                    block.statements[-1].ret_exprs = [ret_expr]
