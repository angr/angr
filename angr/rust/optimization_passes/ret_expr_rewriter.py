from __future__ import annotations

from angr.ailment import Const, Register
from angr.ailment.expression import Call, ComboRegister
from angr.ailment.statement import SideEffectStatement
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.calling_conventions import SimFunctionArgument, SimRegArg, SimStructArg

from .utils import SideEffectStatementRewriter


class RetExprRewriter(OptimizationPass):
    """Rewrite return expressions for functions returning struct via multiple registers."""

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_SSA_LEVEL0_TRANSFORMATION
    NAME = "Rewrite return expressions for functions returning struct via multiple registers"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _flatten_locs(self, arg: SimFunctionArgument):
        if isinstance(arg, SimStructArg):
            locs = []
            for loc in arg.locs.values():
                locs += self._flatten_locs(loc)
            return locs
        return [arg]

    def _analyze(self, cache=None):
        def callback(call_stmt: SideEffectStatement, _block, _stmt):
            if (
                isinstance(call_stmt.expr, Call)
                and isinstance(call_stmt.expr.target, Const)
                and self.kb.functions.contains_addr(call_stmt.expr.target.value_int)
            ):
                func = self.kb.functions.get_by_addr(call_stmt.expr.target.value_int, meta_only=True)
                if func.prototype is not None and func.calling_convention and func.prototype.returnty:
                    ret_val = func.calling_convention.return_val(func.prototype.returnty)
                    ret_locs = self._flatten_locs(ret_val)  # pyright: ignore[reportArgumentType]
                    if (
                        isinstance(ret_val, SimStructArg)
                        and len(ret_val.locs) >= 2
                        and all(isinstance(arg, SimRegArg) for arg in ret_locs)
                    ):
                        regs = []
                        for reg_arg in ret_locs:
                            reg_name = reg_arg.reg_name  # pyright: ignore[reportAttributeAccessIssue]
                            reg_offset, reg_size = self.project.arch.registers[reg_name]
                            reg = Register(
                                self.manager.next_atom(),
                                reg_offset,
                                reg_size * 8,
                                reg_name=reg_name,
                            )
                            regs.append(reg)
                        ret_expr = ComboRegister(self.manager.next_atom(), regs)
                        return SideEffectStatement(
                            call_stmt.idx, call_stmt.expr, ret_expr, call_stmt.fp_ret_expr, **call_stmt.tags
                        )
            return call_stmt

        rewriter = SideEffectStatementRewriter(callback)
        for block in self._graph.nodes:
            rewriter.walk(block)

        self.out_graph = self._graph
