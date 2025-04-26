from ailment import Const, Register
from ailment.expression import ComboRegister
from ailment.statement import Call
from .utils import CallReplacer

from ...calling_conventions import SimStructArg, SimRegArg
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage


class RetExprRewriter(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_SSA_LEVEL0_TRANSFORMATION
    NAME = "Rewrite return expressions for functions returning struct via multiple registers"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze(self, cache=None):
        def callback(call: Call, block, stmt, is_expr):
            if isinstance(call.target, Const) and call.target.value in self.kb.functions:
                func = self.kb.functions[call.target.value]
                if func.prototype and func.calling_convention and func.prototype.returnty:
                    ret_val = func.calling_convention.return_val(func.prototype.returnty)
                    if (
                        isinstance(ret_val, SimStructArg)
                        and len(ret_val.locs) >= 2
                        and all(isinstance(arg, SimRegArg) for arg in ret_val.locs.values())
                    ):
                        regs = []
                        for reg_arg in ret_val.locs.values():
                            reg_offset, reg_size = self.project.arch.registers[reg_arg.reg_name]
                            reg = Register(
                                None,
                                None,
                                reg_offset,
                                reg_size * 8,
                                reg_name=reg_arg.reg_name,
                            )
                            regs.append(reg)
                        ret_expr = ComboRegister(None, None, regs)
                        new_call = call.copy()
                        new_call.ret_expr = ret_expr
                        return new_call
            return None

        replacer = CallReplacer(callback)
        for block in self._graph.nodes:
            replacer.walk(block)
