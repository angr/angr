from __future__ import annotations
from angr.ailment.expression import Const, Load

from angr import SIM_LIBRARIES
from angr.calling_conventions import default_cc
from angr.analyses.decompiler.peephole_optimizations.base import PeepholeOptimizationExprBase
from angr.analyses.decompiler.peephole_optimizations import EXPR_OPTS


class APIObfType1PeepholeOptimizer(PeepholeOptimizationExprBase):
    """
    Integrate type-1 deobfuscated API into decompilation output.
    """

    __slots__ = ()

    NAME = "Simplify Type 1 API obfuscation references"
    expr_classes = (Load,)

    def optimize(self, expr: Load, **kwargs):
        if (
            isinstance(expr.addr, Const)
            and (expr.addr.value in self.kb.obfuscations.type1_deobfuscated_apis)
            and expr.bits == self.project.arch.bits
        ):
            # this is actually a function calling a known API
            # replace it with the actual API and the actual arguments
            _, funcname = self.kb.obfuscations.type1_deobfuscated_apis[expr.addr.value]
            if funcname not in self.kb.functions:
                # assign a new function on-demand
                symbol = self.project.loader.extern_object.make_extern(funcname)
                hook_addr = self.project.hook_symbol(
                    symbol.rebased_addr, SIM_LIBRARIES["linux"][0].get_stub(funcname, self.project.arch)
                )
                func = self.kb.functions.function(addr=hook_addr, name=funcname, create=True)
                func.is_simprocedure = True

                default_cc_kwargs = {}
                if self.project.simos is not None:
                    default_cc_kwargs["platform"] = self.project.simos.name
                default_cc_cls = default_cc(self.project.arch.name, **default_cc_kwargs)
                if default_cc_cls is not None:
                    func.calling_convention = default_cc_cls(self.project.arch)
                func.find_declaration(ignore_binary_name=True)
            else:
                func = self.kb.functions[funcname]
            return Const(expr.idx, None, func.addr, self.project.arch.bits, **expr.tags)
        return None


EXPR_OPTS.append(APIObfType1PeepholeOptimizer)
