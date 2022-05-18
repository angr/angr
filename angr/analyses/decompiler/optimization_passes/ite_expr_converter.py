import logging

from ....code_location import CodeLocation
from ... import AnalysesHub
from .optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(__name__)


class ITEExprConverter(OptimizationPass):
    """
    Transform specific expressions into If-Then-Else expressions, or tertiary expressions in C.
    """

    ARCHES = ["X86", "AMD64", "ARMEL", "ARMHF", "ARMCortexM", "MIPS32", "MIPS64"]
    PLATFORMS = ["windows", "linux", "cgc"]
    STAGE = OptimizationPassStage.DURING_REGION_IDENTIFICATION
    NAME = "Transform specific expressions into ITEs"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        b = self._get_block(0x400bcf)
        print(b)

        atom = b.statements[0].args[1]

        rda = self.project.analyses.ReachingDefinitions(subject=self._func, func_graph=self._graph)

        # find the corresponding definition
        loc = CodeLocation(b.addr, 0)
        for def_, expr in rda.all_uses.get_uses_by_location(loc, exprs=True):
            if expr == atom:
                print(def_)

        import ipdb; ipdb.set_trace()


AnalysesHub.register_default('ITEExprConverter', ITEExprConverter)
