
from .. import AnalysesHub, Analysis
from .optimization_passes import OptimizationPass, StructuredOptimizationPass


class Decompiler(Analysis):
    def __init__(self, func, cfg=None, optimization_passes=None):
        self.func = func
        self._cfg = cfg
        if optimization_passes is None:
            self._unstructured_optimization_passes = None
            self._structured_optimization_passes = None
        else:
            self._unstructured_optimization_passes = [
                op for op in optimization_passes if issubclass(op, OptimizationPass)
            ]
            self._structured_optimization_passes = [
                op for op in optimization_passes if issubclass(op, StructuredOptimizationPass)
            ]

        self.codegen = None

        self._decompile()

    def _decompile(self):

        if self.func.is_simprocedure:
            return

        # convert function blocks to AIL blocks
        clinic = self.project.analyses.Clinic(self.func,
                                              kb=self.kb,
                                              optimization_passes=self._unstructured_optimization_passes)

        # recover regions
        ri = self.project.analyses.RegionIdentifier(self.func, graph=clinic.graph, kb=self.kb)

        # structure it
        rs = self.project.analyses.RecursiveStructurer(ri.region, kb=self.kb)

        # simplify it
        s = self.project.analyses.RegionSimplifier(rs.result, kb=self.kb)

        codegen = self.project.analyses.StructuredCodeGenerator(self.func,
                                                                s.result,
                                                                cfg=self._cfg,
                                                                kb=self.kb,
                                                                optimization_passes=self._structured_optimization_passes)

        self.codegen = codegen


AnalysesHub.register_default('Decompiler', Decompiler)
