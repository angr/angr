
from .. import Analysis, AnalysesHub


class Decompiler(Analysis):
    def __init__(self, func, cfg=None):
        self.func = func
        self._cfg = cfg

        self.codegen = None

        self._decompile()

    def _decompile(self):
        # convert function blocks to AIL blocks
        clinic = self.project.analyses.Clinic(self.func)

        # recover regions
        ri = self.project.analyses.RegionIdentifier(self.func, graph=clinic.graph)

        # structure it
        rs = self.project.analyses.RecursiveStructurer(ri.region)

        # simplify it
        s = self.project.analyses.RegionSimplifier(rs.result)

        codegen = self.project.analyses.StructuredCodeGenerator(self.func, s.result, cfg=self._cfg)

        self.codegen = codegen


AnalysesHub.register_default('Decompiler', Decompiler)
