
from .. import Analysis, AnalysesHub


class Decompiler(Analysis):
    def __init__(self, func, cfg=None, optimization_passes=None, sp_tracker_track_memory=True):
        self.func = func
        self._cfg = cfg
        self._optimization_passes = optimization_passes
        self._sp_tracker_track_memory = sp_tracker_track_memory

        self.codegen = None

        self._decompile()

    def _decompile(self):

        if self.func.is_simprocedure:
            return

        # convert function blocks to AIL blocks
        clinic = self.project.analyses.Clinic(self.func,
                                              kb=self.kb,
                                              optimization_passes=self._optimization_passes,
                                              sp_tracker_track_memory=self._sp_tracker_track_memory)

        # recover regions
        ri = self.project.analyses.RegionIdentifier(self.func, graph=clinic.graph, kb=self.kb)

        # structure it
        rs = self.project.analyses.RecursiveStructurer(ri.region, kb=self.kb)

        # simplify it
        s = self.project.analyses.RegionSimplifier(rs.result, kb=self.kb)

        codegen = self.project.analyses.StructuredCodeGenerator(self.func, s.result, cfg=self._cfg, kb=self.kb)

        self.codegen = codegen


AnalysesHub.register_default('Decompiler', Decompiler)
