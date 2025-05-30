import traceback
import logging

from angr.knowledge_plugins.plugin import KnowledgeBasePlugin


l = logging.getLogger(name=__name__)


class ClinicFactory(KnowledgeBasePlugin):
    def __init__(self, kb):
        super().__init__(kb)
        self.cache = {}

    def get(self, func, optimization_passes=None):
        if optimization_passes is None:
            optimization_passes = tuple()
        key = (func.name, tuple(optimization_passes))
        if key in self.cache:
            return self.cache[key]
        cfg = self._kb.cfgs.get_most_accurate()
        try:
            clinic = self._kb._project.analyses.Clinic(func, cfg=cfg, optimization_passes=optimization_passes)
            self.cache[key] = clinic
            return self.cache[key]
        except Exception as e:
            l.error(f"Failed to recover AIL graph for {func.demangled_name}")
            l.error("".join(traceback.format_exception(e)))
            return None


KnowledgeBasePlugin.register_default("clinic_factory", ClinicFactory)
