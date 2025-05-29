from angr.knowledge_plugins.plugin import KnowledgeBasePlugin


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
        clinic = self._kb._project.analyses.Clinic(func, cfg=cfg, optimization_passes=optimization_passes)
        self.cache[key] = clinic
        return self.cache[key]


KnowledgeBasePlugin.register_default("clinic_factory", ClinicFactory)
