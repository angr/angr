from ..analysis import Analysis
from ..cfg import CFG

class CFGAnalysis(Analysis):
    __analysis_name__ = 'CFG'

    def __init__(self, context_sensitivity=1, start=None, avoid_runs=None):
        self.cfg = CFG(project=self._p, context_sensitivity_level=context_sensitivity)
        self.cfg.construct(self._p.main_binary, start=start, avoid_runs=avoid_runs)
