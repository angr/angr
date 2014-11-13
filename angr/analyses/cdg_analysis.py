from ..analysis import Analysis
from ..cdg import CDG


class CDGAnalysis(Analysis):
    __analysis_name__ = 'CDG'

    def __init__(self, avoid_runs=None, start=None):

        cfg = self._p.analyze('CFG', avoid_runs=avoid_runs, start=start)
        self.cfg = cfg
        self.cdg = CDG(self._p.main_binary, self._p, self.cfg)
        self.cdg.construct()
