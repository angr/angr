from ..analysis import Analysis
from .vfg import VFG
from ..variableseekr import VariableSeekr

class VSA(Analysis):
    def process_function(self, f, interfunction_level):
        interfunction_level = self._interfunction_level if interfunction_level is None else interfunction_level

        with self._resilience():
            self.vfg.construct(f, interfunction_level=interfunction_level)
            self.seeker.construct(func_start=f)

        self.finished_functions.add(f)

    def __init__(self, context_sensitivity_level=2, interfunction_level=2):
        self.finished_functions = set()
        self._cfg = self._p.analyses.CFG(context_sensitivity_level=1)
        self.vfg = VFG(project=self._p, cfg=self._cfg, context_sensitivity_level=context_sensitivity_level)
        self.seeker = VariableSeekr(self._p, self._cfg, self.vfg)
        self._interfunction_level = interfunction_level

        for f in self._cfg.function_manager.functions:
            if f in self.finished_functions:
                continue

            self.process_function(f, interfunction_level=interfunction_level)
            self._checkpoint()
