import networkx

from .reaching_definitions import ReachingDefinitionsAnalysis
from .def_use_state import DefUseState


class DefUseAnalysis(ReachingDefinitionsAnalysis): # pylint: disable=abstract-method
    def __init__(self, *args, **kwargs):
        self.def_use_graph = networkx.DiGraph()
        self.current_codeloc = None
        self.codeloc_uses = set()
        super().__init__(*args, **kwargs)

    def _initial_abstract_state(self, node):
        if self._init_state is not None:
            return self._init_state
        else:
            func_addr = self._function.addr if self._function else None
            return DefUseState(self.project.arch, track_tmps=self._track_tmps, analysis=self,
                                   init_func=self._init_func, cc=self._cc, func_addr=func_addr)
