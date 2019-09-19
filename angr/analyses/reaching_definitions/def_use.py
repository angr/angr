import networkx

from .reaching_definitions import LiveDefinitions, ReachingDefinitionAnalysis, register_analysis

class DefUseState(LiveDefinitions):
    def add_use(self, atom, code_loc):
        if code_loc != self.analysis.current_codeloc:
            self.analysis.current_codeloc = code_loc
            self.analysis.codeloc_uses = set()
        self.analysis.codeloc_uses.update(self.get_definitions(atom))
        return super().add_use(atom, code_loc)

    def kill_and_add_definition(self, atom, code_loc, data, dummy=False):
        if code_loc != self.analysis.current_codeloc:
            self.analysis.current_codeloc = code_loc
            self.analysis.codeloc_uses = set()
        definition = super().kill_and_add_definition(atom, code_loc, data, dummy=dummy)
        self.analysis.def_use_graph.add_node(definition)
        for used in self.analysis.codeloc_uses:
            # moderately confusing misnomers. this is an edge from a def to a use, since the "uses" are actually the
            # definitions that we're using and the "definition" is the new definition
            # i.e. the place the old defs are used
            self.analysis.def_use_graph.add_edge(used, definition)
        return definition

class DefUseAnalysis(ReachingDefinitionAnalysis):
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

register_analysis(DefUseAnalysis, 'DefUseAnalysis')
