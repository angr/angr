import networkx

from .reaching_definitions import LiveDefinitions, ReachingDefinitionAnalysis, register_analysis
from .definition import Definition
from .atoms import Atom

class GuardUse(Atom):
    def __init__(self, target):
        self.target = target

    def __repr__(self):
        return '<Guard %#x>' % self.target


class DefUseState(LiveDefinitions):
    def _cycle(self, code_loc):
        if code_loc != self.analysis.current_codeloc:
            self.analysis.current_codeloc = code_loc
            self.analysis.codeloc_uses = set()

    def add_use(self, atom, code_loc):
        self._cycle(code_loc)
        self.analysis.codeloc_uses.update(self.get_definitions(atom))
        return super().add_use(atom, code_loc)

    def kill_and_add_definition(self, atom, code_loc, data, dummy=False):
        self._cycle(code_loc)
        definition = super().kill_and_add_definition(atom, code_loc, data, dummy=dummy)
        if definition is not None:
            self.analysis.def_use_graph.add_node(definition)
            for used in self.analysis.codeloc_uses:
                # moderately confusing misnomers. this is an edge from a def to a use, since the "uses" are actually the
                # definitions that we're using and the "definition" is the new definition
                # i.e. the def that the old def is used to construct
                # so this is really a graph where nodes are defs and edges are uses
                self.analysis.def_use_graph.add_edge(used, definition)
        return definition

    def mark_guard(self, code_loc, data, target):
        self._cycle(code_loc)
        atom = GuardUse(target)
        kinda_definition = Definition(atom, code_loc, data)
        self.analysis.def_use_graph.add_node(kinda_definition)
        for used in self.analysis.codeloc_uses:
            self.analysis.def_use_graph.add_edge(used, kinda_definition)


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
